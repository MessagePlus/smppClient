#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <math.h>
#include "mysqlDB.h"

#include "gwlib/gwlib.h"

#include "gwlib/gwlib.h"
#include "gw/msg.h"

#include "gw/smsc/smpp_pdu.h"
//#include "gw/smscconn_p.h"

#include "gw/sms.h"
#include "gw/dlr.h"
#include "gw/bearerbox.h"
#include "gw/meta_data.h"
#include "gw/load.h"

#define SMPP_DEAD 0
#define SMPP_SHUTDOWN 1
#define SMPP_RUNNING 2

/* our config */
static Cfg *cfg;
/* have we received restart cmd from bearerbox? */
static volatile sig_atomic_t restart_smppbox = 0;
static volatile sig_atomic_t smppbox_status;

#define SMPP_DEFAULT_CHARSET "UTF-8"

/*
 * Select these based on whether you want to dump SMPP PDUs as they are
 * sent and received or not. Not dumping should be the default in at least
 * stable releases.
 */

#define DEBUG 1

#ifndef DEBUG
#define dump_pdu(msg, id, pdu) do{}while(0)
#else
/** This version does dump. */
#define dump_pdu(msg, id, pdu)                  \
    do {                                        \
        debug("bb.sms.smpp", 0, "SMPP[%s]: %s", \
            octstr_get_cstr(id), msg);          \
        smpp_pdu_dump(pdu);                     \
    } while(0)
#endif

/*
 * Some defaults.
 */

#define SMPP_ENQUIRE_LINK_INTERVAL  30.0
#define SMPP_MAX_PENDING_SUBMITS    10
#define SMPP_DEFAULT_VERSION        0x34
#define SMPP_DEFAULT_PRIORITY       0
#define SMPP_THROTTLING_SLEEP_TIME  1
#define SMPP_DEFAULT_CONNECTION_TIMEOUT  10 * SMPP_ENQUIRE_LINK_INTERVAL
#define SMPP_DEFAULT_WAITACK        60
#define SMPP_DEFAULT_SHUTDOWN_TIMEOUT 30
#define SMSCCONN_RECONNECT_DELAY     10.0

/*
 * Some defines
 */
#define SMPP_WAITACK_RECONNECT      0x00
#define SMPP_WAITACK_REQUEUE        0x01
#define SMPP_WAITACK_NEVER_EXPIRE   0x02
/***********************************************************************
 * Implementation of the actual SMPP protocol: reading and writing
 * PDUs in the correct order.
 */

typedef struct {
	long transmitter;
	long receiver;
	gw_prioqueue_t *msgs_to_send;
	Dict *sent_msgs;
	List *received_msgs;
	Counter *message_id_counter;
	Octstr *host;
	Octstr *system_type;
	Octstr *username;
	Octstr *password;
	Octstr *address_range;
	Octstr *my_number;
	Octstr *service_type;
	int source_addr_ton;
	int source_addr_npi;
	int dest_addr_ton;
	int dest_addr_npi;
	long bind_addr_ton;
	long bind_addr_npi;
	int port;
	int use_ssl;
	Octstr *ssl_client_certkey_file;
	volatile int quitting;
	long enquire_link_interval;
	long max_pending_submits;
	int version;
	int priority; /* set default priority for messages */
	int validityperiod;
	time_t throttling_err_time;
	int smpp_msg_id_type; /* msg id in C string, hex or decimal */
	int autodetect_addr;
	Octstr *alt_charset;
	Octstr *alt_addr_charset;
	long connection_timeout;
	long wait_ack;
	int wait_ack_action;
	int esm_class;
	Load *load;

	Octstr *our_host; /* local device IP to bind for TCP communication */
	/* Our smsc specific log-file data */
//	Octstr *log_file;
//	long log_level;
//	int log_idx; /* index position within the global logfiles[] array in gwlib/log.c */
	long reconnect_delay; /* delay in seconds while re-connect attempts */
	Octstr *smppbox_id;
	Connection *conn;
//	SMSCConn *conn;
} SMPP;


/*
 * Variable de Entorno Generales
 */
Octstr *smppbox_id;
Octstr *host;
long port;
Octstr *carrierId;
Octstr *carrierQueueId;
Octstr *username;
Octstr *password;
Octstr *system_id;
Octstr *system_type;
Octstr *address_range;
long source_addr_ton;
long source_addr_npi;
long dest_addr_ton;
long dest_addr_npi;
Octstr *my_number;
Octstr *service_type;
SMPP *smpp;
int transceiver_mode;
int receiver_mode;
int transmitter_mode;
long enquire_link_interval;
long version;
long priority;
long validity;
long smpp_msg_id_type;
int autodetect_addr;
Octstr *alt_charset;
Octstr *alt_addr_charset;
long esm_class;
long reconnect_delay;
long max_pending_submits;
long connection_timeout, wait_ack, wait_ack_action;

struct smpp_msg {
	time_t sent_time;
	Msg *msg;
};

typedef struct _Message {
    time_t sent_time;
    Octstr *id;
} Message;

typedef struct _service{
	Octstr *id;
	Octstr *name;
	Octstr *integratorId;
	Octstr *integratorQueueId;
	Octstr *carrierId;
	int errorCode;
	Octstr *errorText;
} Service;

static Service *serviceCreate(){
	Service *service;
	service= gw_malloc(sizeof(Service));
	service->id=NULL;
	service->name=NULL;
	service->integratorId=NULL;
	service->integratorQueueId=NULL;
	service->carrierId=NULL;
	service->errorCode=0;
	service->errorText=NULL;
	return service;
}

static void serviceDestroy(Service *service) {
	if (service == NULL)
		return;
	if (service->id)
		octstr_destroy(service->id);
	if (service->name)
		octstr_destroy(service->name);
	if (service->integratorId)
		octstr_destroy(service->integratorId);
	if (service->integratorQueueId)
		octstr_destroy(service->integratorQueueId);
	if (service->carrierId)
		octstr_destroy(service->carrierId);

	if (service->errorText)
		octstr_destroy(service->errorText);

	gw_free(service);
}
/*
 * create smpp_msg struct
 */
static inline struct smpp_msg* smpp_msg_create(Msg *msg) {
	struct smpp_msg *result = gw_malloc(sizeof(struct smpp_msg));

	gw_assert(result != NULL);
	result->sent_time = time(NULL);
	result->msg = msg;

	return result;
}

/*
 * destroy smpp_msg struct. If destroy_msg flag is set, then message will be freed as well
 */
static inline void smpp_msg_destroy(struct smpp_msg *msg, int destroy_msg) {
	/* sanity check */
	if (msg == NULL)
		return;

	if (destroy_msg && msg->msg != NULL)
		msg_destroy(msg->msg);

	gw_free(msg);
}

static Message* createMessage(Octstr *id){

	Message *result=gw_malloc(sizeof(Message));

	result->sent_time=time(NULL);
	result->id=id;

	return result;

}

static SMPP *smpp_create(Octstr *smppbox_id, Octstr *our_host, long reconnect_delay, Octstr *host, int port, Octstr *system_type, Octstr *username,
		Octstr *password, Octstr *address_range, int source_addr_ton, int source_addr_npi, int dest_addr_ton, int dest_addr_npi,
		int enquire_link_interval, int max_pending_submits, int version, int priority, int validity, Octstr *my_number, int smpp_msg_id_type,
		int autodetect_addr, Octstr *alt_charset, Octstr *alt_addr_charset, Octstr *service_type, long connection_timeout, long wait_ack,
		int wait_ack_action, int esm_class) {
	SMPP *smpp;

	smpp = gw_malloc(sizeof(*smpp));
	smpp->transmitter = -1;
	smpp->receiver = -1;
	smpp->msgs_to_send = gw_prioqueue_create(sms_priority_compare);
	smpp->sent_msgs = dict_create(max_pending_submits, NULL);
//	gw_prioqueue_add_producer(smpp->msgs_to_send);
	smpp->received_msgs = gwlist_create();
	smpp->message_id_counter = counter_create();
	counter_increase(smpp->message_id_counter);
	smpp->host = octstr_duplicate(host);
	smpp->system_type = octstr_duplicate(system_type);
	smpp->username = octstr_duplicate(username);
	smpp->password = octstr_duplicate(password);
	smpp->address_range = octstr_duplicate(address_range);
	smpp->source_addr_ton = source_addr_ton;
	smpp->source_addr_npi = source_addr_npi;
	smpp->dest_addr_ton = dest_addr_ton;
	smpp->dest_addr_npi = dest_addr_npi;
	smpp->my_number = octstr_duplicate(my_number);
	smpp->service_type = octstr_duplicate(service_type);
	smpp->port = port;
	smpp->enquire_link_interval = enquire_link_interval;
	smpp->max_pending_submits = max_pending_submits;
	smpp->quitting = 0;
	smpp->version = version;
	smpp->priority = priority;
	smpp->validityperiod = validity;
//	smpp->conn = conn;
	smpp->throttling_err_time = 0;
	smpp->smpp_msg_id_type = smpp_msg_id_type;
	smpp->autodetect_addr = autodetect_addr;
	smpp->alt_charset = octstr_duplicate(alt_charset);
	smpp->alt_addr_charset = octstr_duplicate(alt_addr_charset);
	smpp->connection_timeout = connection_timeout;
	smpp->wait_ack = wait_ack;
	smpp->wait_ack_action = wait_ack_action;
	smpp->bind_addr_ton = 0;
	smpp->bind_addr_npi = 0;
	smpp->use_ssl = 0;
	smpp->ssl_client_certkey_file = NULL;
	smpp->load = load_create_real(0);
	load_add_interval(smpp->load, 1);
	smpp->esm_class = esm_class;
	smpp->our_host = octstr_duplicate(our_host);
//	smpp->log_file = octstr_get_cstr(log_file);
//	smpp->log_level = 0;
	smpp->reconnect_delay = SMSCCONN_RECONNECT_DELAY;
	smpp->smppbox_id = octstr_duplicate(smppbox_id);

	return smpp;
}

static void smpp_destroy(SMPP *smpp) {
	if (smpp != NULL) {
		gw_prioqueue_destroy(smpp->msgs_to_send, msg_destroy_item);
		dict_destroy(smpp->sent_msgs);
		gwlist_destroy(smpp->received_msgs, msg_destroy_item);
		counter_destroy(smpp->message_id_counter);
		octstr_destroy(smpp->host);
		octstr_destroy(smpp->username);
		octstr_destroy(smpp->password);
		octstr_destroy(smpp->system_type);
		octstr_destroy(smpp->service_type);
		octstr_destroy(smpp->address_range);
		octstr_destroy(smpp->my_number);
		octstr_destroy(smpp->alt_charset);
		octstr_destroy(smpp->alt_addr_charset);
		octstr_destroy(smpp->ssl_client_certkey_file);
		octstr_destroy(smpp->our_host);
//		octstr_destroy(smpp->log_file);
		octstr_destroy(smpp->smppbox_id);
		load_destroy(smpp->load);
		gw_free(smpp);
	}
}

/*
 * Try to read an SMPP PDU from a Connection. Return -1 for error (caller
 * should close the connection), -2 for malformed PDU , 0 for no PDU to
 * ready yet, or 1 for PDU
 * read and unpacked. Return a pointer to the PDU in `*pdu'. Use `*len'
 * to store the length of the PDU to read (it may be possible to read the
 * length, but not the rest of the PDU - we need to remember the lenght
 * for the next call). `*len' should be zero at the first call.
 */
static int read_pdu(SMPP *smpp, Connection *conn, long *len, SMPP_PDU **pdu) {
	Octstr *os;

	if (*len == 0) {
		*len = smpp_pdu_read_len(conn);
		if (*len == -1) {
			error(0, "SMPP[%s]: Server sent garbage, ignored.", octstr_get_cstr(smpp->smppbox_id));
			return -2;
		} else if (*len == 0) {
			if (conn_eof(conn) || conn_error(conn))
				return -1;
			return 0;
		}
	}

	os = smpp_pdu_read_data(conn, *len);
	if (os == NULL) {
		if (conn_eof(conn) || conn_error(conn))
			return -1;
		return 0;
	}
	*len = 0;

	*pdu = smpp_pdu_unpack(smpp->smppbox_id, os);
	if (*pdu == NULL) {
		error(0, "SMPP[%s]: PDU unpacking failed.", octstr_get_cstr(smpp->smppbox_id));
		debug("bb.sms.smpp", 0, "SMPP[%s]: Failed PDU follows.", octstr_get_cstr(smpp->smppbox_id));
		octstr_dump(os, 0);
		octstr_destroy(os);
		return -2;
	}

	octstr_destroy(os);
	return 1;
}

static long convert_addr_from_pdu(Octstr *id, Octstr *addr, long ton, long npi, Octstr *alt_addr_charset) {
	long reason = SMPP_ESME_ROK;

	if (addr == NULL)
		return reason;

	switch (ton) {
	case GSM_ADDR_TON_INTERNATIONAL:
		/*
		 * Checks to perform:
		 *   1) assume international number has at least 7 chars
		 *   2) the whole source addr consist of digits, exception '+' in front
		 */
		if (octstr_len(addr) < 2) {
			/* We consider this as a "non-hard" condition, since there "may"
			 * be international numbers routable that are < 7 digits. Think
			 * of 2 digit country code + 3 digit emergency code. */
			warning(0, "SMPP[%s]: Mallformed addr `%s', generally expected at least 7 digits. ", octstr_get_cstr(id), octstr_get_cstr(addr));
		} else if (octstr_get_char(addr, 0) == '+' && !octstr_check_range(addr, 1, 256, gw_isdigit)) {
			error(0, "SMPP[%s]: Mallformed addr `%s', expected all digits. ", octstr_get_cstr(id), octstr_get_cstr(addr));
			reason = SMPP_ESME_RINVSRCADR;
			goto error;
		} else if (octstr_get_char(addr, 0) != '+' && !octstr_check_range(addr, 0, 256, gw_isdigit)) {
			error(0, "SMPP[%s]: Mallformed addr `%s', expected all digits. ", octstr_get_cstr(id), octstr_get_cstr(addr));
			reason = SMPP_ESME_RINVSRCADR;
			goto error;
		}
		/* check if we received leading '00', then remove it*/
		if (octstr_search(addr, octstr_imm("00"), 0) == 0)
			octstr_delete(addr, 0, 2);

		/* international, insert '+' if not already here */
		//if (octstr_get_char(addr, 0) != '+')
		//	octstr_insert_char(addr, 0, '+');
		break;
	case GSM_ADDR_TON_ALPHANUMERIC:
		if (octstr_len(addr) > 11) {
			/* alphanum sender, max. allowed length is 11 (according to GSM specs) */
			error(0, "SMPP[%s]: Mallformed addr `%s', alphanum length greater 11 chars. ", octstr_get_cstr(id), octstr_get_cstr(addr));
			reason = SMPP_ESME_RINVSRCADR;
			goto error;
		}
		if (alt_addr_charset) {
			if (octstr_str_case_compare(alt_addr_charset, "gsm") == 0)
				charset_gsm_to_utf8(addr);
			else if (charset_convert(addr, octstr_get_cstr(alt_addr_charset), SMPP_DEFAULT_CHARSET) != 0)
				error(0, "Failed to convert address from charset <%s> to <%s>, leave as is.", octstr_get_cstr(alt_addr_charset),
						SMPP_DEFAULT_CHARSET);
		}
		break;
	default: /* otherwise don't touch addr, user should handle it */
		break;
	}

	error: return reason;
}

/*
 * Convert SMPP PDU to internal Msgs structure.
 * Return the Msg if all was fine and NULL otherwise, while getting
 * the failing reason delivered back in *reason.
 * XXX semantical check on the incoming values can be extended here.
 */
static Msg *pdu_to_msg(SMPP *smpp, SMPP_PDU *pdu, long *reason) {
	Msg *msg;
	int ton, npi;

	gw_assert(pdu->type == deliver_sm);

	msg = msg_create(sms);
	gw_assert(msg != NULL);
	*reason = SMPP_ESME_ROK;

	/*
	 * Reset source addr to have a prefixed '+' in case we have an
	 * intl. TON to allow backend boxes (ie. smsbox) to distinguish
	 * between national and international numbers.
	 */
	ton = pdu->u.deliver_sm.source_addr_ton;
	npi = pdu->u.deliver_sm.source_addr_npi;
	/* check source addr */
	if ((*reason = convert_addr_from_pdu(smpp->smppbox_id, pdu->u.deliver_sm.source_addr, ton, npi, smpp->alt_addr_charset)) != SMPP_ESME_ROK)
		goto error;
	msg->sms.sender = pdu->u.deliver_sm.source_addr;
	pdu->u.deliver_sm.source_addr = NULL;

	/*
	 * Follows SMPP spec. v3.4. issue 1.2
	 * it's not allowed to have destination_addr NULL
	 */
	if (pdu->u.deliver_sm.destination_addr == NULL) {
		error(0, "SMPP[%s]: Mallformed destination_addr `%s', may not be empty. "
				"Discarding MO message.", octstr_get_cstr(smpp->smppbox_id), octstr_get_cstr(pdu->u.deliver_sm.destination_addr));
		*reason = SMPP_ESME_RINVDSTADR;
		goto error;
	}

	/* Same reset of destination number as for source */
	ton = pdu->u.deliver_sm.dest_addr_ton;
	npi = pdu->u.deliver_sm.dest_addr_npi;
	/* check destination addr */
	if ((*reason = convert_addr_from_pdu(smpp->smppbox_id, pdu->u.deliver_sm.destination_addr, ton, npi, smpp->alt_addr_charset)) != SMPP_ESME_ROK)
		goto error;
	msg->sms.receiver = pdu->u.deliver_sm.destination_addr;
	pdu->u.deliver_sm.destination_addr = NULL;

	/* SMSCs use service_type for billing information */
	msg->sms.binfo = pdu->u.deliver_sm.service_type;
	pdu->u.deliver_sm.service_type = NULL;

	/* Foreign ID on MO */
	msg->sms.foreign_id = pdu->u.deliver_sm.receipted_message_id;
	pdu->u.deliver_sm.receipted_message_id = NULL;

	if (pdu->u.deliver_sm.esm_class & ESM_CLASS_SUBMIT_RPI)
		msg->sms.rpi = 1;

	/*
	 * Check for message_payload if version > 0x33 and sm_length == 0
	 * Note: SMPP spec. v3.4. doesn't allow to send both: message_payload & short_message!
	 */
	if (smpp->version > 0x33 && pdu->u.deliver_sm.sm_length == 0 && pdu->u.deliver_sm.message_payload) {
		msg->sms.msgdata = pdu->u.deliver_sm.message_payload;
		pdu->u.deliver_sm.message_payload = NULL;
	} else {
		msg->sms.msgdata = pdu->u.deliver_sm.short_message;
		pdu->u.deliver_sm.short_message = NULL;
	}

	/*
	 * Encode udh if udhi set
	 * for reference see GSM03.40, section 9.2.3.24
	 */
	if (pdu->u.deliver_sm.esm_class & ESM_CLASS_SUBMIT_UDH_INDICATOR) {
		int udhl;
		udhl = octstr_get_char(msg->sms.msgdata, 0) + 1;
		debug("bb.sms.smpp", 0, "SMPP[%s]: UDH length read as %d", octstr_get_cstr(smpp->smppbox_id), udhl);
		if (udhl > octstr_len(msg->sms.msgdata)) {
			error(0, "SMPP[%s]: Mallformed UDH length indicator 0x%03x while message length "
					"0x%03lx. Discarding MO message.", octstr_get_cstr(smpp->smppbox_id), udhl, octstr_len(msg->sms.msgdata));
			*reason = SMPP_ESME_RINVESMCLASS;
			goto error;
		}
		msg->sms.udhdata = octstr_copy(msg->sms.msgdata, 0, udhl);
		octstr_delete(msg->sms.msgdata, 0, udhl);
	}

	dcs_to_fields(&msg, pdu->u.deliver_sm.data_coding);

	/* handle default data coding */
	switch (pdu->u.deliver_sm.data_coding) {
	case 0x00: /* default SMSC alphabet */
		/*
		 * try to convert from something interesting if specified so
		 * unless it was specified binary, ie. UDH indicator was detected
		 */
		if (smpp->alt_charset && msg->sms.coding != DC_8BIT) {
			if (charset_convert(msg->sms.msgdata, octstr_get_cstr(smpp->alt_charset), SMPP_DEFAULT_CHARSET) != 0)
				error(0, "Failed to convert msgdata from charset <%s> to <%s>, will leave as is.", octstr_get_cstr(smpp->alt_charset),
						SMPP_DEFAULT_CHARSET);
			msg->sms.coding = DC_7BIT;
		} else { /* assume GSM 03.38 7-bit alphabet */
			charset_gsm_to_utf8(msg->sms.msgdata);
			msg->sms.coding = DC_7BIT;
		}
		break;
	case 0x01: /* ASCII or IA5 - not sure if I need to do anything */
		msg->sms.coding = DC_7BIT;
		break;
	case 0x03: /* ISO-8859-1 - I'll convert to unicode */
		if (charset_convert(msg->sms.msgdata, "ISO-8859-1", SMPP_DEFAULT_CHARSET) != 0)
			error(0, "Failed to convert msgdata from ISO-8859-1 to " SMPP_DEFAULT_CHARSET ", will leave as is");
		msg->sms.coding = DC_7BIT;
		break;
	case 0x02: /* 8 bit binary - do nothing */
	case 0x04: /* 8 bit binary - do nothing */
		msg->sms.coding = DC_8BIT;
		break;
	case 0x05: /* JIS - what do I do with that ? */
		break;
	case 0x06: /* Cyrllic - iso-8859-5, I'll convert to unicode */
		if (charset_convert(msg->sms.msgdata, "ISO-8859-5", SMPP_DEFAULT_CHARSET) != 0)
			error(0, "Failed to convert msgdata from cyrllic to " SMPP_DEFAULT_CHARSET ", will leave as is");
		msg->sms.coding = DC_7BIT;
		break;
	case 0x07: /* Hebrew iso-8859-8, I'll convert to unicode */
		if (charset_convert(msg->sms.msgdata, "ISO-8859-8", SMPP_DEFAULT_CHARSET) != 0)
			error(0, "Failed to convert msgdata from hebrew to " SMPP_DEFAULT_CHARSET ", will leave as is");
		msg->sms.coding = DC_7BIT;
		break;
	case 0x08: /* unicode UCS-2, yey */
		msg->sms.coding = DC_UCS2;
		break;

		/*
		 * don't much care about the others,
		 * you implement them if you feel like it
		 */

	default:
		/*
		 * some of smsc send with dcs from GSM 03.38 , but these are reserved in smpp spec.
		 * So we just look decoded values from dcs_to_fields and if none there make our assumptions.
		 * if we have an UDH indicator, we assume DC_8BIT.
		 */
		if (msg->sms.coding == DC_UNDEF && pdu->u.deliver_sm.esm_class & ESM_CLASS_SUBMIT_UDH_INDICATOR)
			msg->sms.coding = DC_8BIT;
		else if (msg->sms.coding == DC_7BIT || msg->sms.coding == DC_UNDEF) { /* assume GSM 7Bit , reencode */
			msg->sms.coding = DC_7BIT;
			charset_gsm_to_utf8(msg->sms.msgdata);
		}
	}
	msg->sms.pid = pdu->u.deliver_sm.protocol_id;

	/* set priority flag */
	msg->sms.priority = pdu->u.deliver_sm.priority_flag;

	if (msg->sms.meta_data == NULL)
		msg->sms.meta_data = octstr_create("");
	meta_data_set_values(msg->sms.meta_data, pdu->u.deliver_sm.tlv, "smpp", 1);

	return msg;

	error: msg_destroy(msg);
	return NULL;
}

/*
 * Convert SMPP PDU to internal Msgs structure.
 * Return the Msg if all was fine and NULL otherwise, while getting
 * the failing reason delivered back in *reason.
 * XXX semantical check on the incoming values can be extended here.
 */
static Msg *data_sm_to_msg(SMPP *smpp, SMPP_PDU *pdu, long *reason) {
	Msg *msg;
	int ton, npi;

	gw_assert(pdu->type == data_sm);

	msg = msg_create(sms);
	gw_assert(msg != NULL);
	*reason = SMPP_ESME_ROK;

	/*
	 * Reset source addr to have a prefixed '+' in case we have an
	 * intl. TON to allow backend boxes (ie. smsbox) to distinguish
	 * between national and international numbers.
	 */
	ton = pdu->u.data_sm.source_addr_ton;
	npi = pdu->u.data_sm.source_addr_npi;
	/* check source addr */
	if ((*reason = convert_addr_from_pdu(smpp->smppbox_id, pdu->u.data_sm.source_addr, ton, npi, smpp->alt_addr_charset)) != SMPP_ESME_ROK)
		goto error;
	msg->sms.sender = pdu->u.data_sm.source_addr;
	pdu->u.data_sm.source_addr = NULL;

	/*
	 * Follows SMPP spec. v3.4. issue 1.2
	 * it's not allowed to have destination_addr NULL
	 */
	if (pdu->u.data_sm.destination_addr == NULL) {
		error(0, "SMPP[%s]: Mallformed destination_addr `%s', may not be empty. "
				"Discarding MO message.", octstr_get_cstr(smpp->smppbox_id), octstr_get_cstr(pdu->u.data_sm.destination_addr));
		*reason = SMPP_ESME_RINVDSTADR;
		goto error;
	}

	/* Same reset of destination number as for source */
	ton = pdu->u.data_sm.dest_addr_ton;
	npi = pdu->u.data_sm.dest_addr_npi;
	/* check destination addr */
	if ((*reason = convert_addr_from_pdu(smpp->smppbox_id, pdu->u.data_sm.destination_addr, ton, npi, smpp->alt_addr_charset)) != SMPP_ESME_ROK)
		goto error;
	msg->sms.receiver = pdu->u.data_sm.destination_addr;
	pdu->u.data_sm.destination_addr = NULL;

	/* SMSCs use service_type for billing information */
	msg->sms.binfo = pdu->u.data_sm.service_type;
	pdu->u.data_sm.service_type = NULL;

	/* Foreign ID on MO */
	msg->sms.foreign_id = pdu->u.data_sm.receipted_message_id;
	pdu->u.data_sm.receipted_message_id = NULL;

	if (pdu->u.data_sm.esm_class & ESM_CLASS_SUBMIT_RPI)
		msg->sms.rpi = 1;

	msg->sms.msgdata = pdu->u.data_sm.message_payload;
	pdu->u.data_sm.message_payload = NULL;

	/*
	 * Encode udh if udhi set
	 * for reference see GSM03.40, section 9.2.3.24
	 */
	if (pdu->u.data_sm.esm_class & ESM_CLASS_SUBMIT_UDH_INDICATOR) {
		int udhl;
		udhl = octstr_get_char(msg->sms.msgdata, 0) + 1;
		debug("bb.sms.smpp", 0, "SMPP[%s]: UDH length read as %d", octstr_get_cstr(smpp->smppbox_id), udhl);
		if (udhl > octstr_len(msg->sms.msgdata)) {
			error(0, "SMPP[%s]: Mallformed UDH length indicator 0x%03x while message length "
					"0x%03lx. Discarding MO message.", octstr_get_cstr(smpp->smppbox_id), udhl, octstr_len(msg->sms.msgdata));
			*reason = SMPP_ESME_RINVESMCLASS;
			goto error;
		}
		msg->sms.udhdata = octstr_copy(msg->sms.msgdata, 0, udhl);
		octstr_delete(msg->sms.msgdata, 0, udhl);
	}

	dcs_to_fields(&msg, pdu->u.data_sm.data_coding);

	/* handle default data coding */
	switch (pdu->u.data_sm.data_coding) {
	case 0x00: /* default SMSC alphabet */
		/*
		 * try to convert from something interesting if specified so
		 * unless it was specified binary, ie. UDH indicator was detected
		 */
		if (smpp->alt_charset && msg->sms.coding != DC_8BIT) {
			if (charset_convert(msg->sms.msgdata, octstr_get_cstr(smpp->alt_charset), SMPP_DEFAULT_CHARSET) != 0)
				error(0, "Failed to convert msgdata from charset <%s> to <%s>, will leave as is.", octstr_get_cstr(smpp->alt_charset),
						SMPP_DEFAULT_CHARSET);
			msg->sms.coding = DC_7BIT;
		} else { /* assume GSM 03.38 7-bit alphabet */
			charset_gsm_to_utf8(msg->sms.msgdata);
			msg->sms.coding = DC_7BIT;
		}
		break;
	case 0x01: /* ASCII or IA5 - not sure if I need to do anything */
		msg->sms.coding = DC_7BIT;
		break;
	case 0x03: /* ISO-8859-1 - I'll convert to unicode */
		if (charset_convert(msg->sms.msgdata, "ISO-8859-1", SMPP_DEFAULT_CHARSET) != 0)
			error(0, "Failed to convert msgdata from ISO-8859-1 to " SMPP_DEFAULT_CHARSET ", will leave as is");
		msg->sms.coding = DC_7BIT;
		break;
	case 0x02: /* 8 bit binary - do nothing */
	case 0x04: /* 8 bit binary - do nothing */
		msg->sms.coding = DC_8BIT;
		break;
	case 0x05: /* JIS - what do I do with that ? */
		break;
	case 0x06: /* Cyrllic - iso-8859-5, I'll convert to unicode */
		if (charset_convert(msg->sms.msgdata, "ISO-8859-5", SMPP_DEFAULT_CHARSET) != 0)
			error(0, "Failed to convert msgdata from cyrllic to " SMPP_DEFAULT_CHARSET ", will leave as is");
		msg->sms.coding = DC_7BIT;
		break;
	case 0x07: /* Hebrew iso-8859-8, I'll convert to unicode */
		if (charset_convert(msg->sms.msgdata, "ISO-8859-8", SMPP_DEFAULT_CHARSET) != 0)
			error(0, "Failed to convert msgdata from hebrew to " SMPP_DEFAULT_CHARSET ", will leave as is");
		msg->sms.coding = DC_7BIT;
		break;
	case 0x08: /* unicode UCS-2, yey */
		msg->sms.coding = DC_UCS2;
		break;

		/*
		 * don't much care about the others,
		 * you implement them if you feel like it
		 */

	default:
		/*
		 * some of smsc send with dcs from GSM 03.38 , but these are reserved in smpp spec.
		 * So we just look decoded values from dcs_to_fields and if none there make our assumptions.
		 * if we have an UDH indicator, we assume DC_8BIT.
		 */
		if (msg->sms.coding == DC_UNDEF && pdu->u.data_sm.esm_class & ESM_CLASS_SUBMIT_UDH_INDICATOR)
			msg->sms.coding = DC_8BIT;
		else if (msg->sms.coding == DC_7BIT || msg->sms.coding == DC_UNDEF) { /* assume GSM 7Bit , reencode */
			msg->sms.coding = DC_7BIT;
			charset_gsm_to_utf8(msg->sms.msgdata);
		}
	}

	if (msg->sms.meta_data == NULL)
		msg->sms.meta_data = octstr_create("");
	meta_data_set_values(msg->sms.meta_data, pdu->u.data_sm.tlv, "smpp", 1);

	return msg;

	error: msg_destroy(msg);
	return NULL;
}

//static long smpp_status_to_smscconn_failure_reason(long status)
//{
//	switch (status)
//	{
//	case SMPP_ESME_RMSGQFUL:
//	case SMPP_ESME_RTHROTTLED:
//	case SMPP_ESME_RX_T_APPN:
//	case SMPP_ESME_RSYSERR:
//		return SMSCCONN_FAILED_TEMPORARILY;
//		break;
//
//	default:
//		return SMSCCONN_FAILED_REJECTED;
//	}
//}

static SMPP_PDU *msg_to_pdu(SMPP *smpp, Msg *msg) {
	SMPP_PDU *pdu;
	int validity;

	pdu = smpp_pdu_create(submit_sm, counter_increase(smpp->message_id_counter));

	pdu->u.submit_sm.source_addr = octstr_duplicate(msg->sms.sender);
	pdu->u.submit_sm.destination_addr = octstr_duplicate(msg->sms.receiver);

	/* Set the service type of the outgoing message. We'll use the config
	 * directive as default and 'binfo' as specific parameter. */
	pdu->u.submit_sm.service_type = octstr_len(msg->sms.binfo) ? octstr_duplicate(msg->sms.binfo) : octstr_duplicate(smpp->service_type);

	/* Check for manual override of source ton and npi values */
	if (smpp->source_addr_ton > -1 && smpp->source_addr_npi > -1) {
		pdu->u.submit_sm.source_addr_ton = smpp->source_addr_ton;
		pdu->u.submit_sm.source_addr_npi = smpp->source_addr_npi;
		debug("bb.sms.smpp", 0, "SMPP[%s]: Manually forced source addr ton = %d, source add npi = %d", octstr_get_cstr(smpp->smppbox_id),
				smpp->source_addr_ton, smpp->source_addr_npi);
	} else {
		/* setup default values */
		pdu->u.submit_sm.source_addr_ton = GSM_ADDR_TON_NATIONAL; /* national */
		pdu->u.submit_sm.source_addr_npi = GSM_ADDR_NPI_E164; /* ISDN number plan */
	}

	if (pdu->u.submit_sm.source_addr && smpp->autodetect_addr) {
		/* lets see if its international or alphanumeric sender */
		if (octstr_get_char(pdu->u.submit_sm.source_addr, 0) == '+') {
			if (!octstr_check_range(pdu->u.submit_sm.source_addr, 1, 256, gw_isdigit)) {
				pdu->u.submit_sm.source_addr_ton = GSM_ADDR_TON_ALPHANUMERIC; /* alphanum */
				pdu->u.submit_sm.source_addr_npi = GSM_ADDR_NPI_UNKNOWN; /* short code */
				if (smpp->alt_addr_charset) {
					if (octstr_str_case_compare(smpp->alt_addr_charset, "gsm") == 0) {
						/* @ would break PDU if converted into GSM*/
						octstr_replace(pdu->u.submit_sm.source_addr, octstr_imm("@"), octstr_imm("?"));
						charset_utf8_to_gsm(pdu->u.submit_sm.source_addr);
					} else if (charset_convert(pdu->u.submit_sm.source_addr, SMPP_DEFAULT_CHARSET, octstr_get_cstr(smpp->alt_addr_charset)) != 0)
						error(0, "Failed to convert source_addr from charset <%s> to <%s>, will send as is.", SMPP_DEFAULT_CHARSET,
								octstr_get_cstr(smpp->alt_addr_charset));
				}
			} else {
				/* numeric sender address with + in front -> international (remove the +) */
				octstr_delete(pdu->u.submit_sm.source_addr, 0, 1);
				pdu->u.submit_sm.source_addr_ton = GSM_ADDR_TON_INTERNATIONAL;
			}
		} else {
			if (!octstr_check_range(pdu->u.submit_sm.source_addr, 0, 256, gw_isdigit)) {
				pdu->u.submit_sm.source_addr_ton = GSM_ADDR_TON_ALPHANUMERIC;
				pdu->u.submit_sm.source_addr_npi = GSM_ADDR_NPI_UNKNOWN;
				if (smpp->alt_addr_charset) {
					if (octstr_str_case_compare(smpp->alt_addr_charset, "gsm") == 0) {
						/* @ would break PDU if converted into GSM */
						octstr_replace(pdu->u.submit_sm.source_addr, octstr_imm("@"), octstr_imm("?"));
						charset_utf8_to_gsm(pdu->u.submit_sm.source_addr);
					} else if (charset_convert(pdu->u.submit_sm.source_addr, SMPP_DEFAULT_CHARSET, octstr_get_cstr(smpp->alt_addr_charset)) != 0)
						error(0, "Failed to convert source_addr from charset <%s> to <%s>, will send as is.", SMPP_DEFAULT_CHARSET,
								octstr_get_cstr(smpp->alt_addr_charset));
				}
			}
		}
	}

	/* Check for manual override of destination ton and npi values */
	if (smpp->dest_addr_ton > -1 && smpp->dest_addr_npi > -1) {
		pdu->u.submit_sm.dest_addr_ton = smpp->dest_addr_ton;
		pdu->u.submit_sm.dest_addr_npi = smpp->dest_addr_npi;
		debug("bb.sms.smpp", 0, "SMPP[%s]: Manually forced dest addr ton = %d, dest add npi = %d", octstr_get_cstr(smpp->smppbox_id),
				smpp->dest_addr_ton, smpp->dest_addr_npi);
	} else {
		pdu->u.submit_sm.dest_addr_ton = GSM_ADDR_TON_NATIONAL; /* national */
		pdu->u.submit_sm.dest_addr_npi = GSM_ADDR_NPI_E164; /* ISDN number plan */
	}

	/*
	 * if its a international number starting with +, lets remove the
	 * '+' and set number type to international instead
	 */
	if (octstr_get_char(pdu->u.submit_sm.destination_addr, 0) == '+') {
		octstr_delete(pdu->u.submit_sm.destination_addr, 0, 1);
		pdu->u.submit_sm.dest_addr_ton = GSM_ADDR_TON_INTERNATIONAL;
	}

	/* check length of src/dst address */
	if (octstr_len(pdu->u.submit_sm.destination_addr) > 20 || octstr_len(pdu->u.submit_sm.source_addr) > 20) {
		smpp_pdu_destroy(pdu);
		return NULL;
	}

	/*
	 * set the data coding scheme (DCS) field
	 * check if we have a forced value for this from the smsc-group.
	 * Note: if message class is set, then we _must_ force alt_dcs otherwise
	 * dcs has reserved values (e.g. mclass=2, dcs=0x11). We check MWI flag
	 * first here, because MWI and MCLASS can not be set at the same time and
	 * function fields_to_dcs check MWI first, so we have no need to force alt_dcs
	 * if MWI is set.
	 */
	if (msg->sms.mwi == MWI_UNDEF && msg->sms.mclass != MC_UNDEF)
		pdu->u.submit_sm.data_coding = fields_to_dcs(msg, 1); /* force alt_dcs */
	else
		pdu->u.submit_sm.data_coding = fields_to_dcs(msg, (msg->sms.alt_dcs));

	/* set protocol id */
	if (msg->sms.pid != SMS_PARAM_UNDEFINED)
		pdu->u.submit_sm.protocol_id = msg->sms.pid;

	/*
	 * set the esm_class field
	 * default is store and forward, plus udh and rpi if requested
	 */
	pdu->u.submit_sm.esm_class = smpp->esm_class;
	if (octstr_len(msg->sms.udhdata))
		pdu->u.submit_sm.esm_class = pdu->u.submit_sm.esm_class | ESM_CLASS_SUBMIT_UDH_INDICATOR;
	if (msg->sms.rpi > 0)
		pdu->u.submit_sm.esm_class = pdu->u.submit_sm.esm_class | ESM_CLASS_SUBMIT_RPI;

	/*
	 * set data segments and length
	 */

	pdu->u.submit_sm.short_message = octstr_duplicate(msg->sms.msgdata);

	/*
	 * only re-encoding if using default smsc charset that is defined via
	 * alt-charset in smsc group and if MT is not binary
	 */
	if (msg->sms.coding == DC_7BIT || (msg->sms.coding == DC_UNDEF && octstr_len(msg->sms.udhdata) == 0)) {
		/*
		 * consider 3 cases:
		 *  a) data_coding 0xFX: encoding should always be GSM 03.38 charset
		 *  b) data_coding 0x00: encoding may be converted according to alt-charset
		 *  c) data_coding 0x00: assume GSM 03.38 charset if alt-charset is not defined
		 */
		if ((pdu->u.submit_sm.data_coding & 0xF0) || (pdu->u.submit_sm.data_coding == 0 && !smpp->alt_charset)) {
			charset_utf8_to_gsm(pdu->u.submit_sm.short_message);
		} else if (pdu->u.submit_sm.data_coding == 0 && smpp->alt_charset) {
			/*
			 * convert to the given alternative charset
			 */
			if (charset_convert(pdu->u.submit_sm.short_message, SMPP_DEFAULT_CHARSET, octstr_get_cstr(smpp->alt_charset)) != 0)
				error(0, "Failed to convert msgdata from charset <%s> to <%s>, will send as is.", SMPP_DEFAULT_CHARSET,
						octstr_get_cstr(smpp->alt_charset));
		}
	}

	/* prepend udh if present */
	if (octstr_len(msg->sms.udhdata)) {
		octstr_insert(pdu->u.submit_sm.short_message, msg->sms.udhdata, 0);
	}

	pdu->u.submit_sm.sm_length = octstr_len(pdu->u.submit_sm.short_message);

	/*
	 * check for validity and defered settings
	 * were message value has higher priiority then smsc config group value
	 * Note: we always send in UTC and just define "Time Difference" as 00 and
	 *       direction '+'.
	 */
	validity = msg->sms.validity != SMS_PARAM_UNDEFINED ? msg->sms.validity : smpp->validityperiod;
	if (validity != SMS_PARAM_UNDEFINED) {
		struct tm tm = gw_gmtime(time(NULL) + validity * 60);
		pdu->u.submit_sm.validity_period = octstr_format("%02d%02d%02d%02d%02d%02d000+", tm.tm_year % 100, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
				tm.tm_min, tm.tm_sec);
	}

	if (msg->sms.deferred != SMS_PARAM_UNDEFINED && msg->sms.deferred > 0) {
		struct tm tm = gw_gmtime(time(NULL) + msg->sms.deferred * 60);
		pdu->u.submit_sm.schedule_delivery_time = octstr_format("%02d%02d%02d%02d%02d%02d000+", tm.tm_year % 100, tm.tm_mon + 1, tm.tm_mday,
				tm.tm_hour, tm.tm_min, tm.tm_sec);
	}

	/* ask for the delivery reports if needed */
	if (DLR_IS_SUCCESS_OR_FAIL(msg->sms.dlr_mask))
		pdu->u.submit_sm.registered_delivery = 1;
	else if (DLR_IS_FAIL(msg->sms.dlr_mask) && !DLR_IS_SUCCESS(msg->sms.dlr_mask))
		pdu->u.submit_sm.registered_delivery = 2;

	if (DLR_IS_INTERMEDIATE(msg->sms.dlr_mask))
		pdu->u.submit_sm.registered_delivery += 16;

	/* set priority */
	if (msg->sms.priority >= 0 && msg->sms.priority <= 3)
		pdu->u.submit_sm.priority_flag = msg->sms.priority;
	else
		pdu->u.submit_sm.priority_flag = smpp->priority;

	/* set more messages to send */
	if (smpp->version > 0x33 && msg->sms.msg_left > 0)
		pdu->u.submit_sm.more_messages_to_send = 1;

	dict_destroy(pdu->u.submit_sm.tlv);
	pdu->u.submit_sm.tlv = meta_data_get_values(msg->sms.meta_data, "smpp");

	return pdu;
}

static int send_enquire_link(SMPP *smpp, Connection *conn, long *last_sent) {
	SMPP_PDU *pdu;
	Octstr *os;
	int ret;

	if (difftime(date_universal_now(), *last_sent) < smpp->enquire_link_interval)
		return 0;
	*last_sent = date_universal_now();

	pdu = smpp_pdu_create(enquire_link, counter_increase(smpp->message_id_counter));
	dump_pdu("Sending enquire link:", smpp->smppbox_id, pdu);
	os = smpp_pdu_pack(smpp->smppbox_id, pdu);
	if (os != NULL)
		ret = conn_write(conn, os); /* Write errors checked by caller. */
	else
		ret = -1;
	octstr_destroy(os);
	smpp_pdu_destroy(pdu);

	return ret;
}

static int send_gnack(SMPP *smpp, Connection *conn, long reason, unsigned long seq_num) {
	SMPP_PDU *pdu;
	Octstr *os;
	int ret;

	pdu = smpp_pdu_create(generic_nack, seq_num);
	pdu->u.generic_nack.command_status = reason;
	dump_pdu("Sending generic_nack:", smpp->smppbox_id, pdu);
	os = smpp_pdu_pack(smpp->smppbox_id, pdu);
	if (os != NULL)
		ret = conn_write(conn, os);
	else
		ret = -1;
	octstr_destroy(os);
	smpp_pdu_destroy(pdu);

	return ret;
}

static int send_unbind(SMPP *smpp, Connection *conn) {
	SMPP_PDU *pdu;
	Octstr *os;
	int ret;

	pdu = smpp_pdu_create(unbind, counter_increase(smpp->message_id_counter));
	dump_pdu("Sending unbind:", smpp->smppbox_id, pdu);
	os = smpp_pdu_pack(smpp->smppbox_id, pdu);
	if (os != NULL)
		ret = conn_write(conn, os);
	else
		ret = -1;
	octstr_destroy(os);
	smpp_pdu_destroy(pdu);

	return ret;
}

static int send_pdu(Connection *conn, Octstr *id, SMPP_PDU *pdu) {
	Octstr *os;
	int ret;

	dump_pdu("Sending PDU:", id, pdu);
	os = smpp_pdu_pack(id, pdu);
	if (os) {
		/* Caller checks for write errors later */
		ret = conn_write(conn, os);
		/* it's not a error if we still have data buffered */
		ret = (ret == 1) ? 0 : ret;
	} else
		ret = -1;
	octstr_destroy(os);
	return ret;
}

/*
 * Open transmission connection to SMS center. Return NULL for error,
 * open Connection for OK. Caller must set smpp->conn->status correctly
 * before calling this.
 */
static Connection *open_transmitter(SMPP *smpp) {
	SMPP_PDU *bind;
	Connection *conn;

	/*
	 #ifdef HAVE_LIBSSL
	 if (smpp->use_ssl)
	 conn = conn_open_ssl(smpp->host, smpp->transmit_port, smpp->ssl_client_certkey_file, smpp->our_host);
	 else
	 #endif
	 */
	conn = conn_open_tcp(smpp->host, smpp->port, smpp->our_host);
	if (conn == NULL) {
		error(0, "SMPP[%s]: Couldn't connect to server.", octstr_get_cstr(smpp->smppbox_id));
		return NULL;
	}

	bind = smpp_pdu_create(bind_transmitter, counter_increase(smpp->message_id_counter));
	bind->u.bind_transmitter.system_id = octstr_duplicate(smpp->username);
	bind->u.bind_transmitter.password = octstr_duplicate(smpp->password);
	if (smpp->system_type == NULL)
		bind->u.bind_transmitter.system_type = octstr_create("VMA");
	else
		bind->u.bind_transmitter.system_type = octstr_duplicate(smpp->system_type);
	bind->u.bind_transmitter.interface_version = smpp->version;
	bind->u.bind_transmitter.address_range = octstr_duplicate(smpp->address_range);
	bind->u.bind_transmitter.addr_ton = smpp->bind_addr_ton;
	bind->u.bind_transmitter.addr_npi = smpp->bind_addr_npi;
	if (send_pdu(conn, smpp->smppbox_id, bind) == -1) {
		error(0, "SMPP[%s]: Couldn't send bind_transmitter to server.", octstr_get_cstr(smpp->smppbox_id));
		conn_destroy(conn);
		conn = NULL;
	}
	smpp_pdu_destroy(bind);

	return conn;
}

/*
 * Open transceiver connection to SMS center. Return NULL for error,
 * open Connection for OK. Caller must set smpp->conn->status correctly
 * before calling this.
 */
static Connection *open_transceiver(SMPP *smpp) {
	SMPP_PDU *bind;
	Connection *conn;

	conn = conn_open_tcp(smpp->host, smpp->port, smpp->our_host);
	if (conn == NULL) {
		error(0, "SMPP[%s]: Couldn't connect to server.", octstr_get_cstr(smpp->smppbox_id));
		return NULL;
	}

	bind = smpp_pdu_create(bind_transceiver, counter_increase(smpp->message_id_counter));
	bind->u.bind_transceiver.system_id = octstr_duplicate(smpp->username);
	bind->u.bind_transceiver.password = octstr_duplicate(smpp->password);
	if (smpp->system_type == NULL)
		bind->u.bind_transceiver.system_type = octstr_create("VMA");
	else
		bind->u.bind_transceiver.system_type = octstr_duplicate(smpp->system_type);
	bind->u.bind_transceiver.interface_version = smpp->version;
	bind->u.bind_transceiver.address_range = octstr_duplicate(smpp->address_range);
	bind->u.bind_transceiver.addr_ton = smpp->bind_addr_ton;
	bind->u.bind_transceiver.addr_npi = smpp->bind_addr_npi;
	if (send_pdu(conn, smpp->smppbox_id, bind) == -1) {
		error(0, "SMPP[%s]: Couldn't send bind_transceiver to server.", octstr_get_cstr(smpp->smppbox_id));
		conn_destroy(conn);
		conn = NULL;
	}
	smpp_pdu_destroy(bind);

	return conn;
}

/*
 * Open reception connection to SMS center. Return NULL for error,
 * open Connection for OK. Caller must set smpp->conn->status correctly
 * before calling this.
 */
static Connection *open_receiver(SMPP *smpp) {
	SMPP_PDU *bind;
	Connection *conn;

	conn = conn_open_tcp(smpp->host, smpp->port, smpp->our_host);
	if (conn == NULL) {
		error(0, "SMPP[%s]: Couldn't connect to server.", octstr_get_cstr(smpp->smppbox_id));
		return NULL;
	}

	bind = smpp_pdu_create(bind_receiver, counter_increase(smpp->message_id_counter));
	bind->u.bind_receiver.system_id = octstr_duplicate(smpp->username);
	bind->u.bind_receiver.password = octstr_duplicate(smpp->password);
	if (smpp->system_type == NULL)
		bind->u.bind_receiver.system_type = octstr_create("VMA");
	else
		bind->u.bind_receiver.system_type = octstr_duplicate(smpp->system_type);
	bind->u.bind_receiver.interface_version = smpp->version;
	bind->u.bind_receiver.address_range = octstr_duplicate(smpp->address_range);
	bind->u.bind_receiver.addr_ton = smpp->bind_addr_ton;
	bind->u.bind_receiver.addr_npi = smpp->bind_addr_npi;
	if (send_pdu(conn, smpp->smppbox_id, bind) == -1) {
		error(0, "SMPP[%s]: Couldn't send bind_receiver to server.", octstr_get_cstr(smpp->smppbox_id));
		conn_destroy(conn);
		conn = NULL;
	}
	smpp_pdu_destroy(bind);

	return conn;
}

/*
 * See SMPP v5.0 spec [http://www.smsforum.net/smppv50.pdf.zip],
 * section 4.8.4.42 network_error_code for correct encoding.
 */
static int error_from_network_error_code(Octstr *network_error_code) {
	unsigned char *nec;
	int type;
	int err;

	if (network_error_code == NULL || octstr_len(network_error_code) != 3)
		return 0;

	nec = (unsigned char*) octstr_get_cstr(network_error_code);
	type = nec[0];
	err = (nec[1] << 8) | nec[2];

	if ((type >= '0') && (type <= '9')) {
		/* this is a bogous SMSC sending back network_error_code as
		 * 3 digit string instead as in the delivery report. */
		sscanf((char*) nec, "%03d", &err);
		return err;
	}

	return err;
}

static Msg *handle_dlr(SMPP *smpp, Octstr *destination_addr, Octstr *short_message, Octstr *message_payload, Octstr *receipted_message_id,
		long message_state, Octstr *network_error_code) {
	Msg *dlrmsg = NULL;
	Octstr *respstr = NULL, *msgid = NULL, *network_err = NULL, *dlr_err = NULL, *tmp;
	int dlrstat = -1;
	int err_int = 0;

	/* first check for SMPP v3.4 and above */
	if (smpp->version > 0x33 && receipted_message_id) {
		msgid = octstr_duplicate(receipted_message_id);
		switch (message_state) {
		case 1: /* ENROUTE */
		case 6: /* ACCEPTED */
			dlrstat = DLR_BUFFERED;
			break;
		case 2: /* DELIVERED */
			dlrstat = DLR_SUCCESS;
			break;
		case 3: /* EXPIRED */
		case 4: /* DELETED */
		case 5: /* UNDELIVERABLE */
		case 7: /* UNKNOWN */
		case 8: /* REJECTED */
			dlrstat = DLR_FAIL;
			break;
		case -1: /* message state is not present, partial SMPP v3.4 */
			debug("bb.sms.smpp", 0, "SMPP[%s]: Partial SMPP v3.4, receipted_message_id present but not message_state.",
					octstr_get_cstr(smpp->smppbox_id));
			dlrstat = -1;
			break;
		default:
			warning(0, "SMPP[%s]: Got DLR with unknown 'message_state' (%ld).", octstr_get_cstr(smpp->smppbox_id), message_state);
			dlrstat = DLR_FAIL;
			break;
		}
	}

	if (network_error_code != NULL) {
		err_int = error_from_network_error_code(network_error_code);
		network_err = octstr_duplicate(network_error_code);
	}

	/* check for SMPP v.3.4. and message_payload */
	if (smpp->version > 0x33 && octstr_len(short_message) == 0)
		respstr = message_payload;
	else
		respstr = short_message;

	if (msgid == NULL || network_err == NULL || dlrstat == -1) {
		/* parse the respstr if it exists */
		if (respstr) {
			long curr = 0, vpos = 0;
			Octstr *stat = NULL;
			char id_cstr[65], stat_cstr[16], sub_d_cstr[15], done_d_cstr[15];
			char err_cstr[4];
			int sub, dlrvrd, ret;

			/* get server message id */
			/* first try sscanf way if thus failed then old way */
			ret = sscanf(octstr_get_cstr(respstr), "id:%64[^s] sub:%d dlvrd:%d submit date:%14[0-9] done "
					"date:%14[0-9] stat:%15[^t^e] err:%3[^t]", id_cstr, &sub, &dlrvrd, sub_d_cstr, done_d_cstr, stat_cstr, err_cstr);
			if (ret == 7) {
				/* only if not already here */
				if (msgid == NULL) {
					msgid = octstr_create(id_cstr);
					octstr_strip_blanks(msgid);
				}
				stat = octstr_create(stat_cstr);
				octstr_strip_blanks(stat);
				sscanf(err_cstr, "%d", &err_int);
				dlr_err = octstr_create(err_cstr);
				octstr_strip_blanks(dlr_err);
			} else {
				debug("bb.sms.smpp", 0, "SMPP[%s]: Couldnot parse DLR string sscanf way,"
						"fallback to old way. Please report!", octstr_get_cstr(smpp->smppbox_id));

				/* only if not already here */
				if (msgid == NULL) {
					if ((curr = octstr_search(respstr, octstr_imm("id:"), 0)) != -1) {
						vpos = octstr_search_char(respstr, ' ', curr);
						if ((vpos - curr > 0) && (vpos != -1))
							msgid = octstr_copy(respstr, curr+3, vpos-curr-3);
					} else {
						msgid = NULL;
					}
				}

				/* get err & status code */
				if ((curr = octstr_search(respstr, octstr_imm("stat:"), 0)) != -1) {
					vpos = octstr_search_char(respstr, ' ', curr);
					if ((vpos - curr > 0) && (vpos != -1))
						stat = octstr_copy(respstr, curr+5, vpos-curr-5);
				} else {
					stat = NULL;
				}
				if ((curr = octstr_search(respstr, octstr_imm("err:"), 0)) != -1) {
					vpos = octstr_search_char(respstr, ' ', curr);
					if ((vpos - curr > 0) && (vpos != -1))
						dlr_err = octstr_copy(respstr, curr+4, vpos-curr-4);
				} else {
					dlr_err = NULL;
				}
			}

			/*
			 * we get the following status:
			 * DELIVRD, ACCEPTD, EXPIRED, DELETED, UNDELIV, UNKNOWN, REJECTD
			 *
			 * Note: some buggy SMSC's send us immediately delivery notifications although
			 *          we doesn't requested these.
			 */
			if (dlrstat == -1) {
				if (stat != NULL && octstr_compare(stat, octstr_imm("DELIVRD")) == 0)
					dlrstat = DLR_SUCCESS;
				else if (stat != NULL
						&& (octstr_compare(stat, octstr_imm("ACCEPTD")) == 0 || octstr_compare(stat, octstr_imm("ACKED")) == 0
								|| octstr_compare(stat, octstr_imm("BUFFRED")) == 0 || octstr_compare(stat, octstr_imm("BUFFERD")) == 0
								|| octstr_compare(stat, octstr_imm("ENROUTE")) == 0))
					dlrstat = DLR_BUFFERED;
				else
					dlrstat = DLR_FAIL;
			}
			octstr_destroy(stat);
		}
	}

	if (msgid != NULL && dlrstat != -1) {
		/*
		 * Obey which SMPP msg_id type this SMSC is using, where we
		 * have the following semantics for the variable smpp_msg_id:
		 *
		 * bit 1: type for submit_sm_resp, bit 2: type for deliver_sm
		 *
		 * if bit is set value is hex otherwise dec
		 *
		 * 0x00 deliver_sm dec, submit_sm_resp dec
		 * 0x01 deliver_sm dec, submit_sm_resp hex
		 * 0x02 deliver_sm hex, submit_sm_resp dec
		 * 0x03 deliver_sm hex, submit_sm_resp hex
		 *
		 * Default behaviour is SMPP spec compliant, which means
		 * msg_ids should be C strings and hence non modified.
		 */
		if (smpp->smpp_msg_id_type == -1) {
			/* the default, C string */
			tmp = octstr_duplicate(msgid);
		} else {
			if ((smpp->smpp_msg_id_type & 0x02) || (!octstr_check_range(msgid, 0, octstr_len(msgid), gw_isdigit))) {
				tmp = octstr_format("%llu", strtoll(octstr_get_cstr(msgid), NULL, 16));
			} else {
				tmp = octstr_format("%llu", strtoll(octstr_get_cstr(msgid), NULL, 10));
			}
		}

		dlrmsg = dlr_find(smpp->smppbox_id, tmp, /* smsc message id */
		destination_addr, /* destination */
		dlrstat, 0);

		octstr_destroy(msgid);
	} else
		tmp = octstr_create("");

	if (network_err == NULL && dlr_err != NULL) {
		unsigned char ctmp[3];

		ctmp[0] = 3; /* we assume here its a GSM error due to lack of other information */
		ctmp[1] = (err_int >> 8) & 0xFF;
		ctmp[2] = (err_int & 0xFF);
		network_err = octstr_create_from_data((char*)ctmp, 3);
	}

	if (dlrmsg != NULL) {
		/*
		 * we found the delivery report in our storage, so recode the
		 * message structure.
		 * The DLR trigger URL is indicated by msg->sms.dlr_url.
		 * Add the DLR error code to meta-data.
		 */
		dlrmsg->sms.msgdata = octstr_duplicate(respstr);
		dlrmsg->sms.sms_type = report_mo;
		dlrmsg->sms.account = octstr_duplicate(smpp->username);
		if (network_err != NULL) {
			if (dlrmsg->sms.meta_data == NULL) {
				dlrmsg->sms.meta_data = octstr_create("");
			}
			meta_data_set_value(dlrmsg->sms.meta_data, "smpp", octstr_imm("dlr_err"), network_err, 1);
		}
	} else {
		error(0, "SMPP[%s]: got DLR but could not find message or was not interested "
				"in it id<%s> dst<%s>, type<%d>", octstr_get_cstr(smpp->smppbox_id), octstr_get_cstr(tmp), octstr_get_cstr(destination_addr),
				dlrstat);
	}
	octstr_destroy(tmp);
	octstr_destroy(network_err);
	octstr_destroy(dlr_err);

	return dlrmsg;
}

static int handle_pdu(SMPP *smpp, Connection *conn, SMPP_PDU *pdu, long *pending_submits) {
	SMPP_PDU *resp = NULL;
	Octstr *os;
	Msg *msg = NULL, *dlrmsg = NULL;
	struct smpp_msg *smpp_msg = NULL;
	Message *message=NULL;
	long reason, cmd_stat;
	int ret = 0;
	Message *removedMessage=NULL;

	switch (pdu->type) {
	case data_sm:
		resp = smpp_pdu_create(data_sm_resp, pdu->u.data_sm.sequence_number);
		/* got a deliver ack (DLR)?
		 * NOTE: following SMPP v3.4. spec. we are interested
		 *       only on bits 2-5 (some SMSC's send 0x44, and it's
		 *       spec. conforme)
		 */
		if (pdu->u.data_sm.esm_class & (0x04 | 0x08 | 0x20)) {
			debug("bb.sms.smpp", 0, "SMPP[%s] handle_pdu, got DLR", octstr_get_cstr(smpp->smppbox_id));
			dlrmsg = handle_dlr(smpp, pdu->u.data_sm.source_addr, NULL, pdu->u.data_sm.message_payload, pdu->u.data_sm.receipted_message_id,
					pdu->u.data_sm.message_state, pdu->u.data_sm.network_error_code);
			if (dlrmsg != NULL) {
				if (dlrmsg->sms.meta_data == NULL)
					dlrmsg->sms.meta_data = octstr_create("");
				meta_data_set_values(dlrmsg->sms.meta_data, pdu->u.data_sm.tlv, "smpp", 0);
				/* passing DLR to upper layer */
//				reason = bb_smscconn_receive(smpp->conn, dlrmsg);
			} else {
				/* no DLR will be passed, but we write an access-log entry */
//				reason = SMSCCONN_SUCCESS;
				msg = data_sm_to_msg(smpp, pdu, &reason);
//				bb_alog_sms(smpp->conn, msg, "FAILED DLR SMS");
				msg_destroy(msg);
			}
//			resp->u.data_sm_resp.command_status = smscconn_failure_reason_to_smpp_status(reason);
		} else { /* MO message */
			msg = data_sm_to_msg(smpp, pdu, &reason);
			if (msg == NULL || reason != SMPP_ESME_ROK) {
				resp->u.data_sm_resp.command_status = reason;
				break;
			}
			/* Replace MO destination number with my-number */
			if (octstr_len(smpp->my_number)) {
				octstr_destroy(msg->sms.receiver);
				msg->sms.receiver = octstr_duplicate(smpp->my_number);
			}
			time(&msg->sms.time);
			msg->sms.smsc_id = octstr_duplicate(smpp->smppbox_id);
//			reason = bb_smscconn_receive(smpp->conn, msg);
//			resp->u.data_sm_resp.command_status = smscconn_failure_reason_to_smpp_status(reason);
		}
		break;

	case deliver_sm:
		/*
		 * Got a deliver ack (DLR)?
		 * NOTE: following SMPP v3.4. spec. we are interested
		 *       only on bits 2-5 (some SMSC's send 0x44, and it's
		 *       spec. conforme)
		 */
		if (pdu->u.deliver_sm.esm_class & (0x04 | 0x08 | 0x20)) {

			debug("bb.sms.smpp", 0, "SMPP[%s] handle_pdu, got DLR", octstr_get_cstr(smpp->smppbox_id));

			dlrmsg = handle_dlr(smpp, pdu->u.deliver_sm.source_addr, pdu->u.deliver_sm.short_message, pdu->u.deliver_sm.message_payload,
					pdu->u.deliver_sm.receipted_message_id, pdu->u.deliver_sm.message_state, pdu->u.deliver_sm.network_error_code);
			resp = smpp_pdu_create(deliver_sm_resp, pdu->u.deliver_sm.sequence_number);
			if (dlrmsg != NULL) {
				if (dlrmsg->sms.meta_data == NULL)
					dlrmsg->sms.meta_data = octstr_create("");
				meta_data_set_values(dlrmsg->sms.meta_data, pdu->u.deliver_sm.tlv, "smpp", 0);
//				reason = bb_smscconn_receive(smpp->conn, dlrmsg);
			}
//			else
//				reason = SMSCCONN_SUCCESS;
//			resp->u.deliver_sm_resp.command_status = smscconn_failure_reason_to_smpp_status(reason);
		} else {/* MO-SMS */
			resp = smpp_pdu_create(deliver_sm_resp, pdu->u.deliver_sm.sequence_number);
			/* ensure the smsc-id is set */
			msg = pdu_to_msg(smpp, pdu, &reason);
			if (msg == NULL) {
				resp->u.deliver_sm_resp.command_status = reason;
				break;
			}

			/* Replace MO destination number with my-number */
			if (octstr_len(smpp->my_number)) {
				octstr_destroy(msg->sms.receiver);
				msg->sms.receiver = octstr_duplicate(smpp->my_number);
			}

			time(&msg->sms.time);
			msg->sms.smsc_id = octstr_duplicate(smpp->smppbox_id);

			Service *service;
			service = serviceCreate();
			if (searchService(service, msg->sms.receiver, carrierId)) {
				//Buscar Servicio
				mysql_update(
						octstr_format(SQL_INSERT_MO, msg->sms.sender, msg->sms.receiver, "0", msg->sms.msgdata, "QUEUED", service->errorCode, service->errorText, service->id, service->name,
								service->carrierId, service->integratorId, service->integratorQueueId));
			} else {
				debug("smppServer", 0, "No existe servicio");
				mysql_update(
						octstr_format(SQL_INSERT_MO, msg->sms.sender, msg->sms.receiver, "0", msg->sms.msgdata, "NOTDISPATCHED", service->errorCode, service->errorText, service->id, service->name,
								service->carrierId, service->integratorId, service->integratorQueueId));
			}

			msg->sms.account = octstr_duplicate(smpp->username);

//			reason = bb_smscconn_receive(smpp->conn, msg);
//			resp->u.deliver_sm_resp.command_status = smscconn_failure_reason_to_smpp_status(reason);
		}
		break;

	case enquire_link:
		resp = smpp_pdu_create(enquire_link_resp, pdu->u.enquire_link.sequence_number);
		break;

	case enquire_link_resp:
		if (pdu->u.enquire_link_resp.command_status != 0) {
			error(0, "SMPP[%s]: SMSC got error to enquire_link, code 0x%08lx (%s).", octstr_get_cstr(smpp->smppbox_id),
					pdu->u.enquire_link_resp.command_status, smpp_error_to_string(pdu->u.enquire_link_resp.command_status));
		}
		break;

	case submit_sm_resp:

		os = octstr_format("%ld", pdu->u.submit_sm_resp.sequence_number);
		message = dict_get(smpp->sent_msgs, os);
		removedMessage = dict_remove(smpp->sent_msgs, os);


		octstr_destroy(os);
		if (removedMessage == NULL) {
			warning(0, "SMPP[%s]: SMSC sent submit_sm_resp "
					"with wrong sequence number 0x%08lx", octstr_get_cstr(smpp->smppbox_id), pdu->u.submit_sm_resp.sequence_number);
			break;
		}

		if (pdu->u.submit_sm_resp.command_status != 0) {
			error(0, "SMPP[%s]: SMSC returned error code 0x%08lx (%s) "
					"in response to submit_sm.", octstr_get_cstr(smpp->smppbox_id), pdu->u.submit_sm_resp.command_status,
					smpp_error_to_string(pdu->u.submit_sm_resp.command_status));
//			reason = smpp_status_to_smscconn_failure_reason(pdu->u.submit_sm_resp.command_status);

			/*
			 * check to see if we got a "throttling error", in which case we'll just
			 * sleep for a while
			 */
			if (pdu->u.submit_sm_resp.command_status == SMPP_ESME_RTHROTTLED)
				time(&(smpp->throttling_err_time));
			else
				smpp->throttling_err_time = 0;

		} else {
			mysql_update(octstr_format(SQL_UPDATE_MT_STATUS_, "CONFIRMED", octstr_get_cstr(pdu->u.submit_sm_resp.message_id),octstr_get_cstr(message->id)));
		} /* end if for SMSC ACK */
		break;

	case bind_transmitter_resp:
		if (pdu->u.bind_transmitter_resp.command_status != 0 && pdu->u.bind_transmitter_resp.command_status != SMPP_ESME_RALYNBD) {
			error(0, "SMPP[%s]: SMSC rejected login to transmit, code 0x%08lx (%s).", octstr_get_cstr(smpp->smppbox_id),
					pdu->u.bind_transmitter_resp.command_status, smpp_error_to_string(pdu->u.bind_transmitter_resp.command_status));
			if (pdu->u.bind_transmitter_resp.command_status == SMPP_ESME_RINVSYSID
					|| pdu->u.bind_transmitter_resp.command_status == SMPP_ESME_RINVPASWD
					|| pdu->u.bind_transmitter_resp.command_status == SMPP_ESME_RINVSYSTYP) {
				smpp->quitting = 1;
			}
		} else {
			*pending_submits = 0;
		}
		break;

	case bind_transceiver_resp:
		if (pdu->u.bind_transceiver_resp.command_status != 0 && pdu->u.bind_transceiver_resp.command_status != SMPP_ESME_RALYNBD) {
			error(0, "SMPP[%s]: SMSC rejected login to transmit, code 0x%08lx (%s).", octstr_get_cstr(smpp->smppbox_id),
					pdu->u.bind_transceiver_resp.command_status, smpp_error_to_string(pdu->u.bind_transceiver_resp.command_status));
			if (pdu->u.bind_transceiver_resp.command_status == SMPP_ESME_RINVSYSID
					|| pdu->u.bind_transceiver_resp.command_status == SMPP_ESME_RINVPASWD
					|| pdu->u.bind_transceiver_resp.command_status == SMPP_ESME_RINVSYSTYP) {
				smpp->quitting = 1;
			}
		} else {
			*pending_submits = 0;
		}
		break;

	case bind_receiver_resp:
		if (pdu->u.bind_receiver_resp.command_status != 0 && pdu->u.bind_receiver_resp.command_status != SMPP_ESME_RALYNBD) {
			error(0, "SMPP[%s]: SMSC rejected login to receive, code 0x%08lx (%s).", octstr_get_cstr(smpp->smppbox_id),
					pdu->u.bind_receiver_resp.command_status, smpp_error_to_string(pdu->u.bind_receiver_resp.command_status));

			if (pdu->u.bind_receiver_resp.command_status == SMPP_ESME_RINVSYSID || pdu->u.bind_receiver_resp.command_status == SMPP_ESME_RINVPASWD
					|| pdu->u.bind_receiver_resp.command_status == SMPP_ESME_RINVSYSTYP) {
				smpp->quitting = 1;
			}
		} else {

		}
		break;

	case unbind:
		resp = smpp_pdu_create(unbind_resp, pdu->u.unbind.sequence_number);

		*pending_submits = -1;
		break;

	case unbind_resp:
		//smpp->conn = NULL;
		break;

	case generic_nack:
		cmd_stat = pdu->u.generic_nack.command_status;

		os = octstr_format("%ld", pdu->u.generic_nack.sequence_number);
		smpp_msg = dict_remove(smpp->sent_msgs, os);
		octstr_destroy(os);

		if (smpp_msg == NULL) {
			error(0, "SMPP[%s]: SMSC rejected last command, code 0x%08lx (%s).", octstr_get_cstr(smpp->smppbox_id), cmd_stat,
					smpp_error_to_string(cmd_stat));
		} else {
			msg = smpp_msg->msg;
			smpp_msg_destroy(smpp_msg, 0);

			error(0, "SMPP[%s]: SMSC returned error code 0x%08lx (%s) in response to submit_sm.", octstr_get_cstr(smpp->smppbox_id), cmd_stat,
					smpp_error_to_string(cmd_stat));

			/*
			 * check to see if we got a "throttling error", in which case we'll just
			 * sleep for a while
			 */
			if (cmd_stat == SMPP_ESME_RTHROTTLED)
				time(&(smpp->throttling_err_time));
			else
				smpp->throttling_err_time = 0;

		}
		break;

	default:
		error(0, "SMPP[%s]: Unknown PDU type 0x%08lx, ignored.", octstr_get_cstr(smpp->smppbox_id), pdu->type);
		/*
		 * We received an unknown PDU type, therefore we will respond
		 * with a generic_nack PDU, see SMPP v3.4 spec, section 3.3.
		 */
		ret = send_gnack(smpp, conn, SMPP_ESME_RINVCMDID, pdu->u.generic_nack.sequence_number);
		break;
	}

	if (resp != NULL) {
		ret = send_pdu(conn, smpp->smppbox_id, resp) != -1 ? 0 : -1;
		smpp_pdu_destroy(resp);
	}

	return ret;
}

int searchService(Service *service,Octstr *shortNumber,Octstr *carrierId) {
	Octstr *sql;
	MYSQL_RES *res;
	MYSQL_ROW row;

	int result;

	sql = octstr_format(SQL_SELECT_SERVICE,octstr_get_cstr(shortNumber), octstr_get_cstr(carrierId));
	res = mysql_select(sql);

	if (res == NULL) {
		debug("SQLBOX", 0, "SQL statement failed: %s", octstr_get_cstr(sql));
	} else {
		if (mysql_num_rows(res) >= 1) {
			row = mysql_fetch_row(res);
			service->id = octstr_imm(row[0]);
			service->name = octstr_imm(row[1]);
			service->integratorId = octstr_imm(row[2]);
			service->integratorQueueId = octstr_imm(row[3]);
			service->carrierId = octstr_imm(row[4]);
			service->errorCode = 0;
			service->errorText = octstr_format("");
			result = 1;
		} else {
			service->errorCode = 1012;
			service->errorText = octstr_format("No service to the message");
			result = 0;
		}
		mysql_free_result(res);
	}
	octstr_destroy(sql);
	return result;

}

struct io_arg {
	SMPP *smpp;
	int transmitter;
	int port;
};

static void init_smpp_client_box(Cfg *cfg) {

	CfgGroup *grp;
	Octstr *log_file;
	long log_level;

	Octstr *smsc_id;
	Octstr *our_host;/* local device IP to bind for TCP communication */

	/* Our smsc specific log-file data */
	//	int log_idx; /* index position within the global logfiles[] array in gwlib/log.c */
	/* initialize low level PDUs */
	if (smpp_pdu_init(cfg) == -1)
		panic(0, "Connot start with PDU init failed.");

	my_number = alt_addr_charset = alt_charset = NULL;
	transceiver_mode = 0;
	receiver_mode = 0;
	transmitter_mode = 0,

	autodetect_addr = 1;
	grp = cfg_get_single_group(cfg, octstr_imm("smppClient"));

	smppbox_id = cfg_get(grp, octstr_imm("smppClient-id"));
	carrierId = cfg_get(grp, octstr_imm("carrier-id"));

	host = cfg_get(grp, octstr_imm("host"));
	our_host = cfg_get(grp, octstr_imm("our_host"));
	if (cfg_get_integer(&port, grp, octstr_imm("port")) == -1)
		port = 0;
	/* setup logfile stuff */
	log_file = cfg_get(grp, octstr_imm("log-file"));
	if (cfg_get_integer(&log_level, grp, octstr_imm("log-level")) == -1)
		log_level = 0;
	if (log_file != NULL) {
		info(0, "Starting to log to file %s level %ld", octstr_get_cstr(log_file), log_level);
		log_open(octstr_get_cstr(log_file), log_level, GW_NON_EXCL);

	}
	if (cfg_get_integer(&reconnect_delay, grp, octstr_imm("reconnect-delay")) == -1)
		reconnect_delay = SMSCCONN_RECONNECT_DELAY;
	cfg_get_bool(&transceiver_mode, grp, octstr_imm("transceiver-mode"));
	if (cfg_get_bool(&receiver_mode, grp, octstr_imm("receiver-mode")) == -1
			& cfg_get_bool(&transmitter_mode, grp, octstr_imm("transmitter-mode")) == -1) {
		panic(0, "Connection should be receiver mode or transmitter mode");
	} else if (receiver_mode == 1 && transmitter_mode == 1) {
		panic(0, "Connection should be receiver mode or transmitter mode");
	}

	username = cfg_get(grp, octstr_imm("smsc-username"));
	password = cfg_get(grp, octstr_imm("smsc-password"));
	system_type = cfg_get(grp, octstr_imm("system-type"));
	address_range = cfg_get(grp, octstr_imm("address-range"));
	my_number = cfg_get(grp, octstr_imm("my-number"));
	service_type = cfg_get(grp, octstr_imm("service-type"));

	system_id = cfg_get(grp, octstr_imm("system-id"));
	if (system_id != NULL) {
		warning(0, "SMPP: obsolete system-id variable is set, "
				"use smsc-username instead.");
		if (username == NULL) {
			warning(0, "SMPP: smsc-username not set, using system-id instead");
			username = system_id;
		} else
			octstr_destroy(system_id);
	}

	/*
	 * check if timing values have been configured, otherwise
	 * use the predefined default values.
	 */
	if (cfg_get_integer(&enquire_link_interval, grp, octstr_imm("enquire-link-interval")) == -1)
		enquire_link_interval = SMPP_ENQUIRE_LINK_INTERVAL;
	if (cfg_get_integer(&max_pending_submits, grp, octstr_imm("max-pending-submits")) == -1)
		max_pending_submits = SMPP_MAX_PENDING_SUBMITS;

	/* Check that config is OK */
	if (host == NULL) {
		panic(0, "SMPP: Configuration file doesn't specify host");
	}
	if (username == NULL) {
		panic(0, "SMPP: Configuration file doesn't specify username.");
	}
	if (password == NULL) {
		panic(0, "SMPP: Configuration file doesn't specify password.");
	}
	if (system_type == NULL) {
		panic(0, "SMPP: Configuration file doesn't specify system-type.");
	}
	if (octstr_len(service_type) > 6) {
		panic(0, "SMPP: Service type must be 6 characters or less.");
	}

	/* if the ton and npi values are forced, set them, else set them to -1 */
	if (cfg_get_integer(&source_addr_ton, grp, octstr_imm("source-addr-ton")) == -1)
		source_addr_ton = -1;
	if (cfg_get_integer(&source_addr_npi, grp, octstr_imm("source-addr-npi")) == -1)
		source_addr_npi = -1;
	if (cfg_get_integer(&dest_addr_ton, grp, octstr_imm("dest-addr-ton")) == -1)
		dest_addr_ton = -1;
	if (cfg_get_integer(&dest_addr_npi, grp, octstr_imm("dest-addr-npi")) == -1)
		dest_addr_npi = -1;

	/* if source addr autodetection should be used set this to 1 */
	if (cfg_get_bool(&autodetect_addr, grp, octstr_imm("source-addr-autodetect")) == -1)
		autodetect_addr = 1; /* default is autodetect if no option defined */

	/* check for any specified interface version */
	if (cfg_get_integer(&version, grp, octstr_imm("interface-version")) == -1)
		version = SMPP_DEFAULT_VERSION;
	else
		/* convert decimal to BCD */
		version = ((version / 10) << 4) + (version % 10);

	/* check for connection timeout */
	if (cfg_get_integer(&connection_timeout, grp, octstr_imm("connection-timeout")) == -1)
		connection_timeout = SMPP_DEFAULT_CONNECTION_TIMEOUT;

	smpp = smpp_create(smppbox_id, our_host, reconnect_delay, host, port, system_type, username, password, address_range, source_addr_ton,
			source_addr_npi, dest_addr_ton, dest_addr_npi, enquire_link_interval, max_pending_submits, version, priority, validity, my_number,
			smpp_msg_id_type, autodetect_addr, alt_charset, alt_addr_charset, service_type, connection_timeout, wait_ack, wait_ack_action, esm_class);
	cfg_get_integer(&smpp->bind_addr_ton, grp, octstr_imm("bind-addr-ton"));
	cfg_get_integer(&smpp->bind_addr_npi, grp, octstr_imm("bind-addr-npi"));

	debug("smppClient", 0, "==========Configuration Parameters============");
	debug("smppClient", 0, "===> smppClient-id:          %s ", octstr_get_cstr(smppbox_id));
	debug("smppClient", 0, "===> carrier-id:             %s ", octstr_get_cstr(carrierId));
	debug("smppClient", 0, "===> mode:                   %s ", (transmitter_mode ? "TX" : "RX"));
	debug("smppClient", 0, "===> our_host:               %s ", octstr_get_cstr(our_host));
	debug("smppClient", 0, "===> host:                   %s ", octstr_get_cstr(host));
	debug("smppClient", 0, "===> port:                   %ld", port);
	debug("smppClient", 0, "===> smsc-username:          %s ", octstr_get_cstr(username));
	debug("smppClient", 0, "===> smsc-password:          %s ", octstr_get_cstr(password));
	debug("smppClient", 0, "===> system-type:            %s ", octstr_get_cstr(system_type));
	debug("smppClient", 0, "===> reconnect-delay:        %ld", reconnect_delay);
	debug("smppClient", 0, "===> log-file:               %s ", octstr_get_cstr(log_file));
	debug("smppClient", 0, "===> log-level:              %ld", log_level);
	debug("smppClient", 0, "===> enquire-link-interval:  %ld", enquire_link_interval);
	debug("smppClient", 0, "===> source_addr_ton:        %ld", source_addr_ton);
	debug("smppClient", 0, "===> source_addr_npi:        %ld", source_addr_npi);
	debug("smppClient", 0, "===> dest_addr_ton:          %ld", dest_addr_ton);
	debug("smppClient", 0, "===> dest_addr_npi:          %ld", dest_addr_npi);
	debug("smppClient", 0, "===> interface-version:      %ld", version);
	debug("smppClient", 0, "===> connection-timeout:     %ld", connection_timeout);
	debug("smppClient", 0, "===> bind-addr-ton:          %ld ", smpp->bind_addr_ton);
	debug("smppClient", 0, "===> bind-addr-npi:          %ld ", smpp->bind_addr_npi);
	debug("smppClient", 0, "==============================================");

	octstr_destroy(host);
	octstr_destroy(username);
	octstr_destroy(password);
	octstr_destroy(service_type);
	octstr_destroy(log_file);

	smppbox_status = SMPP_RUNNING;

}

static void signal_handler(int signum) {
	/* On some implementations (i.e. linuxthreads), signals are delivered
	 * to all threads.  We only want to handle each signal once for the
	 * entire box, and we let the gwthread wrapper take care of choosing
	 * one.
	 */
	if (!gwthread_shouldhandlesignal(signum))
		return;

	switch (signum) {
	case SIGINT:
	case SIGTERM:
		if (smppbox_status == SMPP_RUNNING) {
			error(0, "SIGINT received, aborting program...");
			smppbox_status = SMPP_SHUTDOWN;
			//smpp->conn = NULL;
			gwthread_wakeup_all();
		}
		break;

	case SIGHUP:
		warning(0, "SIGHUP received, catching and re-opening logs");
		log_reopen();
		alog_reopen();
		break;

		/*
		 * It would be more proper to use SIGUSR1 for this, but on some
		 * platforms that's reserved by the pthread support.
		 */
	case SIGQUIT:
		warning(0, "SIGQUIT received, reporting memory usage.");
		gw_check_leaks();
		break;
	}
}

static void setup_signal_handlers(void) {
	struct sigaction act;

	act.sa_handler = signal_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGQUIT, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGPIPE, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
}

static int check_args(int i, int argc, char **argv) {
	if (strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--tryhttp") == 0) {
		//only_try_http = 1;
	} else
		return -1;

	return 0;
}

/*
 * Adding hooks to kannel check config
 *
 * Martin Conte.
 */

static int smppbox_is_allowed_in_group(Octstr *group, Octstr *variable) {
	Octstr *groupstr;

	groupstr = octstr_imm("group");

#define OCTSTR(name) \
        if (octstr_compare(octstr_imm(#name), variable) == 0) \
        return 1;
#define SINGLE_GROUP(name, fields) \
        if (octstr_compare(octstr_imm(#name), group) == 0) { \
        if (octstr_compare(groupstr, variable) == 0) \
        return 1; \
        fields \
        return 0; \
    }
#define MULTI_GROUP(name, fields) \
        if (octstr_compare(octstr_imm(#name), group) == 0) { \
        if (octstr_compare(groupstr, variable) == 0) \
        return 1; \
        fields \
        return 0; \
    }
#include "smppClient-cfg.def"

	return 0;
}

#undef OCTSTR
#undef SINGLE_GROUP
#undef MULTI_GROUP

static int smppbox_is_single_group(Octstr *query) {
#define OCTSTR(name)
#define SINGLE_GROUP(name, fields) \
        if (octstr_compare(octstr_imm(#name), query) == 0) \
        return 1;
#define MULTI_GROUP(name, fields) \
        if (octstr_compare(octstr_imm(#name), query) == 0) \
        return 0;
#include "smppClient-cfg.def"
	return 0;
}

static void gw_smpp_leave() {
}
static void smpp_client_box_shutdown(void) {
	smpp_pdu_shutdown();
}

#define octstr_null_create(x) ((x != NULL) ? octstr_create(x) : octstr_create(""))
static int send_messages(SMPP *smpp, Connection *conn) {
	Msg *msg;
	SMPP_PDU *pdu;
	Octstr *os = NULL;
	MYSQL_RES *result = NULL;
	MYSQL_ROW row = NULL;
	int send;
	result = mysql_select(octstr_format(SQL_SELECT_MT,octstr_get_cstr(smppbox_id)));
	int num_rows = mysql_num_rows(result);
	debug("smppserver", 0, "%i messages in the queue", num_rows);
	if (num_rows == 0) {
		mysql_free_result(result);
		return 0;
	}

	while ((row = mysql_fetch_row(result))) {
		pdu = smpp_pdu_create(submit_sm, counter_increase(smpp->message_id_counter));
		pdu->u.submit_sm.source_addr = octstr_null_create(row[2]);
		pdu->u.submit_sm.destination_addr = octstr_null_create(row[1]);
		pdu->u.submit_sm.short_message = octstr_null_create(row[7]);

		if (send_pdu(conn, smpp->smppbox_id, pdu) == 0) {
			Message *message=NULL;
			message=createMessage(octstr_null_create(row[0]));
			os = octstr_format("%ld", pdu->u.submit_sm.sequence_number);
			dict_put(smpp->sent_msgs, os, message);
			mysql_update(octstr_format(SQL_UPDATE_MT_STATUS, "DISPATCHED", row[0]));
			smpp_pdu_destroy(pdu);
			octstr_destroy(os);
		} else { /* write error occurs */
			mysql_update(octstr_format(SQL_UPDATE_MT_STATUS, "NOTDISPATCHED", row[0]));
			smpp_pdu_destroy(pdu);
			return -1;
		}

	}
	mysql_free_result(result);
	return 0;

}
static void smpp_to_sql(void *arg) {


	int ret;
	long pending_submits;
	long len;
	SMPP_PDU *pdu;
	double timeout;
	time_t last_cleanup, last_enquire_sent, last_response, now;
	smpp->conn = NULL;


	debug("smppClient", 0, "Start smpp_to_sql process..........");
	while (smppbox_status == SMPP_RUNNING) {
		debug("smppClient", 0, "Ready to connect to smsc.........");

		smpp->conn = open_receiver(smpp);

		len = 0;
		last_response = last_cleanup = last_enquire_sent = time(NULL);
		while (smpp->conn != NULL) {

			ret = read_pdu(smpp, smpp->conn, &len, &pdu);
			if (ret == -1) { /* connection broken */
				error(0, "SMPP[%s]: I/O error or other error. Re-connecting.", octstr_get_cstr(smpp->smppbox_id));
				break;
			} else if (ret == -2) {
				/* wrong pdu length , send gnack */
				len = 0;
				if (send_gnack(smpp, smpp->conn, SMPP_ESME_RINVCMDLEN, 0) == -1) {
					error(0, "SMPP[%s]: I/O error or other error. Re-connecting.", octstr_get_cstr(smpp->smppbox_id));
					break;
				}
			} else if (ret == 1) { /* data available */
				/* Deal with the PDU we just got */
				dump_pdu("Got PDU:", smpp->smppbox_id, pdu);
				ret = handle_pdu(smpp, smpp->conn, pdu, &pending_submits);
				smpp_pdu_destroy(pdu);
				if (ret == -1) {
					error(0, "SMPP[%s]: I/O error or other error. Re-connecting.", octstr_get_cstr(smpp->smppbox_id));
					break;
				}

				time(&last_response);
			} else { /* no data available */
				/* check last enquire_resp, if difftime > as idle_timeout
				 * mark connection as broken.
				 * We have some SMSC connections where connection seems to be OK, but
				 * in reallity is broken, because no responses received.
				 */
				if (smpp->connection_timeout > 0 && difftime(time(NULL), last_response) > smpp->connection_timeout) {
					/* connection seems to be broken */
					warning(0, "Got no responses within %ld sec., reconnecting...", (long) difftime(time(NULL), last_response));
					break;
				}

				time(&now);
				timeout = last_enquire_sent + smpp->enquire_link_interval - now;
				if (timeout <= 0)
					timeout = smpp->enquire_link_interval;
				/* sleep a while */
				if (timeout > 0 && conn_wait(smpp->conn, 1.0) == -1) {
					break;
				}

			}

			if (send_enquire_link(smpp, smpp->conn, &last_enquire_sent) == -1)
				break;
			/* unbind
			 * Read so long as unbind_resp received or timeout passed. Otherwise we have
			 * double delivered messages.
			 */
			if (smppbox_status != SMPP_RUNNING) {
				if (send_unbind(smpp, smpp->conn) == -1)
					break;
				time(&last_response);
				while (conn_wait(smpp->conn, 1.00) != -1 && difftime(time(NULL), last_response) < SMPP_DEFAULT_SHUTDOWN_TIMEOUT) {
					if (read_pdu(smpp, smpp->conn, &len, &pdu) == 1) {
						dump_pdu("Got PDU:", smpp->smppbox_id, pdu);
						handle_pdu(smpp, smpp->conn, pdu, &pending_submits);
						smpp_pdu_destroy(pdu);
					}
				}
				debug("bb.sms.smpp", 0, "SMPP[%s]: %s: break and shutting down", octstr_get_cstr(smpp->smppbox_id), __PRETTY_FUNCTION__);

				break;
			}

		}
		if (smpp->conn != NULL) {
			conn_destroy(smpp->conn);
			smpp->conn = NULL;
		}
		if (!smpp->quitting) {
			error(0, "SMPP[%s]: Couldn't connect to SMS center (retrying in %ld seconds).", octstr_get_cstr(smpp->smppbox_id), smpp->reconnect_delay);
			gwthread_sleep(smpp->reconnect_delay);
		}

	}

}

static void sql_to_smpp(void *arg) {

	int ret;
	long pending_submits;
	long len;
	SMPP_PDU *pdu;
	double timeout;
	time_t last_cleanup, last_enquire_sent, last_response, now;
	smpp->conn = NULL;
	int thread_transmiter = 0;

	debug("smppClient", 0, "Start sql_to_smpp process..........");
	while (smppbox_status == SMPP_RUNNING) {
		debug("smppClient", 0, "Ready to connect to smsc.........");

		smpp->conn = open_transmitter(smpp);

		pending_submits = -1;
		len = 0;
		last_response = last_cleanup = last_enquire_sent = time(NULL);
		while (smpp->conn != NULL) {
			debug("smppClient", 0, "Ready to read_pdu while connection is diffent NULL");
			ret = read_pdu(smpp, smpp->conn, &len, &pdu);
			if (ret == -1) { /* connection broken */
				error(0, "SMPP[%s]: I/O error or other error. Re-connecting.", octstr_get_cstr(smpp->smppbox_id));
				break;
			} else if (ret == -2) {
				/* wrong pdu length , send gnack */
				len = 0;
				if (send_gnack(smpp, smpp->conn, SMPP_ESME_RINVCMDLEN, 0) == -1) {
					error(0, "SMPP[%s]: I/O error or other error. Re-connecting.", octstr_get_cstr(smpp->smppbox_id));
					break;
				}
			} else if (ret == 1) { /* data available */
				/* Deal with the PDU we just got */
				dump_pdu("Got PDU:", smpp->smppbox_id, pdu);
				ret = handle_pdu(smpp, smpp->conn, pdu, &pending_submits);
				smpp_pdu_destroy(pdu);
				if (ret == -1) {
					error(0, "SMPP[%s]: I/O error or other error. Re-connecting.", octstr_get_cstr(smpp->smppbox_id));
					break;
				}

				time(&last_response);
			} else { /* no data available */
				debug("smppClient",0,"NO DATA");
				/* check last enquire_resp, if difftime > as idle_timeout
				 * mark connection as broken.
				 * We have some SMSC connections where connection seems to be OK, but
				 * in reallity is broken, because no responses received.
				 */
				if (smpp->connection_timeout > 0 && difftime(time(NULL), last_response) > smpp->connection_timeout) {
					/* connection seems to be broken */
					warning(0, "Got no responses within %ld sec., reconnecting...", (long) difftime(time(NULL), last_response));
					break;
				}

				time(&now);
				timeout = last_enquire_sent + smpp->enquire_link_interval - now;
				if (timeout <= 0)
					timeout = smpp->enquire_link_interval;
				/* sleep a while */
				if (timeout > 0 && conn_wait(smpp->conn, 1.0) == -1) {
					break;
				}

			}

			if (send_enquire_link(smpp, smpp->conn, &last_enquire_sent) == -1)
				break;

			debug("smppClient", 0, "Sending messages");
			if (difftime(time(NULL), smpp->throttling_err_time) > SMPP_THROTTLING_SLEEP_TIME) {
				smpp->throttling_err_time = 0;

				if (send_messages(smpp, smpp->conn) == -1)
					break;
			}
			/* unbind
			 * Read so long as unbind_resp received or timeout passed. Otherwise we have
			 * double delivered messages.
			 */
			if (smppbox_status != SMPP_RUNNING) {
				if (send_unbind(smpp, smpp->conn) == -1)
					break;
				time(&last_response);
				while (conn_wait(smpp->conn, 1.00) != -1 && difftime(time(NULL), last_response) < SMPP_DEFAULT_SHUTDOWN_TIMEOUT) {
					if (read_pdu(smpp, smpp->conn, &len, &pdu) == 1) {
						dump_pdu("Got PDU:", smpp->smppbox_id, pdu);
						handle_pdu(smpp, smpp->conn, pdu, &pending_submits);
						smpp_pdu_destroy(pdu);
					}
				}
				debug("bb.sms.smpp", 0, "SMPP[%s]: %s: break and shutting down", octstr_get_cstr(smpp->smppbox_id), __PRETTY_FUNCTION__);

				break;
			}

		}
		if (smpp->conn != NULL) {
			conn_destroy(smpp->conn);
			smpp->conn = NULL;
		}
		if (!smpp->quitting) {
			error(0, "SMPP[%s]: Couldn't connect to SMS center (retrying in %ld seconds).", octstr_get_cstr(smpp->smppbox_id), smpp->reconnect_delay);
			//			mutex_lock(smpp->conn->flow_mutex);
			//			smpp->conn->status = SMSCCONN_RECONNECTING;
			//			mutex_unlock(smpp->conn->flow_mutex);
			gwthread_sleep(smpp->reconnect_delay);
		}

	}
	//gwthread_join(transmiter);

}

static void main_thread() {

	if (transmitter_mode == 1) {
		debug("smppClient", 0, "Inicialization thead sql_to_smpp");
		smpp->transmitter = gwthread_create(sql_to_smpp,NULL);
		if (smpp->transmitter == -1) {
			debug("smppClient", 0, "sql_to_smpp create error");
		}
		debug("smppClient", 0, "Thread sql_to_smpp ends");
		gwthread_join(smpp->transmitter);

	}

	if (receiver_mode == 1) {
		debug("smppClient", 0, "Inicialization thread smpp_to_sql");
		smpp->receiver = gwthread_create(smpp_to_sql,NULL);
		if (smpp->receiver == -1) {
			debug("smppClient", 0, "smpp_to_sql create error");
		}
		debug("smppClient", 0, "Thread smpp_to_sql ends");
		gwthread_join(smpp->receiver);
	}
	while (smppbox_status == SMPP_RUNNING) {
		//	debug("smppClient", 0, "sever is running with %d", smppbox_status);
		gwthread_sleep(1.0);

	}
}

void smpp_client_box_run() {
	debug("smppClient", 0, "Start method smpp_client_box_run");
	main_thread();
	debug("smppClient", 0, "End method smpp_client_box_run");
}

int main(int argc, char **argv) {
	int cf_index;
	Octstr *filename, *version;

	gwlib_init();

	cf_index = get_and_set_debugs(argc, argv, check_args);
	setup_signal_handlers();

	if (argv[cf_index] == NULL)
		filename = octstr_create("smppClient.conf");
	else
		filename = octstr_create(argv[cf_index]);

	cfg = cfg_create(filename);

	/* Adding cfg-checks to core */
	cfg_add_hooks(smppbox_is_allowed_in_group, smppbox_is_single_group);

	if (cfg_read(cfg) == -1)
		panic(0, "Couldn't read configuration from `%s'.", octstr_get_cstr(filename));

	octstr_destroy(filename);

	version = octstr_format("smppClient version %s gwlib", GW_VERSION);
	report_versions(octstr_get_cstr(version));
	octstr_destroy(version);

	struct server_type *res = NULL;
	res = sqlbox_init_mysql(cfg);
	sqlbox_configure_mysql(cfg);

	init_smpp_client_box(cfg);

	smpp_client_box_run();

	smpp_client_box_shutdown();

	cfg_destroy(cfg);

	if (restart_smppbox) {
		gwthread_sleep(1.0);
	}

	gw_smpp_leave();
	gwlib_shutdown();

	if (restart_smppbox)
		execvp(argv[0], argv);
	return 0;

}
