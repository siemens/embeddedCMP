/*
 * coap_helper.c
 *
 *  Created on: 25.01.2019
 *      Author: kretscha
 */

/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* coap-client -- simple CoAP client
 *
 * Copyright (C) 2010--2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms of
 * use.
 */

// #define NO_COAP /* just for CoAP code size differential measurement */

#include "coap_config.h"

#include "coap.h"
#include "coap_list.h"
#include "coap_helper.h"
#include "lwip_helper.h"

#define NDEBUG 1

static size_t g_total_rx_len = 0;
static size_t g_total_tx_len = 0;

static unsigned char _token_data[8];
str the_token = { 0, _token_data };

static coap_list_t *optlist = NULL;
/* Request URI.
 * TODO: associate the resources with transaction id and make it expireable */
static coap_uri_t uri;

/* reading is done when this flag is set */
static int ready = 0;

//static str payload; /* optional payload to send */

static const unsigned char *payload;
static size_t payload_length;

const unsigned char msgtype = COAP_MESSAGE_CON; /* usually, requests are sent confirmable */

typedef unsigned char method_t;
static const method_t method = COAP_REQUEST_POST; /* the method we are using in our requests */

coap_block_t block = { .num = 0, .m = 0, .szx = 6 };

const unsigned int wait_seconds = 90; /* default timeout in seconds */
coap_tick_t max_wait; /* global timeout (changed by set_timeout()) */

const unsigned int obs_seconds = 30; /* default observe time */
coap_tick_t obs_wait; /* timeout for current subscription */

#define min(a,b) ((a) < (b) ? (a) : (b))

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

#define MAX_REC_BUFFER_SIZE 10000

typedef struct ReceiveContext {
	u16_t receivelen;
	unsigned char inbuf[MAX_REC_BUFFER_SIZE + 1];
} ReceiveContext;

static ReceiveContext rcontext;

static int append_to_output(const uint8_t *data, size_t len) {
	// fill up response buffer, 0 on success, -1 on fault
	if (len + rcontext.receivelen > MAX_REC_BUFFER_SIZE) {
		coap_log(LOG_CRIT, "receive buffer overflow\n");
		return -1;
	}
	memcpy(rcontext.inbuf + rcontext.receivelen, data, len);
	rcontext.receivelen += len;
	return 0;
}

static coap_list_t *
new_option_node(unsigned short key, unsigned int length, unsigned char *data) {
	coap_list_t *node;

	node = coap_malloc(sizeof(coap_list_t) + sizeof(coap_option) + length);

	if (node) {
		coap_option *option;
		option = (coap_option *) (node->data);
		COAP_OPTION_KEY(*option) = key;
		COAP_OPTION_LENGTH(*option) = length;
		memcpy(COAP_OPTION_DATA(*option), data, length);
	} else {
		coap_log(LOG_DEBUG, "new_option_node: malloc\n");
	}

	return node;
}

static inline void set_timeout(coap_tick_t *timer, const unsigned int seconds) {
	coap_ticks(timer);
	*timer += seconds * COAP_TICKS_PER_SECOND;
}

static int order_opts(void *a, void *b) {
	coap_option *o1, *o2;

	if (!a || !b)
		return a < b ? -1 : 1;

	o1 = (coap_option *) (((coap_list_t *) a)->data);
	o2 = (coap_option *) (((coap_list_t *) b)->data);

	return (COAP_OPTION_KEY(*o1) < COAP_OPTION_KEY(*o2)) ?
			-1 : (COAP_OPTION_KEY(*o1) != COAP_OPTION_KEY(*o2));
}

/* Called after processing the options from the commandline to set
 * Block1 or Block2 depending on method. */
static void set_blocksize(void) {
	static unsigned char buf[4]; /* hack: temporarily take encoded bytes */
	unsigned short opt;
	unsigned int opt_length;

	if (method != COAP_REQUEST_DELETE) {
		opt = method == COAP_REQUEST_GET ?
				COAP_OPTION_BLOCK2 : COAP_OPTION_BLOCK1;

		block.m = (opt == COAP_OPTION_BLOCK1)
				&& ((1u << (block.szx + 4)) < payload_length);

		opt_length = coap_encode_var_bytes(buf,
				(block.num << 4 | block.m << 3 | block.szx));

		coap_insert(&optlist, new_option_node(opt, opt_length, buf));
	}
}

static coap_pdu_t *
coap_new_request(coap_context_t *ctx, method_t m, coap_list_t **options,
		const unsigned char *data, size_t length) {
	coap_pdu_t *pdu;
	coap_list_t *opt;

	if (!(pdu = coap_new_pdu()))
		return NULL;

	pdu->hdr->type = msgtype;
	pdu->hdr->id = coap_new_message_id(ctx);
	pdu->hdr->code = m;

	pdu->hdr->token_length = the_token.length;
	if (!coap_add_token(pdu, the_token.length, the_token.s)) {
		debug("cannot add token to request\n");
	}

	if (options) {
		/* sort options for delta encoding */
		LL_SORT((*options), order_opts);

		LL_FOREACH((*options), opt)
		{
			coap_option *o = (coap_option *) (opt->data);
			coap_add_option(pdu, COAP_OPTION_KEY(*o), COAP_OPTION_LENGTH(*o),
					COAP_OPTION_DATA(*o));
		}
	}

	if (length) {
		// if ((flags & FLAGS_BLOCK) == 0)
		if (0)
			coap_add_data(pdu, length, data);
		else
			coap_add_block(pdu, length, data, block.num, block.szx);
	}

	return pdu;
}

#define HANDLE_BLOCK1(Pdu)                                        \
  ((method == COAP_REQUEST_PUT || method == COAP_REQUEST_POST) && \
   ((flags & FLAGS_BLOCK) == 0) &&                                \
   ((Pdu)->hdr->code == COAP_RESPONSE_CODE(201) ||                \
    (Pdu)->hdr->code == COAP_RESPONSE_CODE(204)))

static inline int check_token(coap_pdu_t *received) {
	return received->hdr->token_length == the_token.length
			&& memcmp(received->hdr->token, the_token.s, the_token.length) == 0;
}

static void message_handler(struct coap_context_t *ctx,
		const coap_endpoint_t *local_interface, const coap_address_t *remote,
		coap_pdu_t *sent, coap_pdu_t *received,
		const coap_tid_t id UNUSED_PARAM) {

	coap_pdu_t *pdu = NULL;
	coap_opt_t *block_opt;
	coap_opt_iterator_t opt_iter;
	unsigned char buf[4];
	coap_list_t *option;
	size_t len;
	unsigned char *databuf;
	coap_tid_t tid;

#ifndef NDEBUG
	if (LOG_DEBUG <= coap_get_log_level()) {
		debug("** process incoming %d.%02d response:\n",
				(received->hdr->code >> 5), received->hdr->code & 0x1F);
		coap_show_pdu(received);
	}
#endif



	/* check if this is a response to our original request */
	if (!check_token(received)) {
		/* drop if this was just some message, or send RST in case of notification */
		if (!sent
				&& (received->hdr->type == COAP_MESSAGE_CON
						|| received->hdr->type == COAP_MESSAGE_NON))
			coap_send_rst(ctx, local_interface, remote, received);
		return;
	}

	if (received->hdr->type == COAP_MESSAGE_RST) {
		info("got RST\n");
		return;
	}

    CMPINFOV("CoAP received Block length: %d", received->length);
    g_total_rx_len += received->length;

	/* output the received data, if any */
	if (COAP_RESPONSE_CLASS(received->hdr->code) == 2) {

		/* set obs timer if we have successfully subscribed a resource */
		if (sent
				&& coap_check_option(received, COAP_OPTION_SUBSCRIPTION,
						&opt_iter)) {
			debug("observation relationship established, set timeout to %d\n",
					obs_seconds);
			set_timeout(&obs_wait, obs_seconds);
		}

		/* Got some data, check if block option is set. Behavior is undefined if
		 * both, Block1 and Block2 are present. */
		block_opt = coap_check_option(received, COAP_OPTION_BLOCK2, &opt_iter);
		if (block_opt) { /* handle Block2 */
			unsigned short blktype = opt_iter.type;

			/* TODO: check if we are looking at the correct block number */
			if (coap_get_data(received, &len, &databuf))
				append_to_output(databuf, len);

			if (COAP_OPT_BLOCK_MORE(block_opt)) {
				/* more bit is set */
				debug("found the M bit, block size is %u, block nr. %u\n",
						COAP_OPT_BLOCK_SZX(block_opt),
						coap_opt_block_num(block_opt));

				/* create pdu with request for next block */
				pdu = coap_new_request(ctx, method, NULL, NULL, 0); /* first, create bare PDU w/o any option  */
				if (pdu) {
					/* add URI components from optlist */
					for (option = optlist; option; option = option->next) {
						coap_option *o = (coap_option *) (option->data);
						switch (COAP_OPTION_KEY(*o)) {
						case COAP_OPTION_URI_HOST:
						case COAP_OPTION_URI_PORT:
						case COAP_OPTION_URI_PATH:
						case COAP_OPTION_URI_QUERY:
							coap_add_option(pdu, COAP_OPTION_KEY(*o),
									COAP_OPTION_LENGTH(*o),
									COAP_OPTION_DATA(*o));
							break;
						default:
							; /* skip other options */
						}
					}

					/* finally add updated block option from response, clear M bit */
					/* blocknr = (blocknr & 0xfffffff7) + 0x10; */
					debug("query block %d\n",
							(coap_opt_block_num(block_opt) + 1));
					coap_add_option(pdu, blktype,
							coap_encode_var_bytes(buf,
									((coap_opt_block_num(block_opt) + 1) << 4)
											| COAP_OPT_BLOCK_SZX(block_opt)),
							buf);

					CMPINFOV("Sent CoAP Block length %d", pdu->length);

					if (pdu->hdr->type == COAP_MESSAGE_CON)
						tid = coap_send_confirmed(ctx, local_interface, remote,
								pdu);
					else
						tid = coap_send(ctx, local_interface, remote, pdu);

					if (tid == COAP_INVALID_TID) {
						debug("message_handler: error sending new request");
						coap_delete_pdu(pdu);
					} else {
						set_timeout(&max_wait, wait_seconds);
						if (pdu->hdr->type != COAP_MESSAGE_CON)
							coap_delete_pdu(pdu);
					}

					return;
				}
			}
		} else { /* no Block2 option */
			block_opt = coap_check_option(received, COAP_OPTION_BLOCK1,
					&opt_iter);

			if (block_opt) { /* handle Block1 */
				unsigned int szx = COAP_OPT_BLOCK_SZX(block_opt);
				unsigned int num = coap_opt_block_num(block_opt);
				debug("found Block1 option, block size is %u, block nr. %u\n",
						szx, num);
				if (szx != block.szx) {
					unsigned int bytes_sent = ((block.num + 1)
							<< (block.szx + 4));
					if (bytes_sent % (1 << (szx + 4)) == 0) {
						/* Recompute the block number of the previous packet given the new block size */
						block.num = (bytes_sent >> (szx + 4)) - 1;
						block.szx = szx;
						debug(
								"new Block1 size is %u, block number %u completed\n",
								(1 << (block.szx + 4)), block.num);
					} else {
						debug(
								"ignoring request to increase Block1 size, "
										"next block is not aligned on requested block size boundary. "
										"(%u x %u mod %u = %u != 0)\n",
								block.num + 1, (1 << (block.szx + 4)),
								(1 << (szx + 4)),
								bytes_sent % (1 << (szx + 4)));
					}
				}

				if (payload_length
						<= (block.num + 1) * (1 << (block.szx + 4))) {
					debug("upload ready\n");

                    if (coap_get_data(received, &len, &databuf))
                        append_to_output(databuf, len);

                    ready = 1;
                    return;
				}

				/* create pdu with request for next block */
				pdu = coap_new_request(ctx, method, NULL, NULL, 0); /* first, create bare PDU w/o any option  */
				if (pdu) {

					/* add URI components from optlist */
					for (option = optlist; option; option = option->next) {
						coap_option *o = (coap_option *) (option->data);
						switch (COAP_OPTION_KEY(*o)) {
						case COAP_OPTION_URI_HOST:
						case COAP_OPTION_URI_PORT:
						case COAP_OPTION_URI_PATH:
						case COAP_OPTION_CONTENT_FORMAT:
						case COAP_OPTION_URI_QUERY:
							coap_add_option(pdu, COAP_OPTION_KEY(*o),
									COAP_OPTION_LENGTH(*o),
									COAP_OPTION_DATA(*o));
							break;
						default:
							; /* skip other options */
						}
					}

					/* finally add updated block option from response, clear M bit */
					/* blocknr = (blocknr & 0xfffffff7) + 0x10; */
					block.num++;
					block.m = ((block.num + 1) * (1 << (block.szx + 4))
							< payload_length);

					debug("send block %d\n", block.num);
					coap_add_option(pdu,
					COAP_OPTION_BLOCK1,
							coap_encode_var_bytes(buf,
									(block.num << 4) | (block.m << 3)
											| block.szx), buf);

					coap_add_block(pdu, payload_length, payload, block.num,
							block.szx);
#ifndef NDEBUG
					coap_show_pdu(pdu);
#endif
					if (pdu->hdr->type == COAP_MESSAGE_CON)
						tid = coap_send_confirmed(ctx, local_interface, remote,
								pdu);
					else
						tid = coap_send(ctx, local_interface, remote, pdu);

				    CMPINFOV("CoAP sent Block length: %d", pdu->length);
				    g_total_tx_len += pdu->length;

					if (tid == COAP_INVALID_TID) {
						debug("message_handler: error sending new request");
						coap_delete_pdu(pdu);
					} else {
						set_timeout(&max_wait, wait_seconds);
						if (pdu->hdr->type != COAP_MESSAGE_CON)
							coap_delete_pdu(pdu);
					}

					return;
				}
			} else {
				/* There is no block option set, just read the data and we are done. */
				if (coap_get_data(received, &len, &databuf))
					append_to_output(databuf, len);
			}
		}
	} else { /* no 2.05 */

		/* check if an error was signaled and output payload if so */
		if (COAP_RESPONSE_CLASS(received->hdr->code) >= 4) {
			CMPERRV("%d.%02d", (received->hdr->code >> 5),
					received->hdr->code & 0x1F);
			if (coap_get_data(received, &len, &databuf)) {
				while (len--)
					CMPERRV("%c", *databuf++);
			}
		}

	}

	/* finally send new request, if needed */
	if (pdu && coap_send(ctx, local_interface, remote, pdu) == COAP_INVALID_TID) {
		debug("message_handler: error sending response");
	}
	coap_delete_pdu(pdu);

	/* our job is done, we can exit at any time */
	ready = coap_check_option(received, COAP_OPTION_SUBSCRIPTION,
			&opt_iter) == NULL;
}

static inline void cmdline_token(char *arg) {
	strncpy((char *) the_token.s, arg, min(sizeof(_token_data), strlen(arg)));
	the_token.length = strlen(arg);
}

/**
 * Calculates decimal value from hexadecimal ASCII character given in
 * @p c. The caller must ensure that @p c actually represents a valid
 * heaxdecimal character, e.g. with isxdigit(3).
 *
 * @hideinitializer
 */
#define hexchar_to_dec(c) ((c) & 0x40 ? ((c) & 0x0F) + 9 : ((c) & 0x0F))

static coap_context_t *
get_context(const char *node, uint16_t port) {
	coap_address_t src;
	coap_address_init(&src);
	if (node != NULL) {
		if (!ip4addr_aton(node, &src.addr)) {
			coap_log(LOG_EMERG,
					"only IP addresses are allow for COAP server: %s", node);
			return NULL;
		}
	} else {
		src.addr.addr = IPADDR_ANY;
	}
	if (port != 0) {
		src.port = port;
	} else {
		src.port = COAP_DEFAULT_PORT;
	}

	coap_context_t *ctx = coap_new_context(&src);
	if (!ctx) {
		CMPERRV("no context available for interface '%s'\n", node);
		return NULL;
	}
	return ctx;
}

/* prototype adapted to match http_send_receive(), but no proxy functionality implemented yet! */
int coap_send_receive(const char *shost, const int sport, const char *spath,
		const char *phost, const int pport,
		const unsigned char *outbuf, const size_t outlen, unsigned char **inbuf,
		size_t *inlen) {
    g_total_rx_len = 0;
    g_total_tx_len = 0;
	optlist = NULL;
	ready = 0;
	block.num = 0;
	block.m = 0;
	block.szx = 6;
	payload = outbuf;
	payload_length = outlen;
	uri.port = sport;
	uri.path.s = (unsigned char *) spath;
	uri.path.length = strlen(spath);
	uri.host.s = (unsigned char *) shost;
	uri.host.length = strlen(shost);
	uri.query.s = NULL;
	uri.query.length = 0;
	coap_context_t *ctx = NULL;

	coap_address_t dst;

	coap_pdu_t *pdu;
	// coap_log_t log_level = LOG_WARNING;
	coap_log_t log_level = LOG_ERR;
	rcontext.receivelen = 0;
	coap_set_log_level(log_level);
	coap_tid_t tid = COAP_INVALID_TID;

#ifndef NO_COAP
	CMPINFOV("## CoAP connection to %s:%d%s%s ##", shost, uri.port, *spath != '/' ? "/" : "", spath);

	coap_set_log_level(log_level);

	coap_address_init(&dst);
	if (!ip4addr_aton(shost, &dst.addr)) {
		coap_log(LOG_EMERG, "only IP addresses are allow for COAP server: %s",
				shost);
		return -1;
	}
	dst.port = COAP_DEFAULT_PORT; // TODO or sport ?
	ctx = get_context("0.0.0.0", dst.port);
	if (!ctx) {
		coap_log(LOG_EMERG, "cannot create context\n");
		return -1;
	}

	{
		unsigned char portbuf[2];
#define BUFSIZE 40
		unsigned char _buf[BUFSIZE];
		unsigned char *buf = _buf;
		size_t buflen;
		int res;
		int create_uri_opts = 1;

		if (uri.port != COAP_DEFAULT_PORT && create_uri_opts) {
			coap_insert(&optlist,
					new_option_node(COAP_OPTION_URI_PORT,
							coap_encode_var_bytes(portbuf, uri.port), portbuf));
		}
		if (uri.path.length) {
			buflen = BUFSIZE;
			/* remove trailing slashes in paths to prevent empty coap uri option field */
			if (uri.path.s[uri.path.length - 1] == '/') {
				uri.path.s[uri.path.length - 1] = '\0';
				uri.path.length -= 1;
			}
			res = coap_split_path(uri.path.s,
					uri.path.length,
					buf, &buflen);

			while (res--) {
				coap_insert(&optlist,
						new_option_node(COAP_OPTION_URI_PATH,
								COAP_OPT_LENGTH(buf), COAP_OPT_VALUE(buf)));

				buf += COAP_OPT_SIZE(buf);
			}
		}

		if (uri.query.length) {
			buflen = BUFSIZE;
			buf = _buf;
			res = coap_split_query(uri.query.s, uri.query.length, buf, &buflen);

			while (res--) {
				coap_insert(&optlist,
						new_option_node(COAP_OPTION_URI_QUERY,
								COAP_OPT_LENGTH(buf), COAP_OPT_VALUE(buf)));

				buf += COAP_OPT_SIZE(buf);
			}
		}
		coap_insert(&optlist,
				new_option_node(COAP_OPTION_CONTENT_TYPE,
						coap_encode_var_bytes(buf,
						COAP_MEDIATYPE_APPLICATION_OCTET_STREAM), buf));
	}

	coap_register_option(ctx, COAP_OPTION_BLOCK2);
	set_blocksize();
	coap_register_response_handler(ctx, message_handler);

	if (!(pdu = coap_new_request(ctx, method, &optlist, payload,
			payload_length)))
		return -1;

#ifndef NDEBUG
	if (LOG_DEBUG <= coap_get_log_level()) {
		debug("sending CoAP request:\n");
		coap_show_pdu(pdu);
	}
#endif

	CMPINFOV("CoAP sent Block length: %d", pdu->length);
	g_total_tx_len += pdu->length;

	if (pdu->hdr->type == COAP_MESSAGE_CON)
		tid = coap_send_confirmed(ctx, ctx->endpoint, &dst, pdu);
	else
		tid = coap_send(ctx, ctx->endpoint, &dst, pdu);

	if (pdu->hdr->type != COAP_MESSAGE_CON || tid == COAP_INVALID_TID)
		coap_delete_pdu(pdu);

	set_timeout(&max_wait, wait_seconds);
	debug("timeout is set to %d seconds\n", wait_seconds);
	while (!(ready && coap_can_exit(ctx))) {
		poll_lwip_driver();
		coap_tick_t now;
		coap_ticks(&now);
		coap_queue_t * nextpdu = coap_peek_next(ctx);
		while (nextpdu && nextpdu->t <= now - ctx->sendqueue_basetime) {
			coap_retransmit(ctx, coap_pop_next(ctx));
			CMPINFOV("CoAP retransmit Block length: %d", nextpdu->pdu->length);
			g_total_tx_len += nextpdu->pdu->length;
			nextpdu = coap_peek_next(ctx);
		}
		// coap_read(ctx); /* read received data */
		// coap_dispatch(ctx);
		coap_ticks(&now);
		if (max_wait <= now) {
			info("timeout\n");
			break;
		}
	}
	CMPINFOV("CoAP sent total length: %d", g_total_tx_len);
	CMPINFOV("CoAP send overhead: %d", g_total_tx_len - outlen);

	*inbuf = rcontext.inbuf;
	*inlen = rcontext.receivelen;
	coap_delete_list(optlist);
	optlist = NULL;
	coap_free_context(ctx);

	CMPINFOV("CoAP received total length: %d", g_total_rx_len);
	CMPINFOV("CoAP receive overhead: %d", g_total_rx_len - rcontext.receivelen);

	return 0;

#else
    CMPERRS("This build does not include CoAP.");
    return -1;
#endif // NO_COAP
}

