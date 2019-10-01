/*
 *  Copyright (c) 2019 Siemens AG
 * *
 *  Licensed under the Apache License, Version 2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 * lwip_helper.c
 *
 *  Created on: 09.01.2019
 *      Author: kretscha
 */
#include "http_helper.h"
#include "cmpcl.h"
#include "tcp.h"
#include "lwip_helper.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define NEWLINE     "\r\n"

#define MAX_REC_BUFFER_SIZE 10000

typedef enum {
	filling, completed, error
} context_state;

typedef struct SendReceiveContext {
	volatile context_state state;
	u16_t receivelen;
	unsigned char inbuf[MAX_REC_BUFFER_SIZE + 1];
} SendReceiveContext;

static err_t receive_function(void *arg, struct tcp_pcb *tpcb, struct pbuf *p,
		err_t err) {
	SendReceiveContext* srcontext = (SendReceiveContext*) arg;
	if (err != ERR_OK) {
		CMPERRV("receive error %d", err);
		srcontext->state = error;
		return ERR_OK;
	}
	if (!p) {
		srcontext->state = completed;
		tcp_close(tpcb);
		return ERR_OK;
	}
	const u16_t newreceivedlen = pbuf_copy_partial(p,
			srcontext->inbuf + srcontext->receivelen,
			MAX_REC_BUFFER_SIZE - srcontext->receivelen, 0);
	srcontext->receivelen += newreceivedlen;
	tcp_recved(tpcb, p->tot_len);
	pbuf_free(p);
	if (srcontext->receivelen >= MAX_REC_BUFFER_SIZE) {
		CMPERRS("receive buffer overflow");
		srcontext->state = error;
		return ERR_ABRT;
	}
	return ERR_OK;
}

static void error_function(void *arg, err_t err) {
	CMPERRV("TCP error %d", err);
	((SendReceiveContext*) arg)->state = error;
}

static SendReceiveContext srcontext;


int http_send_receive(const char *shost, const int sport, const char *spath,
		const char *phost, const int pport,
		const unsigned char *outbuf, const size_t outlen, unsigned char **inbuf,
		size_t *inlen) {

	ip4_addr_t serveraddress;
	ip4_addr_t proxyaddress;
	if (phost != NULL) { /* use proxy, no need to resolve host */
		if (!ip4addr_aton(phost, &proxyaddress)) {
			CMPERRV("only IP addresses are allow for HTTP proxy server: %s",
					phost);
			return -1;
		}
	} else { /* no proxy configured, ensure host IP was provided */
		if (!ip4addr_aton(shost, &serveraddress)) {
			CMPERRV("only IP addresses are allow for HTTP server: %s", shost);
			return -1;
		}
	}
	CMPINFOV("## HTTP connection to %s:%d%s%s ##", shost, sport, *spath != '/' ? "/" : "", spath);
    if(phost != NULL)
        CMPINFOV("## via proxy %s:%d ##", phost, pport);

	srcontext.state = filling;
	srcontext.receivelen = 0;
	struct tcp_pcb *pcb = tcp_new();
	tcp_arg(pcb, &srcontext);
	tcp_recv(pcb, receive_function);
	tcp_err(pcb, error_function);
	err_t err = tcp_bind(pcb, IP_ADDR_ANY, 0);
	if (err != ERR_OK) {
		CMPERRV("tcp_bind failed: %d", err);
		tcp_close(pcb);
		return -1;
	}
	if (phost != NULL) {
		err = tcp_connect(pcb, &proxyaddress, pport, NULL);
	} else {
		err = tcp_connect(pcb, &serveraddress, sport, NULL);
	}
	if (err != ERR_OK) {
		CMPERRV("tcp_connect failed: %d", err);
		tcp_close(pcb);
		return -1;
	}
	char header[200];
	sprintf(header, "POST ");
	if (phost != NULL) {
		sprintf( header+strlen(header), "http://%s:%d", shost, sport);
	}
	sprintf( header+strlen(header),
			"%s%s HTTP/1.1" NEWLINE
			"Host: %s" NEWLINE
			"Content-Type: application/pkixcmp" NEWLINE
			"Connection: close" NEWLINE
			"Content-Length: %d" NEWLINE NEWLINE,
			//
			*spath != '/' ? "/" : "", spath, shost, (int) outlen);
	size_t sentHeaderLen = strlen(header);
	err = tcp_write(pcb, header, sentHeaderLen, TCP_WRITE_FLAG_MORE);
	if (err != ERR_OK) {
		CMPERRV("tcp_write (header) failed: %d", err);
		tcp_close(pcb);
		return -1;
	}
	err = tcp_write(pcb, outbuf, outlen, 0);
	if (err != ERR_OK) {
		CMPERRV("tcp_write (body) failed: %d", err);
		tcp_close(pcb);
		return -1;
	}
	err = tcp_output(pcb);
	if (err != ERR_OK) {
		CMPERRV("tcp_output failed: %d", err);
		tcp_close(pcb);
		return -1;
	}
	CMPINFOV("HTTP sent header: %d", (int)sentHeaderLen);
	CMPINFOV("HTTP sent total : %d", (int)sentHeaderLen + (int)outlen);
	while (srcontext.state == filling) {
		poll_lwip_driver();
	}
	tcp_close(pcb); /* TODO: keep connection open for further certConf/PKIconf messages */
	if (srcontext.state != completed) {
		return -1;
	}
	// skip HTTP header
	srcontext.inbuf[srcontext.receivelen] = '\0';
	unsigned char* header_end = (unsigned char*) strstr((char*) srcontext.inbuf,
	NEWLINE NEWLINE);
	if (header_end == NULL) {
		CMPERRS("no HTTP header found in response");
		return -1;
	}
	header_end += 4;
        int header_len = header_end - srcontext.inbuf;
	*inbuf = header_end;
	*inlen = srcontext.receivelen - header_len;
	*(header_end - 1) = '\0';
	CMPINFOV("HTTP received header: %d", header_len);
	CMPINFOV("HTTP received total : %d", (int)(srcontext.receivelen));
	return 0;
}
