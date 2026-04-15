/*
 *  Copyright (c) 2016-2017, Nokia, All rights reserved.
 *  Copyright (c) 2019 Siemens AG
 *
 *  This CMP client contains code derived from examples and documentation for
 *  mbedTLS by ARM
 *  Copyright (C) 2006-2017, ARM Limited, All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 */

#include "cmpcl_int.h"
#include <time.h>

static unsigned char output_buf[OUTPUT_BUF_SIZE];

static int cmp_get_first_failinfo_bit(const mbedtls_asn1_bitstring *fi)
{
    size_t byte_idx;
    size_t bit_idx;

    if (fi == NULL || fi->p == NULL || fi->len == 0) {
        return -1;
    }

    for (byte_idx = 0; byte_idx < fi->len; byte_idx++) {
        unsigned char b = fi->p[byte_idx];
        if (b == 0) {
            continue;
        }
        for (bit_idx = 0; bit_idx < 8; bit_idx++) {
            if ((b & (0x80u >> bit_idx)) != 0) {
                return (int) (byte_idx * 8 + bit_idx);
            }
        }
    }
    return -1;
}

static void cmp_log_freetext(const char *label, const mbedtls_asn1_sequence *seq)
{
    int i = 0;
    const mbedtls_asn1_sequence *cur = seq;
    while (cur != NULL) {
        CMPERRV("%s[%d]: %.*s", label, i, (int) cur->buf.len, cur->buf.p == NULL ? "" : (const char *) cur->buf.p);
        cur = cur->next;
        i++;
    }
}

static void cmp_log_server_error(cmp_ctx *ctx, const cmp_pkimessage *cmp_response)
{
    int failinfo = -1;

    if (cmp_response == NULL || cmp_response->error == NULL) {
        CMPERRS("CMP error response received, but no error details were parsed");
        cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_BADDATAFORMAT);
        return;
    }

    CMPERRV("CMP server error: PKIStatus=%d", cmp_response->error->pKIStatusInfo.PKIStatus);
    CMPERRV("CMP server errorCode=%d", cmp_response->error->errorCode);

    if (cmp_response->error->pKIStatusInfo.statusString != NULL) {
        cmp_log_freetext("CMP statusString", cmp_response->error->pKIStatusInfo.statusString);
    }
    if (cmp_response->error->errorDetails != NULL) {
        cmp_log_freetext("CMP errorDetails", cmp_response->error->errorDetails);
    }

    failinfo = cmp_get_first_failinfo_bit(&cmp_response->error->pKIStatusInfo.PKIFailureInfo);
    if (failinfo >= 0) {
        CMPERRV("CMP failInfo bit=%d", failinfo);
        cmp_ctx_set_failinfo(ctx, failinfo);
    } else {
        cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_BADDATAFORMAT);
    }
}

/* body_type may be ir, cr, or kur */
int cmpcl_do_transaction(cmp_ctx *ctx, const int body_type)
{

    memset(output_buf, 0, sizeof(output_buf));
    unsigned char *output_start = output_buf+sizeof(output_buf);
    int len;
    unsigned char *input = NULL;
    size_t inputlen;
    int ret = -1;
    cmp_pkimessage *cmp_response = NULL;
    cmp_pkimessage *pki_conf_msg = NULL;

    time_t now;
    struct tm gm_now;
    char msg_time[MBEDTLS_X509_RFC5280_UTC_TIME_LEN];
    /* Provide current UTC messageTime for servers enforcing badTime checks. */
    now = time(NULL);
    if (now == (time_t) -1 || gmtime_r(&now, &gm_now) == NULL ||
        strftime(msg_time, sizeof(msg_time), "%Y%m%d%H%M%S", &gm_now) !=
            (MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1) ||
        (ret = cmp_ctx_set_messageTime(ctx, msg_time)) != 0) {
        CMPERRS("Error setting messageTime");
        goto syserr;
    }

    cmp_ctx_set_body_type(ctx, body_type);
    int unprotected = ctx->unprotected_ir && (ctx->body_type == MBEDTLS_CMP_PKIBODY_IR);
    size_t sender_nonce_len = ctx->senderNonce_len ? ctx->senderNonce_len : 16;

    /* Generate a fresh senderNonce for each outgoing CMP message. */
    if ((ret = cmp_ctx_set_senderNonce(ctx, sender_nonce_len)) != 0) {
        CMPERRS("Failed to set fresh senderNonce for initial request");
        goto syserr;
    }

    len = cmpcl_CMPwrite_PKIMessage_der(&output_start, output_buf, ctx, unprotected);
    //CMPINFOV("cmpcl_CMPwrite_PKIMessage_der length: %d", len);
    
    if (len < 0) {
        CMPERRV("cmpcl_CMPwrite_PKIMessage der returned %d", len);
        ret = len; /* if negative, len is an error code*/
        goto syserr;
    }
    if (ctx->body_type == MBEDTLS_CMP_PKIBODY_IR) {
        (void) write_to_file("last_ir_request.der", output_start, len);
    } else {
        (void) write_to_file("last_request.der", output_start, len);
    }
    ret = ctx->send_receive_func(ctx->cb_context,
                                 output_start, (size_t) len, &input, &inputlen);
    if (ret < 0) {
        CMPERRS("transport failed");
        goto syserr;
    }
    (void) write_to_file("last_response.der", input, inputlen);

    cmp_response = mbedtls_calloc(1, sizeof(cmp_pkimessage));
    if (!cmp_response) {
        CMPERRS("alloc cmp");
        ret = CMPCL_ERR_MEMORY_ALLOCATION;
        goto syserr;
    }
    cmp_pkimessage_init(cmp_response);

    if ((ret = cmp_pkimessage_parse_check_der(ctx, body_type + 1 /* ip, cp, or kup */, cmp_response,
                                              input, inputlen)) < 0) {
        if (ret == CMPCL_ERR_SERVER_ERROR) {
            cmp_log_server_error(ctx, cmp_response);
            goto syserr;
        }
        CMPERRV("handling CMP response FAILED with return code %d", ret);
        cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_BADDATAFORMAT);
        goto conferr;
    }

    CMPDBGV("Received Header Len %d", (int) cmp_response->header.len);
    CMPDBGV("Received Body Len %d", (int) cmp_response->body.len);


    /* check before possible certConf because new_cert is needed as input */
    /* any caPubs in the response are ignored */
    if (cmp_response->crep && cmp_response->crep->response
        && cmp_response->crep->response->certifiedKeyPair
        && cmp_response->crep->response->certifiedKeyPair->cert) {

        /* verify received Cert */
        mbedtls_x509_crt *new_cert = cmp_response->crep->response->certifiedKeyPair->cert;

        /* take enrolled certificate and chain extraCerts to it */
        if (new_cert->next != NULL) {
            CMPERRS("Received multiple certs. This is unexpected behaviour. Abort transaction!");
            cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_INCORECTDATA);
            ret = -1;
            goto conferr;
        }
        new_cert->next = ctx->extraCerts;

        if (ctx->enrol_trust_anchor != NULL) {
            if ((ret = cmp_x509_crt_verify(new_cert,
                                           ctx->enrol_trust_anchor,
                                           ctx->enrol_crls,
                                           ctx->subject)) != 0) {
                CMPERRV("enrollment chain validation for new certificate failed with return code %d", ret);
                cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_INCORECTDATA);
            }
        } else {
            CMPINFOV("skipping enrollment chain validation for new certificate: no trust anchor given");
        }
        new_cert->next = NULL;

        /* remember */
        ctx->new_cert = cmp_response->crep->response->certifiedKeyPair->cert;
        cmp_response->crep->response->certifiedKeyPair->cert = NULL; /* don't free */

    } else {

        cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_INCORECTDATA);
        ret = CMPCL_ERR_CERT_NOT_RECEIVED;
        goto syserr;
    }
conferr:
    /* check if implicit confirm was granted */
/* preserve ret, if certconf succeeds */
    if ((cmp_response->implicit_conf_granted  == 0 || ctx->cert_conf_fail_info != 0) &&
        ctx->new_cert != NULL) {                                                                                     /* proceed with certConf <--> PKIConf */

        CMPINFOV("## Certificate Confirmation ##");

        pki_conf_msg = mbedtls_calloc(1, sizeof(cmp_pkimessage));
        cmp_pkimessage_init(pki_conf_msg);

        /* reuse output_buf */
        memset(output_buf, 0, sizeof(output_buf));
        output_start = output_buf+sizeof(output_buf);

        cmp_ctx_set_body_type(ctx, MBEDTLS_CMP_PKIBODY_CERTCONF);

        if ((ret = cmp_ctx_set_senderNonce(ctx, sender_nonce_len)) != 0) {
            CMPERRS("Failed to set fresh senderNonce for certConf");
            goto syserr;
        }

        /* build certConf message */
        len = cmpcl_CMPwrite_PKIMessage_der(&output_start, output_buf, ctx, unprotected);

        if (len < 0) {
            CMPERRV("cmpcl_CMPwrite_PKIMessage der returned %d", len);
            ret = len; /* if negative, len is an error code */
            goto syserr;
        }

        /* reuse send_receive for now
         * TODO: leave http session open to improve performance
         */
        input = NULL;
        inputlen = 0;
        len = ctx->send_receive_func(ctx->cb_context,
                                     output_start, (size_t) len, &input, &inputlen);
        if (len < 0) {
            CMPERRS("HTTP/CoAP transfer failed");
            ret = len; /* if negative, len is an error code */
            goto syserr;
        }
        (void) write_to_file("last_pki_conf_response.der", input, inputlen);

        /* parse received PKIConf message */
        if ((len = cmp_pkimessage_parse_check_der(ctx, MBEDTLS_CMP_PKIBODY_PKICONF,
                                                  pki_conf_msg, input, inputlen)) < 0) {
            CMPERRV("Parsing of PKIConf FAILED with return code %d", ret);
            ret = len; /* if negative, len is an error code */
            goto syserr;
        }

    }


syserr:
    cmp_pkimessage_free(pki_conf_msg);
    mbedtls_free(pki_conf_msg);

    cmp_pkimessage_free(cmp_response);
    mbedtls_free(cmp_response);

    return ret;
}
