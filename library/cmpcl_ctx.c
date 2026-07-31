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
#include "mbedtls_transport.h"


/* **************************************************************** */
/* CMP CTX-setting functions */
/* **************************************************************** */
cmp_ctx *cmp_ctx_init(mbedtls_ctr_drbg_context *ctr_drbg,
                 void *cb_context, cmp_send_receive_cb send_receive_func,
                 int popo_method, int prot_md_alg, int popo_md_alg)
{
    cmp_ctx *ctx = mbedtls_calloc(1, sizeof(cmp_ctx));
    if (ctx == NULL) {
        CMPERRS("Out of memory\n");
        return NULL;
    }
    memset(ctx, 0, sizeof(cmp_ctx));

    ctx->cb_context = cb_context;
    ctx->send_receive_func = send_receive_func;
    ctx->ctr_drbg = ctr_drbg;

    if (cmp_ctx_set_transactionID(ctx, 16) != 0) {
        CMPERRS("Failed to set transaction ID!");
        cmp_ctx_free(ctx);
        return NULL;
    }
    if (cmp_ctx_set_senderNonce(ctx, 16) != 0) {
        CMPERRS("Failed to set sender nonce!");
        cmp_ctx_free(ctx);
        return NULL;

    }
    cmp_ctx_set_popo_method(ctx, popo_method);

    cmp_ctx_set_sig_prot_md_alg(ctx, prot_md_alg);
    cmp_ctx_set_popo_md_alg(ctx, popo_md_alg);

    ctx->cb_context = cb_context;
    ctx->send_receive_func = send_receive_func;

    return ctx;
}

/* **************************************************************** */
int cmp_ctx_set_prot_pbm_secret(cmp_ctx *ctx, mbedtls_ctr_drbg_context *ctr_drbg,
                                mbedtls_md_type_t owf, mbedtls_md_type_t mac,
                                const unsigned char *secret, size_t len)
{
    setStr(&ctx->prot_secret, secret, len);
    ctx->secret_len = len;

    cmp_PBMParameter *pbmp;
    pbmp = (cmp_PBMParameter *) mbedtls_calloc(1, sizeof(cmp_PBMParameter));
    if (pbmp == NULL) {
        CMPERRS("Out of memory\n");
        return CMPCL_ERR_MEMORY_ALLOCATION;
    }
    if (cmp_PBMParameter_init(pbmp, ctr_drbg, 16, /* salt_len, TODO remove hard-coded */
                              owf, 1000, /* iterationCount, TODO remove hard-coded */
                              mac) != 0) {
        CMPERRS("FAILED to set PBM parameter!");
        return CMPCL_ERR_PBM_PARM;
    }
    cmp_ctx_set_pbmp(ctx, pbmp);
    return 0;
}

/* **************************************************************** */
int cmp_ctx_set_senderKID(cmp_ctx *ctx, const unsigned char *ref, size_t len)
{
    if (setStr(&ctx->senderKID, ref, len) != 0) {
        CMPERRS("Failed to set senderKID!");
        return -1;
    }
    ctx->reference_len = len;
    return 0;
}

/* **************************************************************** */
int cmp_ctx_set_messageTime(cmp_ctx *ctx, const char *msgTime)
{
    if (strlen(msgTime) != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1) {
        return CMPCL_ERR_MSGTIME_LEN;
    }
    if (!ctx->messageTime) {
        ctx->messageTime = mbedtls_calloc(1, MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1);
    }
    if (!ctx->messageTime) {
        CMPERRS("Out of memory!");
        return CMPCL_ERR_MEMORY_ALLOCATION;
    }

    strncpy(ctx->messageTime, msgTime, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);
    ctx->messageTime[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';
    ctx->messageTime[MBEDTLS_X509_RFC5280_UTC_TIME_LEN] = '\0';

    return 0;
}

/* **************************************************************** */
int cmp_ctx_set_transactionID(cmp_ctx *ctx, size_t len)
{
    if (cmp_ctx_set_rndm_str(&ctx->transactionID, &ctx->transactionID_len, ctx->ctr_drbg,
                             len) != 0) {
        CMPERRS("Failed to set transaction ID!");
        return -1;
    }
    return 0;
}

/* **************************************************************** */
int cmp_ctx_set_senderNonce(cmp_ctx *ctx, size_t len)
{
    if (cmp_ctx_set_rndm_str(&ctx->senderNonce, &ctx->senderNonce_len, ctx->ctr_drbg,
                             len) != 0) {
        CMPERRS("Failed to set sender nonce!");
        return -1;
    }
    return 0;
}

/* **************************************************************** */
int cmp_ctx_set_recipNonce(cmp_ctx *ctx, const unsigned char *nonce, size_t len)
{
    if (setStr(&ctx->recipNonce, nonce, len) != 0) {
        CMPERRS("Failed to set recipient nonce!");
        return -1;
    }
    return 0;
}

/* **************************************************************** */
void cmp_ctx_set_prot_key(cmp_ctx *ctx, const mbedtls_pk_context *key)
{
    key_free((mbedtls_pk_context*) ctx->prot_key);
    ctx->prot_key = key;
}


/* **************************************************************** */
void cmp_ctx_set_prot_crt(cmp_ctx *ctx, const mbedtls_x509_crt *crt)
{
    crt_free(ctx->prot_cert);
    ctx->prot_cert = crt;
}


/* **************************************************************** */
void cmp_ctx_set_prot_crt_chain(cmp_ctx *ctx, const mbedtls_x509_crt *crt_chain)
{
    crt_free(ctx->prot_chain);
    ctx->prot_chain = crt_chain;
}

/* **************************************************************** */
int cmp_ctx_set_sender_name(cmp_ctx *ctx, const char *sender_name)
{
    return mbedtls_x509_string_to_names(&ctx->sender, sender_name);
}

/* **************************************************************** */
int cmp_ctx_set_recipient_name(cmp_ctx *ctx, const char *recipient_name)
{
    return mbedtls_x509_string_to_names(&ctx->recipient, recipient_name);
}

/* **************************************************************** */
void cmp_ctx_set_sig_prot_md_alg(cmp_ctx *ctx, mbedtls_md_type_t md_alg)
{
    ctx->sig_prot_md_alg = md_alg;
}

/* **************************************************************** */
void cmp_ctx_set_prot_trust_anchor(cmp_ctx *ctx, const mbedtls_x509_crt *crt)
{
    crt_free(ctx->prot_trust_anchor);
    ctx->prot_trust_anchor = crt;
}

/* **************************************************************** */
void cmp_ctx_set_prot_crls(cmp_ctx *ctx, const mbedtls_x509_crl *crl)
{
    crl_free(ctx->prot_crls);
    ctx->prot_crls = crl;
}

/* **************************************************************** */
void cmp_ctx_set_crmf_extension(cmp_ctx *ctx,
                                const unsigned char *exts, size_t len)
{
    ctx->crmf_extensions = exts;
    ctx->crmf_extensions_len = len;
}

/* **************************************************************** */
void cmp_ctx_set_p10(cmp_ctx *ctx,
                     OPTIONAL const unsigned char *p10, size_t len)
{
    ctx->p10 = p10;
    ctx->p10_len = len;
}


/* **************************************************************** */
void cmp_ctx_set_enrol_trust_anchor(cmp_ctx *ctx, const mbedtls_x509_crt *crt)
{
    crt_free(ctx->enrol_trust_anchor);
    ctx->enrol_trust_anchor = crt;
}

/* **************************************************************** */
void cmp_ctx_set_enrol_crls(cmp_ctx *ctx, const mbedtls_x509_crl *crl)
{
    crl_free(ctx->enrol_crls);
    ctx->enrol_crls = crl;
}

/* **************************************************************** */
/* body CTX-setting functions */
/* **************************************************************** */

/* **************************************************************** */
int cmp_ctx_set_subject_name(cmp_ctx *ctx, const char *subject_name)
{
    return mbedtls_x509_string_to_names(&ctx->subject, subject_name);
}

/* **************************************************************** */
void cmp_ctx_set_new_key(cmp_ctx *ctx, const mbedtls_pk_context *new_key)
{
    key_free(ctx->new_key);
    ctx->new_key = new_key;
}

/* **************************************************************** */
void cmp_ctx_set_popo_method(cmp_ctx *ctx, int popo_method)
{
    ctx->popo_method = popo_method;
}

/* **************************************************************** */
void cmp_ctx_set_popo_md_alg(cmp_ctx *ctx, mbedtls_md_type_t md_alg)
{
    ctx->popo_md_alg = md_alg;
}

/* **************************************************************** */
void cmp_ctx_set_pbmp(cmp_ctx *ctx, cmp_PBMParameter *pbmp)
{
    if (ctx->pbmp) {
        cmp_PBMParameter_free(ctx->pbmp);
        mbedtls_free(ctx->pbmp);
    }
    ctx->pbmp = pbmp;
}

/* **************************************************************** */
void cmp_ctx_set_body_type(cmp_ctx *ctx, int type)
{
    ctx->body_type = type;
}

/* **************************************************************** */
void cmp_ctx_set_implicit_confirm(cmp_ctx *ctx, int ic)
{
    ctx->implicitConfirm = ic;
}

/* **************************************************************** */
void cmp_ctx_set_unprotected_errors(cmp_ctx *ctx, int allow)
{
    ctx->unprotected_errors = allow;
}

/* **************************************************************** */
void cmp_ctx_set_cache_extracerts(cmp_ctx *ctx, int cache)
{
    ctx->cache_extracerts = cache;
}
/* **************************************************************** */
void cmp_ctx_set_unprotected_requests(cmp_ctx *ctx, int unprot)
{
    ctx->unprotected_requests = unprot;
}
/* **************************************************************** */

void cmp_ctx_set_failinfo(cmp_ctx *ctx, int fail_info)
{
    ctx->cert_conf_fail_info |= (1 << fail_info);
}
/* **************************************************************** */

mbedtls_x509_crt *cmp_ctx_get_new_cert(const cmp_ctx *ctx)
{
    return ctx->new_cert;
}
/* **************************************************************** */

mbedtls_x509_crt *cmp_ctx_get_extraCerts(const cmp_ctx *ctx)
{
    return ctx->extraCerts;
}
/* **************************************************************** */

void cmp_ctx_free(cmp_ctx *ctx)
{
    if (ctx == NULL)
        return;

    mbedtls_asn1_free_named_data_list(&ctx->sender);
    mbedtls_asn1_free_named_data_list(&ctx->recipient);

    if (ctx->messageTime) {
        mbedtls_free(ctx->messageTime);
    }
    if (ctx->senderKID) {
        mbedtls_free(ctx->senderKID);
    }
    if (ctx->transactionID) {
        mbedtls_free(ctx->transactionID);
    }
    if (ctx->senderNonce) {
        mbedtls_free(ctx->senderNonce);
    }
    if (ctx->recipNonce) {
        mbedtls_free(ctx->recipNonce);
    }
    if (ctx->extraCerts) {
        mbedtls_x509_crt_free(ctx->extraCerts);
        mbedtls_free(ctx->extraCerts);
    }
    mbedtls_asn1_free_named_data_list(&ctx->subject);

    if (ctx->pbmp) {
        cmp_PBMParameter_free(ctx->pbmp);
        mbedtls_free(ctx->pbmp);
    }
    if (ctx->prot_secret) {
        mbedtls_free(ctx->prot_secret);
    }
    if (ctx->new_cert) {
        mbedtls_x509_crt_free(ctx->new_cert);
        mbedtls_free(ctx->new_cert);
    }
    mbedtls_ctr_drbg_free(ctx->ctr_drbg);
    mbedtls_entropy_free(ctx->entropy);
    mbedtls_platform_zeroize(ctx, sizeof(cmp_ctx));
    mbedtls_free(ctx);
}
