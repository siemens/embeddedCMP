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

#include "cmpcl_high.h"
#include "cmpcl_int.h"

cmp_ctx *cmp_client_init(const char *server, OPTIONAL const char *port,
                         const char *path,
                         OPTIONAL const char *tls_key, OPTIONAL const char *tls_cert,
                         OPTIONAL const char *tls_trusted,
                         OPTIONAL const char *sender_name,
                         OPTIONAL const char *recipient_name,
                         int allow_unprotected_errors)
{
    cmp_ctx *ctx = mbedtls_calloc(1, sizeof(cmp_ctx));
    if (ctx == NULL) {
        CMPERRS("Out of memory\n");
        return NULL;
    }

    ctx->entropy = mbedtls_calloc(1, sizeof(mbedtls_entropy_context));
    ctx->ctr_drbg = mbedtls_calloc(1, sizeof(mbedtls_ctr_drbg_context));
    if (ctx->entropy == NULL || ctx->ctr_drbg == NULL) {
        CMPERRS("Out of memory\n");
        cmp_ctx_free(ctx);
        return NULL;
    }

    mbedtls_entropy_init(ctx->entropy);
    mbedtls_ctr_drbg_init(ctx->ctr_drbg);
    const char *pers = "cmp_client";
    int ret = mbedtls_ctr_drbg_seed(ctx->ctr_drbg, mbedtls_entropy_func, ctx->entropy,
                                    (const unsigned char *) pers, strlen(pers));
    if (ret != 0) {
        CMPERRV(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        cmp_ctx_free(ctx);
        return NULL;
    }

    // TODO complete the function body
    return ctx;
}


int cmp_client_set_signature_protection(cmp_ctx *ctx, int md_alg,
                                        OPTIONAL const mbedtls_pk_context *key,
                                        OPTIONAL const char *crt,
                                        OPTIONAL const char *crt_chain,
                                        OPTIONAL const char *trusted,
                                        OPTIONAL const char *crls)
                                        /*
                                        OPTIONAL const mbedtls_x509_crt *crt,
                                        OPTIONAL const mbedtls_x509_crt *crt_chain,
                                        OPTIONAL const mbedtls_x509_crt *trusted,
                                        OPTIONAL const mbedtls_x509_crl *crls)
                                         */
{
    /* either key and crt, and crt_chain must be NULL (unprotected_requests) or key and crt must be given */
   /* if trusted is NULL, also crls must be NULL */

    // TODO implement the function body
    return 0;
}
int cmp_client_set_pbm_protection(cmp_ctx *ctx,
                                  size_t salt_len, /* mbedtls_md_type_t */ int owf,
                                  /* mbedtls_md_type_t */ int mac, int iterationCount,
                                  const unsigned char *secret, size_t len,
                                  OPTIONAL const unsigned char *ref, size_t ref_len)
{
    int ret = 0;

    cmp_PBMParameter *pbmp = (cmp_PBMParameter *) mbedtls_calloc(1, sizeof(cmp_PBMParameter));
    if (pbmp == NULL) {
        CMPERRS("Out of memory\n");
        return CMPCL_ERR_MEMORY_ALLOCATION;
    }

    if ((ret = cmp_PBMParameter_init(pbmp, ctx->ctr_drbg, salt_len, owf, iterationCount, mac)) != 0) {
        CMPERRS("Failed to initialize PBM parameters\n");
        mbedtls_free(pbmp);
        return ret;
    }
    cmp_ctx_set_pbmp(ctx, pbmp); /* consumes pbmp */

    if (setStr(&ctx->prot_secret, secret, len) != 0) {
        CMPERRS("Failed to set PBM secret\n");
        return CMPCL_ERR_MEMORY_ALLOCATION;
    }
    ctx->secret_len = len;

    if (ref != NULL && ref_len > 0) {
        if ((ret = cmp_ctx_set_senderKID(ctx, ref, ref_len)) != 0)
            return ret;
    }

    // TODO complete the function body
    return 0;
}

int cmp_client_enroll_cert(cmp_ctx *ctx, int request_body_type,
                           const char *subject,
                           const mbedtls_pk_context *key,
                           // TODO OPTIONAL const ... extensions,
                           int popo_md_alg,
                           OPTIONAL const char *enrol_trusted,
                           OPTIONAL const char *enrol_CRLs,
                           int implicit_confirm,
                           char *new_cert, char *extraCerts
                           /*mbedtls_x509_crt **new_cert, mbedtls_x509_crt **extraCerts*/)
{
    /* use CMP_CTX_POPO_RAVERIFIED if popo_md_alg == -1 */

    // TODO complete the function body
    return 0;
}

void cmp_client_free(cmp_ctx *ctx)
{
    cmp_ctx_free(ctx);
}

