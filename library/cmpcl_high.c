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
#include "mbedtls/rsa.h"
#include "mbedtls_transport.h"
#include "credential_storage.h"

void cmp_client_set_transport(cmp_ctx *ctx,
                              void *cb_context,
                              cmp_send_receive_cb send_receive_func)
{
    ctx->cb_context = cb_context;
    ctx->send_receive_func = send_receive_func;
}

int cmp_client_set_http(cmp_ctx *ctx,
                        const char *server, OPTIONAL const char *port,
                        const char *path,
                        OPTIONAL const char *tls_trusted,
                        OPTIONAL const char *tls_key, OPTIONAL const char *tls_cert)
{
    ctx->cb_context = mbedtls_calloc(1, sizeof(mbed_tls_transport_ctx));
    if (ctx->cb_context == NULL) {
        CMPERRS("Out of memory\n");
        return CMPCL_ERR_MEMORY_ALLOCATION;
    }
    int use_plain_http = tls_trusted == NULL;
    if (port == NULL) {
        port = use_plain_http ? "80" : "443";
    }
    int ret = mbed_tls_transport_init(ctx->cb_context, use_plain_http, ctx->ctr_drbg,
            tls_cert, tls_key, tls_trusted, server, port, path);
    if (ret != 0) {
        CMPERRV(" failed\n  ! mbed_tls_transport_init returned %d\n", ret);
        return ret;
    }
    cmp_client_set_transport(ctx, ctx->cb_context, mbed_tls_send_receive);
    return 0;
}

cmp_ctx *cmp_client_init(OPTIONAL const char *sender_name,
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
    if (sender_name) {
        ret = cmp_ctx_set_sender_name(ctx, sender_name);
        if (ret != 0) {
            CMPERRV(" failed\n  ! cmp_ctx_set_sender_name returned %d\n", ret);
            cmp_ctx_free(ctx);
            return NULL;
        }
    }
    if (recipient_name) {
        ret = cmp_ctx_set_recipient_name(ctx, recipient_name);
        if (ret != 0) {
            CMPERRV(" failed\n  ! cmp_ctx_set_recipient_name returned %d\n", ret);
            cmp_ctx_free(ctx);
            return NULL;
        }
    }
    cmp_ctx_set_unprotected_errors(ctx, allow_unprotected_errors);
    return ctx;
}


static mbedtls_x509_crt* new_crt_from_pem(const char *path_to_pem) {
    mbedtls_x509_crt *crt = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));
    if (crt == NULL) {
        CMPERRS("Out of memory\n");
        return NULL;
    }
    mbedtls_x509_crt_init(crt);
    if ((append_certs_from_pem(crt, path_to_pem)) == 0) {
        CMPDBGV("Parsed cert from ", path_to_pem);
        return crt;
    } else {
        CMPERRV("Parsing cert from %s failed", path_to_pem);
        mbedtls_x509_crt_free(crt);
        return NULL;
    }
}

static mbedtls_x509_crl* new_crl_from_pem(const char *path_to_pem) {
    mbedtls_x509_crl *crl = mbedtls_calloc(1, sizeof(mbedtls_x509_crl));
    if (crl == NULL) {
        CMPERRS("Out of memory\n");
        return NULL;
    }
    mbedtls_x509_crl_init(crl);
    if ((append_crls_from_pem(crl, path_to_pem)) == 0) {
        CMPDBGV("Parsed crl from ", path_to_pem);
        return crl;
    } else {
        CMPERRV("Parsing crl from %s failed", path_to_pem);
        mbedtls_x509_crl_free(crl);
        return NULL;
    }
}


int cmp_client_enable_signature_protection(cmp_ctx *ctx, int md_alg,
                                           OPTIONAL const mbedtls_pk_context *key,
                                           OPTIONAL const char *crt,
                                           OPTIONAL const char *crt_chain,
                                           OPTIONAL const char *trusted,
                                           OPTIONAL const char *crls)
{
    int ret = -1;

    if (ctx == NULL) {
        CMPERRS("Invalid context");
        return ret;
    }

    /* if trusted is NULL, also crls must be NULL */
     if (trusted == NULL && crls != NULL) {
             CMPERRS("if trusted is NULL, also crls must be NULL");
             return ret;
         }

    /* either key and crt, and crt_chain must be NULL (unprotected_requests) or key and crt must be given */

    if (key == NULL && crt == NULL && crt_chain == NULL) {
        cmp_ctx_set_prot_key(ctx, NULL);
        cmp_ctx_set_prot_crt(ctx, NULL);
        cmp_ctx_set_prot_crt_chain(ctx, NULL);
        cmp_ctx_set_sig_prot_md_alg(ctx, -1);
    } else if (key == NULL || crt == NULL) {
        CMPERRS("key and crt must be given");
        return ret;
    }  else {
        cmp_ctx_set_sig_prot_md_alg(ctx, md_alg);
        cmp_ctx_set_prot_key(ctx, key);
        mbedtls_x509_crt *mcrt = new_crt_from_pem(crt);
        if (mcrt == NULL) {
            goto err;
        }
        cmp_ctx_set_prot_crt(ctx, mcrt);
        if (crt_chain != NULL) {
            mbedtls_x509_crt *mcrt_chain = new_crt_from_pem(crt_chain);
            if (mcrt_chain == NULL) {
                goto err;
            }
            cmp_ctx_set_prot_crt_chain(ctx, mcrt_chain);
        } else {
            cmp_ctx_set_prot_crt_chain(ctx, NULL);
        }
    }
    if (trusted == NULL) {
        if (crls != NULL) {
            CMPERRS("if trusted is NULL, also crls must be NULL");
            goto err;
        }
        cmp_ctx_set_prot_trust_anchor(ctx, NULL);
    } else {
        mbedtls_x509_crt *mtrusted = new_crt_from_pem(trusted);
        if (mtrusted == NULL) {
            goto err;
        }
        cmp_ctx_set_prot_trust_anchor(ctx, mtrusted);
    }
    if (crls != NULL) {
        mbedtls_x509_crl *mcrls = new_crl_from_pem(crls);
        if (mcrls == NULL) {
            goto err;
        }
        cmp_ctx_set_prot_crls(ctx, mcrls);
    } else {
        cmp_ctx_set_prot_crls(ctx, NULL);
    }
    return 0;
  err:
    cmp_ctx_set_sig_prot_md_alg(ctx, -1);
    cmp_ctx_set_prot_trust_anchor(ctx, NULL);
    cmp_ctx_set_prot_crls(ctx, NULL);
    cmp_ctx_set_prot_key(ctx, NULL);
    cmp_ctx_set_prot_crt(ctx, NULL);
    cmp_ctx_set_prot_crt_chain(ctx, NULL);
    return ret;
}

int cmp_client_set_pbm_protection(cmp_ctx *ctx,
                                  const unsigned char *secret, size_t len,
                                  OPTIONAL const unsigned char *ref, size_t ref_len,
                                  size_t salt_len, /* mbedtls_md_type_t */ int owf,
                                  /* mbedtls_md_type_t */ int mac, int iterationCount)
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

    if ((ret = setStr(&ctx->prot_secret, secret, len)) != 0) {
        CMPERRS("Failed to set PBM secret\n");
        return ret;
    }
    ctx->secret_len = len;

    if (ref != NULL && ref_len > 0) {
        if ((ret = cmp_ctx_set_senderKID(ctx, ref, ref_len)) != 0)
            return ret;
    }
    return 0;
}

int generate_key(const char *key_type,
                 mbedtls_ctr_drbg_context *ctr_drbg,
                 mbedtls_pk_context **pkey)
{
    int ret;
    const char *param;

    *pkey = NULL;

    mbedtls_pk_context *key = mbedtls_calloc(1, sizeof(mbedtls_pk_context));
    if (key == NULL) {
        CMPERRS("Out of memory\n");
        return CMPCL_ERR_MEMORY_ALLOCATION;
    }
    mbedtls_pk_init(key);

    if (strncmp(key_type, "RSA:", 4) == 0) {
        param = key_type + 4;
        unsigned int nbits = (unsigned int) atoi(param);
        if (nbits == 0) {
            CMPERRV("Invalid RSA key size: %s", param);
            ret = -1;
            goto end;
        }
        ret = mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
        if (ret != 0) {
            CMPERRV("Key setup failed, mbedtls_pk_setup returned 0x%04x", -ret);
            goto end;
        }
        ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key),
                                  mbedtls_ctr_drbg_random, ctr_drbg,
                                  nbits, 65537);
        if (ret != 0) {
            CMPERRV("RSA key generation failed, returned 0x%04x", -ret);
            goto end;
        }
    } else {
        /* EC key: accept "EC:<curve>" or bare "<curve>" for backward compat */
        if (strncmp(key_type, "EC:", 3) == 0) {
            param = key_type + 3;
        } else {
            param = key_type;
        }
        const mbedtls_ecp_curve_info *curve_info =
            mbedtls_ecp_curve_info_from_name(param);
        if (curve_info == NULL) {
            CMPERRV("Unknown EC curve name: %s", param);
            ret = -1;
            goto end;
        }
        ret = mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        if (ret != 0) {
            CMPERRV("Key setup failed, mbedtls_pk_setup returned 0x%04x", -ret);
            goto end;
        }
        ret = mbedtls_ecp_gen_key(curve_info->grp_id, mbedtls_pk_ec(*key),
                                  mbedtls_ctr_drbg_random, ctr_drbg);
        if (ret != 0) {
            CMPERRV("EC key generation failed, returned 0x%04x", -ret);
            goto end;
        }
    }

    *pkey = key;
    return 0;

  end:
    mbedtls_pk_free(key);
    mbedtls_free(key);
    return ret;
}

int cmp_client_enroll_cert(cmp_ctx *ctx, int request_body_type,
                           const char *subject,
                           OPTIONAL const char *new_key_type,
                           OPTIONAL mbedtls_pk_context **pkey,
                           OPTIONAL const char *key_file,
                           // TODO OPTIONAL const ... extensions,
                           int popo_md_alg,
                           OPTIONAL const char *enrol_trusted,
                           OPTIONAL const char *enrol_CRLs,
                           int implicit_confirm,
                           const char *new_cert, const char *extraCerts
                           /*mbedtls_x509_crt **new_cert, mbedtls_x509_crt **extraCerts*/)
{
    mbedtls_pk_context *key = NULL;
    int generated = 0;
    int ret;

    if (new_key_type != NULL) {
        ret = generate_key(new_key_type, ctx->ctr_drbg, &key);
        if (ret != 0) {
            return ret;
        }
        generated = 1;
    } else if (pkey != NULL) {
        key = *pkey;
    }

    cmp_ctx_set_subject_name(ctx, subject);
    cmp_ctx_set_new_key(ctx, key);
    /* use CMP_CTX_POPO_RAVERIFIED if popo_md_alg == -1 */
    cmp_ctx_set_popo_method(ctx, popo_md_alg == -1 ?
    CMP_CTX_POPO_RAVERIFIED : CMP_CTX_POPO_SIGNATURE);
    cmp_ctx_set_popo_md_alg(ctx, popo_md_alg);
    ret = -1;
    if (enrol_trusted) {
        mbedtls_x509_crt *menrol_trusted = new_crt_from_pem(enrol_trusted);
        if (menrol_trusted == NULL) {
            goto err;
        }
        cmp_ctx_set_enrol_trust_anchor(ctx, menrol_trusted);
    }
    if (enrol_CRLs) {
        mbedtls_x509_crl *menrol_CRLs = new_crl_from_pem(enrol_CRLs);
        if (menrol_CRLs == NULL) {
            goto err;
        }
        cmp_ctx_set_enrol_crls(ctx, menrol_CRLs);
    }
    cmp_ctx_set_implicit_confirm(ctx, implicit_confirm);


    if ((ret = cmpcl_do_transaction(ctx, request_body_type)) != 0) {
        goto err;
    }
    print_certinfo("new cert received:\n", "  ", cmp_ctx_get_new_cert(ctx)); /* TODO: find more elegant way to deal with Eclipse terminal */

    if ((ret = write_cert_pem(cmp_ctx_get_new_cert(ctx), new_cert)) != 0) {
        CMPERRV("Failed to write new cert to file %s", new_cert);
        goto err;
    }
    if ((ret = write_cert_pem(cmp_ctx_get_extraCerts(ctx), extraCerts)) != 0) {
        CMPERRV("Failed to write new chain to file %s", extraCerts);
        goto err;
    }
    if (key_file != NULL && (ret = write_private_key_pem(key, key_file)) != 0) {
        CMPERRV("Failed to write key to file %s", key_file);
        goto err;
    }
    if (pkey != NULL) {
        *pkey = key;
    }
    return 0;

  err:
    if (generated) {
        /* Use cmp_ctx_set_new_key(NULL) to free the key and clear ctx->new_key
         * in one step, preventing the double-free that would otherwise occur
         * when cmp_client_free() calls key_free(ctx->new_key) later. */
        cmp_ctx_set_new_key(ctx, NULL);
        if (pkey != NULL)
            *pkey = NULL;
    } else {
        /* Key is caller-owned; just clear the pointer so cmp_client_free()
         * does not free memory it does not own. */
        ctx->new_key = NULL;
    }
    return ret != 0 ? ret : -1;
}

int cmp_client_enroll_p10(cmp_ctx *ctx,
                          const unsigned char *p10, size_t p10_len,
                          OPTIONAL const char *enrol_trusted,
                          OPTIONAL const char *enrol_CRLs,
                          int implicit_confirm,
                          char *new_cert, char *extraCerts) {
    int ret = -1;
    if (p10 == NULL || p10_len == 0) {
        CMPERRS("invalid p10 ");
        return -1;
    }
    ctx->p10 = p10;
    ctx->p10_len = p10_len;
    if (enrol_CRLs) {
        mbedtls_x509_crl *menrol_CRLs = new_crl_from_pem(enrol_CRLs);
        if (menrol_CRLs == NULL) {
            goto err;
        }
        cmp_ctx_set_enrol_crls(ctx, menrol_CRLs);
    }
    cmp_ctx_set_implicit_confirm(ctx, implicit_confirm);


    if ((ret = cmpcl_do_transaction(ctx, MBEDTLS_CMP_PKIBODY_P10CR)) != 0) {
        goto err;
    }
    print_certinfo("new cert received:\n", "  ", cmp_ctx_get_new_cert(ctx)); /* TODO: find more elegant way to deal with Eclipse terminal */

    if ((ret = write_cert_pem(cmp_ctx_get_new_cert(ctx), new_cert)) != 0) {
        CMPERRV("Failed to write new cert to file %s", new_cert);
        goto err;
    }
    if ((ret = write_cert_pem(cmp_ctx_get_extraCerts(ctx), extraCerts)) != 0) {
        CMPERRV("Failed to write new chain to file %s", extraCerts);
        goto err;
    }
    return 0;

  err:
    return ret != 0 ? ret : -1;
}


void cmp_client_free(cmp_ctx *ctx)
{
    crt_free(ctx->prot_trust_anchor);
    crl_free(ctx->prot_crls);
    key_free(ctx->prot_key);
    crt_free(ctx->prot_cert);
    crt_free(ctx->prot_chain);
    crt_free(ctx->enrol_trust_anchor);
    crl_free(ctx->enrol_crls);
    key_free(ctx->new_key);
    if (ctx->cb_context != NULL) {
        mbed_tls_transport_free(ctx->cb_context);
        mbedtls_free(ctx->cb_context);
    }
    mbedtls_ctr_drbg_context *ctr_drbg = ctx->ctr_drbg;
    mbedtls_entropy_context *entropy = ctx->entropy;
    cmp_ctx_free(ctx);
    if (ctr_drbg) {
        mbedtls_free(ctr_drbg);
    }
    if (entropy) {
        mbedtls_free(entropy);
    }
}

