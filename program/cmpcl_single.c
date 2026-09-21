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

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include "cmpcl_single.h"
#include "cmpcl_log.h"
#include <string.h>
#include "credential_storage.h"

/*******************************************************************************
 * Variables
 ******************************************************************************/


/* ************************************************************************** */

static int gen_ec_key(const char *ecc_curve, mbedtls_pk_context *key, mbedtls_ctr_drbg_context *ctr_drbg)
{
    int ret;
    const mbedtls_ecp_curve_info *curve_info;

    if ((ret = mbedtls_pk_setup(key,
                                mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0) {
        CMPERRV("Key setup failed, mbedtls_pk_setup returned 0x%04x", -ret);
        return ret;
    }

    curve_info = mbedtls_ecp_curve_info_from_name(ecc_curve);
    if (!curve_info) {
        CMPERRV("Failed to extract ecc curve from given name '%s'", ecc_curve);
        return -1;
    }
    ret = mbedtls_ecp_gen_key(curve_info->grp_id, mbedtls_pk_ec(*key),
                              &mbedtls_ctr_drbg_random, ctr_drbg);

    if (ret == 0) {
        CMPDBGS("Generated Key");
    } else {
        CMPERRV("Key gen failed, mbedtls_ec_gen_key returned 0x%04x", ret);
    }
    return ret;
}

/* ************************************************************************** */

int invoke_cert_request(const int body_type,
                        const char *subject_name,
                        const char *ecc_curve,
                        OPTIONAL const unsigned char *exts, size_t exts_len,
                        int popo_method, int popo_md_alg,
                        OPTIONAL const unsigned char *p10, size_t p10_len,
                        OPTIONAL const char *sender_name,
                        OPTIONAL const char *recipient_name,
                        OPTIONAL const char *reference,
                        OPTIONAL const char *pbm_secret,
                        void *cb_context,
                        cmp_send_receive_cb send_receive_func,
                        mbedtls_ctr_drbg_context *ctr_drbg,
                        mbedtls_md_type_t owf, mbedtls_md_type_t mac,
                        int prot_md_alg,
                        OPTIONAL const char *path_to_protection_cert,
                        OPTIONAL const char *path_to_protection_key,
                        OPTIONAL const char *path_to_protection_chain,
                        OPTIONAL const char *path_to_protection_trust_anchor,
                        OPTIONAL const char *path_to_protection_crls,
                        OPTIONAL const char *path_to_enrollment_trust_anchor,
                        OPTIONAL const char *path_to_enrollment_crls,
                        const char *path_to_new_cert,
                        const char *path_to_new_key,
                        const char *path_to_new_chain)
{
    int do_p10cr = body_type == MBEDTLS_CMP_PKIBODY_P10CR;

    /* TODO better use
       cmp_ctx *cmp_client_init(), cmp_client_set_signature_protection(),
       cmp_client_set_pbm_protection(), and cmp_client_enroll_cert(),
       moving repective code portions from there to those functions in cmpcl_high.c */

    mbedtls_x509_crt prot_cert;
    mbedtls_x509_crt_init(&prot_cert);
    mbedtls_pk_context prot_key;
    mbedtls_pk_init(&prot_key);
    mbedtls_x509_crt prot_chain;
    mbedtls_x509_crt_init(&prot_chain);
    mbedtls_x509_crt prot_trust_anchor;
    mbedtls_x509_crt_init(&prot_trust_anchor);
    mbedtls_x509_crl prot_crls;
    mbedtls_x509_crl_init(&prot_crls);

    mbedtls_pk_context enrol_key;
    mbedtls_pk_init(&enrol_key);
    mbedtls_x509_crt enrol_trust_anchor;
    mbedtls_x509_crt_init(&enrol_trust_anchor);
    mbedtls_x509_crl enrol_crls;
    mbedtls_x509_crl_init(&enrol_crls);



    int ret = -1;
    /* create new context */
    cmp_ctx *ctx = cmp_ctx_init(ctr_drbg, cb_context, send_receive_func,
                           popo_method, prot_md_alg, popo_md_alg);
    if (ctx == NULL) {
        CMPERRS("Error initializing context");
        goto err;
        /* need to call cmp_ctx_free() since cmp_ctx_init() does not clean up on error */
    }

    /* protection Cert */
    if (path_to_protection_cert != NULL) {
        if ((ret = append_certs_from_pem(&prot_cert, path_to_protection_cert)) == 0) {
            CMPDBGS("Parsed protecting Cert");
        } else {
            CMPERRS("Parsing protecting Cert failed");
            goto err;
        }
    } else {
        CMPDBGS("No protecting Cert provided");
    }

    if (path_to_protection_chain != NULL) {
        if ((ret = append_certs_from_pem(&prot_chain, path_to_protection_chain)) == 0) {
            CMPDBGS("Parsed protecting Chain");
        } else {
            CMPERRS("Parsing protecting Chain failed");
            goto err;
        }
    } else {
        CMPDBGS("No protecting cert chain provided");
    }

    if (path_to_protection_key != NULL) {
        if ((ret = parse_key_from_pem(&prot_key, path_to_protection_key, ctr_drbg)) == 0) {
            CMPDBGS("Parsed protecting Key");
        } else {
            CMPERRS("Parsing protecting Key failed");
            goto err;
        }
    } else {
        CMPDBGS("No protecting key provided");
    }

    /* protection trust anchor */
    if (path_to_protection_trust_anchor != NULL) {
        if ((ret = append_certs_from_pem(&prot_trust_anchor, path_to_protection_trust_anchor)) == 0) {
            CMPDBGS("Parsed protection trust certs");
        } else {
            CMPERRS("Parsing protection trust failed");
            goto err;
        }
        cmp_ctx_set_prot_trust_anchor(ctx, &prot_trust_anchor);
    } else {
        CMPDBGS("No protection trust certs provided");
    }

    /* protection trust anchor CRLs*/
/*    if (path_to_protection_crls != NULL) {
        if ((ret = append_crls_from_pem(&prot_crls, path_to_protection_crls) == 0)) {
            CMPDBGS("Parsed protection trust CRL");
            cmp_ctx_set_prot_crls(ctx, &prot_crls);
        } else {
            CMPERRS("Parsing protection trust CRL failed");
            goto err;
        }
    } else {
        CMPDBGS("No protection trust CRL provided");
    }
*/
    /* enrollment trust anchor */
    if (path_to_enrollment_trust_anchor != NULL) {
        if ((ret = append_certs_from_pem(&enrol_trust_anchor,
                                         path_to_enrollment_trust_anchor)) == 0) {
            CMPDBGS("Parsed enrollment trust anchor");
        } else {
            CMPERRS("Parsing enrollment trust anchor failed!");
            goto err;
        }
        cmp_ctx_set_enrol_trust_anchor(ctx, &enrol_trust_anchor);
    } else {
        CMPDBGS("No enrollment trust anchor provided");
    }

    /* enrollment trust anchor CRLs */
    if (path_to_enrollment_crls != NULL) {
        if ((ret = append_crls_from_pem(&enrol_crls, path_to_enrollment_crls) == 0)) {
            CMPDBGS("Parsed enrollment CRL");
            cmp_ctx_set_enrol_crls(ctx, &enrol_crls);
        } else {
            CMPERRS("Parsing enrollment CRL failed");
            goto err;
        }
    } else {
        CMPDBGS("No enrollment CRL provided");
    }


    /* set basic header info in ctx */
    char sender_name_aux[MAX_NAME_LENGTH];
    if (sender_name == NULL && path_to_protection_cert != NULL) {
        ret = mbedtls_x509_dn_gets(sender_name_aux, MAX_NAME_LENGTH,
                                   &prot_cert.subject);
        if (ret < 0) {
            CMPERRV(
                "Error reading subject name from existing cert. Code: 0x%04x",
                -ret);
            goto err;
        }
        sender_name = sender_name_aux;
    }
    printf("### sender_name %s\n", sender_name);  
    ret = cmp_ctx_set_sender_name(ctx, sender_name);
    if (ret != 0) {
        CMPERRS("Error setting sender name");
        goto err;
    }

    char recipient_name_aux[MAX_NAME_LENGTH];
    if (recipient_name == NULL && path_to_protection_cert != NULL) {
        ret = mbedtls_x509_dn_gets(recipient_name_aux, MAX_NAME_LENGTH,
                                   &prot_cert.issuer);
        if (ret < 0) {
            CMPERRV(
                "Error reading subject name from existing cert. Code: 0x%04x",
                -ret);
            goto err;
        }
        recipient_name = recipient_name_aux;
    }
    ret = cmp_ctx_set_recipient_name(ctx, recipient_name);
    if (ret != 0) {
        goto err;
    }

    if (reference != NULL) {
        ret = cmp_ctx_set_senderKID(ctx, (const unsigned char *) reference,
                                    strlen((const char *) reference));
        if (ret != 0) {
            goto err;
        }
    }

    /* set request specific fields */
    if (do_p10cr) {
        if (p10 == NULL || p10_len == 0) {
            CMPERRS("P10CR request requires a non-empty p10 CSR");
            goto err;
        }
        cmp_ctx_set_p10(ctx, p10, p10_len);
    } else {
        if (p10 != NULL) {
            CMPERRS("p10 CSR given but request type is not P10CR");
            goto err;
        }
        if ((ret = gen_ec_key(ecc_curve, &enrol_key, ctr_drbg)) < 0) {
            goto err;
        }
        cmp_ctx_set_new_key(ctx, &enrol_key);

        /* take given subject name or read from existing cert */
        char subject_name_aux[MAX_NAME_LENGTH];
        if (subject_name == NULL && path_to_protection_cert != NULL) {
            if (mbedtls_x509_dn_gets(subject_name_aux, MAX_NAME_LENGTH,
                                     &prot_cert.subject) < 0) {
                CMPERRS("Error reading subject name from existing cert");
                goto err;
            }
            subject_name = subject_name_aux;
        }
        if ((ret = cmp_ctx_set_subject_name(ctx, subject_name)) != 0) {
            CMPERRS("Error setting subject name");
            goto err;
        }
        if (exts != NULL)
            cmp_ctx_set_crmf_extension(ctx, exts, exts_len);
    }

    if (body_type != MBEDTLS_CMP_PKIBODY_IR) { /* cert-based protection */
        if (path_to_protection_cert == NULL) {
            CMPERRS("No certificate for CR or KUR!");
            goto err;
        }
        cmp_ctx_set_prot_crt(ctx, &prot_cert);
        if (body_type == MBEDTLS_CMP_PKIBODY_CR) {
            cmp_ctx_set_prot_crt_chain(ctx, &prot_chain);
        }
        cmp_ctx_set_prot_key(ctx, &prot_key);
    } else if (pbm_secret != NULL && body_type != MBEDTLS_CMP_PKIBODY_KUR) { /* this enables use of PBM */
        ret = cmp_ctx_set_prot_pbm_secret(ctx, ctr_drbg, owf, mac,
                                          (const unsigned char *) pbm_secret,
                                          strlen((const char *) pbm_secret));
        if (ret != 0) {
            CMPERRS("Error initializing PBM");
            goto err;
        }
    }

#ifdef UNPROTECTED_ERRORS
    cmp_ctx_set_unprotected_errors(ctx, 1);
#endif

#ifdef IMPLICIT_CONFIRM
    cmp_ctx_set_implicit_confirm(ctx, 1);
#endif

#ifdef CACHE_EXTRACERTS
    cmp_ctx_set_cache_extracerts(ctx, 1);
#endif

#ifdef UNPROTECTED_IR
    cmp_ctx_set_unprotected_ir(ctx, 1);
#endif

    /* execute CMP operation */
    if ((ret = cmpcl_do_transaction(ctx, body_type)) != 0) {
        CMPERRS("Certificate enrollment failed :-/");
    } else {
        print_certinfo("new cert received:\n", "  ", cmp_ctx_get_new_cert(ctx)); /* TODO: find more elegant way to deal with Eclipse terminal */

        if (!do_p10cr && write_private_key_pem(&enrol_key, path_to_new_key) != 0) {
            CMPERRV("Failed to write new key to file %s", path_to_new_key);
            ret = -1;
        }
        if (write_cert_pem(cmp_ctx_get_new_cert(ctx), path_to_new_cert) != 0) {
            CMPERRV("Failed to write new cert to file %s", path_to_new_cert);
            ret = -1;
        }
        if (write_cert_pem(cmp_ctx_get_extraCerts(ctx), path_to_new_chain) != 0) {
            CMPERRV("Failed to write new chain to file %s", path_to_new_chain);
            ret = -1;
        }
    }

err:
    /* cleanup */
    cmp_ctx_free(ctx);
    mbedtls_pk_free(&enrol_key);
    mbedtls_pk_free(&prot_key);
    mbedtls_x509_crt_free(&prot_chain);
    mbedtls_x509_crt_free(&prot_cert);
    mbedtls_x509_crt_free(&prot_trust_anchor);
    mbedtls_x509_crl_free(&prot_crls);
    mbedtls_x509_crt_free(&enrol_trust_anchor);
    mbedtls_x509_crl_free(&enrol_crls);
    return ret;

}
