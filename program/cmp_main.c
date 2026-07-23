/*
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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "cmpcl_high.h"
#include "cmpclient_config.h"
#include "credential_storage.h"
#include "debug_macros.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)


#ifdef IMPLICIT_CONFIRM
static int implicit_confirm = 1;
#else
static int implicit_confirm = 0;
#endif

static int run_enroll(int body_type, const char *server_path,
                      const char *subject,
                      /* signature-based protection (NULL for PBM-only): */
                      const char *prot_key_path,
                      const char *prot_cert_path,
                      const char *prot_chain_path,
                      /* output paths: */
                      const char *out_key_path,
                      const char *out_cert_path,
                      const char *out_chain_path,
                      mbedtls_ctr_drbg_context *ctr_drbg)
{
    int ret = -1;
    cmp_ctx *ctx = cmp_client_init(subject, RECIPIENT_NAME, 1);
    if (ctx == NULL) {
        PRINTF("failed to initialize CMP context\n");
        return ret;
    }
    if ((ret = cmp_client_set_http(ctx, SERVER_HOST, TOSTRING(SERVER_PORT),
                                   server_path, TLS_CLIENT_KEY,
                                   TLS_CLIENT_CERT, TLS_SERVER_ROOT)) != 0) {
        goto end;
    }
    if (prot_key_path != NULL) {
        /* signature-based protection using existing credentials */
        mbedtls_pk_context *protkey = mbedtls_calloc(1, sizeof(mbedtls_pk_context));
        if (protkey == NULL) {
            CMPERRS("Out of memory\n");
            goto end;
        }
        if ((ret = parse_key_from_pem(protkey, prot_key_path, ctr_drbg)) < 0) {
            goto end;
        }
        if ((ret = cmp_client_enable_signature_protection(ctx, SIG_PROT_MD_ALG,
                                                          protkey, prot_cert_path,
                                                          prot_chain_path,
                                                          PATH_TO_PROTECTION_TRUST_ANCHOR_PEM,
                                                          PATH_TO_PROTECTION_CRLS)) < 0) {
            goto end;
        }
    } else {
        /* PBM-based protection (e.g., initial enrollment) */
        if ((ret = cmp_client_enable_signature_protection(ctx, -1, NULL, NULL, NULL,
                                                          PATH_TO_PROTECTION_TRUST_ANCHOR_PEM,
                                                          PATH_TO_PROTECTION_CRLS)) < 0) {
            goto end;
        }
        if ((ret = cmp_client_set_pbm_protection(ctx,
                                                 (unsigned char *) PBM_SECRET,
                                                 strlen(PBM_SECRET),
                                                 (unsigned char *) PBM_KID,
                                                 strlen(PBM_KID),
                                                 16, PBM_OWF, PBM_MAC, 1000)) < 0) {
            goto end;
        }
    }
    mbedtls_pk_context *newkey = NULL;
    if ((ret = cmp_client_enroll_cert(ctx, body_type, subject,
                                      NEW_KEY_ECCURVE, &newkey, out_key_path,
                                      POPO_MD_ALG,
                                      PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM,
                                      PATH_TO_ENROLLMENT_CRLS,
                                      implicit_confirm,
                                      out_cert_path, out_chain_path)) < 0) {
        goto end;
    }
    ret = 0;
  end:
    cmp_client_free(ctx);
    return ret;
}

static int run_p10(mbedtls_ctr_drbg_context *ctr_drbg)
{
    unsigned char* p10 = NULL;
    size_t p10_len = 0;
    int ret = -1;
    cmp_ctx *ctx = cmp_client_init(BOOTSTRAPPING_SUBJECT_NAME, RECIPIENT_NAME, 1);
    if (ctx == NULL) {
        PRINTF("failed to initialize p10 context\n");
        return ret;
    }
    if ((ret = cmp_client_set_http(ctx, SERVER_HOST, TOSTRING(SERVER_PORT),
                                   SERVER_PATH_CR, TLS_CLIENT_KEY,
                                   TLS_CLIENT_CERT, TLS_SERVER_ROOT)) != 0) {
        goto end;
    }
    mbedtls_pk_context* protkey = mbedtls_calloc(1, sizeof(mbedtls_pk_context));
    if (protkey == NULL) {
        CMPERRS("Out of memory\n");
        goto end;
    }
    if ((ret =  parse_key_from_pem(protkey, PATH_TO_PROTECTION_KEY, ctr_drbg)) < 0) {
        goto end;
    }
    if ((ret = cmp_client_enable_signature_protection(ctx, SIG_PROT_MD_ALG,
                                                      protkey, PATH_TO_PROTECTION_CERT,
                                                      PATH_TO_PROTECTION_CHAIN,
                                                      PATH_TO_PROTECTION_TRUST_ANCHOR_PEM,
                                                      PATH_TO_PROTECTION_CRLS)) < 0) {
        goto end;
    };
    if ((ret = read_file(&p10, PATH_TO_VENDOR_P10_DER))<0) {
        goto end;
    }
    p10_len = ret;
    if ((ret = cmp_client_enroll_p10(ctx, p10, p10_len,
                                     PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM,
                                     PATH_TO_ENROLLMENT_CRLS,
                                     implicit_confirm,
                                     PATH_TO_OPERATIONAL_CERT_PEM,
                                     PATH_TO_OPERATIONAL_CHAIN_PEM)) < 0) {
        goto end;
    };
    ret = 0;
    end:
    mbedtls_free(p10);
    cmp_client_free(ctx);
    return ret;
}


void usage(char *argv[])
{
    PRINTF("Usage: %s [-i][-c][-k][-p]\n", argv[0]);
}

int main(int argc, char *argv[])
{
    if (argc <= 1) {
        usage(argv);
        return -1;
    }
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        PRINTF("Failed to initialize PSA Crypto implementation: %d\n",
               (int) status);
        return -1;
    }

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    /**
     * init pseudorandom generator
     */
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    int ret = 0;
    const char *pers = "cmp_client";
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        PRINTF(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto end;
    }
    int opt;
    while ((opt = getopt(argc, argv, "icpk")) != -1) {
        switch (opt) {
            case 'i':
                ret = run_enroll(MBEDTLS_CMP_PKIBODY_IR, SERVER_PATH_IR,
                                 IMPRINTING_SUBJECT_NAME,
                                 NULL, NULL, NULL,
                                 PATH_TO_VENDOR_KEY_PEM,
                                 PATH_TO_VENDOR_CERT_PEM,
                                 PATH_TO_VENDOR_CHAIN_PEM,
                                 &ctr_drbg);
                break;
            case 'c':
                ret = run_enroll(MBEDTLS_CMP_PKIBODY_CR, SERVER_PATH_CR,
                                 BOOTSTRAPPING_SUBJECT_NAME,
                                 PATH_TO_PROTECTION_KEY,
                                 PATH_TO_PROTECTION_CERT,
                                 PATH_TO_PROTECTION_CHAIN,
                                 PATH_TO_OPERATIONAL_KEY_PEM,
                                 PATH_TO_OPERATIONAL_CERT_PEM,
                                 PATH_TO_OPERATIONAL_CHAIN_PEM,
                                 &ctr_drbg);
                break;
            case 'p':
                if ((ret = run_p10(&ctr_drbg)) != 0) {
                    goto end;
                }
                break;
            case 'k':
                ret = run_enroll(MBEDTLS_CMP_PKIBODY_KUR, SERVER_PATH_KUR,
                                 BOOTSTRAPPING_SUBJECT_NAME,
                                 PATH_TO_OPERATIONAL_KEY_PEM,
                                 PATH_TO_OPERATIONAL_CERT_PEM,
                                 PATH_TO_OPERATIONAL_CHAIN_PEM,
                                 PATH_TO_OPERATIONAL_KEY_PEM,
                                 PATH_TO_OPERATIONAL_CERT_PEM,
                                 PATH_TO_OPERATIONAL_CHAIN_PEM,
                                 &ctr_drbg);
                break;
            default:
                usage(argv);
                goto end;
        }
        if (ret != 0) {
            goto end;
        }
    }
end:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_psa_crypto_free();
    return ret;
}
