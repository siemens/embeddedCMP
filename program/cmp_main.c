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
                      OPTIONAL const char *subject,
                      /* signature-based protection (NULL for PBM-only): */
                      OPTIONAL const char *prot_key_path,
                      OPTIONAL const char *prot_cert_path,
                      OPTIONAL const char *prot_chain_path,
                      /* P10CR: path to DER-encoded CSR, or NULL for IR/CR/KUR: */
                      OPTIONAL const char *p10_path,
                      /* output paths: */
                      OPTIONAL const char *out_key_path,
                      const char *out_cert_path,
                      const char *out_chain_path,
                      mbedtls_ctr_drbg_context *ctr_drbg)
{
    unsigned char *p10 = NULL;
    size_t p10_len = 0;
    int ret = -1;
    cmp_ctx *ctx = cmp_client_init(subject /* taken as sender name */, RECIPIENT_NAME, 1);
    if (ctx == NULL) {
        PRINTF("failed to initialize CMP context\n");
        return ret;
    }
    if ((ret = cmp_client_set_http(ctx, SERVER_HOST, TOSTRING(SERVER_PORT),
                                   server_path, TLS_SERVER_ROOT,
                                   TLS_CLIENT_KEY, TLS_CLIENT_CERT)) != 0) {
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
    if (p10_path != NULL) {
        if ((ret = read_file(&p10, p10_path)) < 0) {
            goto end;
        }
        p10_len = ret;
    }
    mbedtls_pk_context *newkey = NULL;
    if ((ret = cmp_client_enroll_cert(ctx, body_type,
                                      p10 != NULL ? NULL : subject,
                                      p10 != NULL ? NULL : NEW_KEY_ECCURVE,
                                      p10 != NULL ? NULL : &newkey,
                                      p10 != NULL ? NULL : out_key_path,
                                      POPO_MD_ALG,
                                      p10, p10_len,
                                      PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM,
                                      PATH_TO_ENROLLMENT_CRLS,
                                      implicit_confirm,
                                      out_cert_path, out_chain_path)) < 0) {
        goto end;
    }
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
                                 NULL, NULL, NULL, /* no signature-based protection used */
                                 NULL /* no p10 for IR */,
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
                                 NULL /* no p10 for CR */,
                                 PATH_TO_OPERATIONAL_KEY_PEM,
                                 PATH_TO_OPERATIONAL_CERT_PEM,
                                 PATH_TO_OPERATIONAL_CHAIN_PEM,
                                 &ctr_drbg);
                break;
            case 'p':
                ret = run_enroll(MBEDTLS_CMP_PKIBODY_P10CR, SERVER_PATH_CR,
                                 BOOTSTRAPPING_SUBJECT_NAME,
                                 PATH_TO_PROTECTION_KEY,
                                 PATH_TO_PROTECTION_CERT,
                                 PATH_TO_PROTECTION_CHAIN,
                                 PATH_TO_VENDOR_P10_DER,
                                 NULL /* no key output for P10CR */,
                                 PATH_TO_OPERATIONAL_CERT_PEM,
                                 PATH_TO_OPERATIONAL_CHAIN_PEM,
                                 &ctr_drbg);
                break;
            case 'k':
                ret = run_enroll(MBEDTLS_CMP_PKIBODY_KUR, SERVER_PATH_KUR,
                                 BOOTSTRAPPING_SUBJECT_NAME,
                                 PATH_TO_OPERATIONAL_KEY_PEM,
                                 PATH_TO_OPERATIONAL_CERT_PEM,
                                 PATH_TO_OPERATIONAL_CHAIN_PEM,
                                 NULL /* no p10 for KUR */,
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
