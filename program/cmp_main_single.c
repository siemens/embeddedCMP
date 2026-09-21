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
#include "mbedtls/platform.h"
#include "mbedtls_transport.h"
#include "cmpcl_single.h"
#include "cmpclient_config.h"
#include "credential_storage.h"
#include "cmpcl_log.h"

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#define USE_PLAIN_HTTP (TLS_SERVER_ROOT == NULL)

//====================================================================================================
static
int invoke_kur_transaction(cmp_send_receive_cb send_receive_func,
                           void *cb_context,
                           mbedtls_ctr_drbg_context *ctr_drbg)
{

    int ret = -1;

    //CMPINFOV("### Starting KUR transaction ###");
    ret = invoke_cert_request(MBEDTLS_CMP_PKIBODY_KUR,
                              NULL,
                              NEW_KEY_ECCURVE,
                              NULL, 0,
                              POPO_METHOD, POPO_MD_ALG,
                              NULL, 0,
                              NULL,
                              NULL, // recipient_name
                              NULL,
                              NULL,
                              cb_context,
                              send_receive_func,
                              ctr_drbg,
                              PBM_OWF, PBM_MAC,
                              SIG_PROT_MD_ALG,
                              PATH_TO_OPERATIONAL_CERT_PEM,
                              PATH_TO_OPERATIONAL_KEY_PEM,
                              PATH_TO_OPERATIONAL_CHAIN_PEM,
                              PATH_TO_PROTECTION_TRUST_ANCHOR_PEM,
                              PATH_TO_PROTECTION_CRLS,
                              PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM,
                              PATH_TO_ENROLLMENT_CRLS,
                              PATH_TO_OPERATIONAL_CERT_PEM,
                              PATH_TO_OPERATIONAL_KEY_PEM,
                              PATH_TO_OPERATIONAL_CHAIN_PEM);

    if (ret != 0) {
        CMPERRV("### KUR transaction returned code %d ###\r\n", ret);
    }

    return ret;
}



//====================================================================================================
static
int invoke_cr_transaction(cmp_send_receive_cb send_receive_func,
                          void *cb_context,
                          mbedtls_ctr_drbg_context *ctr_drbg)
{

    int ret = -1;

    //CMPINFOV("### Starting CR transaction ###");
    ret = invoke_cert_request(MBEDTLS_CMP_PKIBODY_CR,
                              BOOTSTRAPPING_SUBJECT_NAME,
                              NEW_KEY_ECCURVE,
                              NULL, 0,
                              POPO_METHOD, POPO_MD_ALG,
                              NULL, 0,
                              NULL,
                              RECIPIENT_NAME, // recipient_name
                              NULL,
                              NULL,
                              cb_context,
                              send_receive_func,
                              ctr_drbg,
                              PBM_OWF, PBM_MAC,
                              SIG_PROT_MD_ALG,
                              PATH_TO_PROTECTION_CERT,
                              PATH_TO_PROTECTION_KEY,
                              PATH_TO_PROTECTION_CHAIN,
                              PATH_TO_PROTECTION_TRUST_ANCHOR_PEM,
                              PATH_TO_PROTECTION_CRLS,
                              PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM,
                              PATH_TO_ENROLLMENT_CRLS,
                              PATH_TO_OPERATIONAL_CERT_PEM,
                              PATH_TO_OPERATIONAL_KEY_PEM,
                              PATH_TO_OPERATIONAL_CHAIN_PEM);

    CMPDBGV("### CR transaction returned code %d ###\r\n", ret);

    return ret;
}

//====================================================================================================
static
int invoke_p10cr_transaction(cmp_send_receive_cb send_receive_func,
                             void *cb_context,
                             mbedtls_ctr_drbg_context *ctr_drbg)
{
    unsigned char *p10 = NULL;
    size_t p10_len = 0;
    int ret = -1;

    if ((ret = read_file(&p10, PATH_TO_VENDOR_P10_DER)) < 0) {
        CMPERRS("Failed to read P10 DER file");
        return ret;
    }
    p10_len = (size_t) ret;

    ret = invoke_cert_request(MBEDTLS_CMP_PKIBODY_P10CR,
                              NULL,              // subject_name: ignored for P10CR
                              NULL,              // ecc_curve: ignored for P10CR
                              NULL, 0,           // exts: ignored for P10CR
                              -1, -1,            // popo_method, popo_md_alg: ignored for P10CR
                              p10, p10_len,
                              NULL,
                              RECIPIENT_NAME,    // recipient_name
                              NULL,
                              NULL,
                              cb_context,
                              send_receive_func,
                              ctr_drbg,
                              PBM_OWF, PBM_MAC,
                              SIG_PROT_MD_ALG,
                              PATH_TO_PROTECTION_CERT,
                              PATH_TO_PROTECTION_KEY,
                              PATH_TO_PROTECTION_CHAIN,
                              PATH_TO_PROTECTION_TRUST_ANCHOR_PEM,
                              PATH_TO_PROTECTION_CRLS,
                              PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM,
                              PATH_TO_ENROLLMENT_CRLS,
                              PATH_TO_OPERATIONAL_CERT_PEM,
                              NULL,              // path_to_new_key: no key output for P10CR
                              PATH_TO_OPERATIONAL_CHAIN_PEM);

    CMPDBGV("### P10CR transaction returned code %d ###\r\n", ret);
    mbedtls_free(p10);
    return ret;
}

//====================================================================================================
static
int invoke_ir_transaction(cmp_send_receive_cb send_receive_func,
                          void *cb_context,
                          mbedtls_ctr_drbg_context *ctr_drbg)
{

    int ret = -1;

    //CMPINFOV("### Starting IR transaction ###");

    ret = invoke_cert_request(
        MBEDTLS_CMP_PKIBODY_IR,         // body_type,
        IMPRINTING_SUBJECT_NAME,        // subject_name,
        NEW_KEY_ECCURVE,
        NULL, 0,
        POPO_METHOD, POPO_MD_ALG,
        NULL, 0,
        IMPRINTING_SUBJECT_NAME,        // sender_name,
        RECIPIENT_NAME,                 // recipient_name
#ifdef PBM_KID                        // reference
        PBM_KID
#else
        NULL
#endif
        ,
#ifdef      PBM_SECRET
        PBM_SECRET
#else
        NULL
#endif
        ,                               // pbm_secret
        cb_context,
        send_receive_func,
        ctr_drbg,
        PBM_OWF, PBM_MAC,
        SIG_PROT_MD_ALG,
        NULL,                           // path_to_protecting_cert
        NULL,                           // path_to_protecting_key
        NULL,                           // path_to_protecting_chain
        PATH_TO_PROTECTION_TRUST_ANCHOR_PEM,
        PATH_TO_PROTECTION_CRLS,
        PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM,
        PATH_TO_ENROLLMENT_CRLS,
        PATH_TO_VENDOR_CERT_PEM,        // path_to_new_cert,
        PATH_TO_VENDOR_KEY_PEM,         // path_to_new_key
        PATH_TO_VENDOR_CHAIN_PEM);      // path_to_new_chain

    CMPDBGV("### IR transaction returned code %d ###\r\n", ret);

    return ret;
}

static int run_ir(mbedtls_ctr_drbg_context *ctr_drbg)
{
    /*
     * call invoke_ir_transaction
     */
    /*
     * init mbedtls transport
     */
    int ret = -1;
    mbed_tls_transport_ctx ctx;
    if ((ret =
             mbed_tls_transport_init(&ctx, USE_PLAIN_HTTP,  ctr_drbg, TLS_CLIENT_CERT,
                                     TLS_CLIENT_KEY,
                                     TLS_SERVER_ROOT,
                                     SERVER_HOST, TOSTRING(SERVER_PORT), SERVER_PATH_IR)) != 0) {
        PRINTF("failed to initialize ir transport context\n");
        mbed_tls_transport_free(&ctx);
        return ret;
    }

    if ((ret = invoke_ir_transaction(mbed_tls_send_receive, (void *) &ctx, ctr_drbg)) != 0) {
        PRINTF("failed to execute ir transaction\n");
        mbed_tls_transport_free(&ctx);
        return ret;
    }
    mbed_tls_transport_free(&ctx);
    return ret;
}


static int run_p10cr(mbedtls_ctr_drbg_context *ctr_drbg)
{
    mbed_tls_transport_ctx ctx;
    int ret = -1;
    if ((ret =
             mbed_tls_transport_init(&ctx, USE_PLAIN_HTTP, ctr_drbg, TLS_CLIENT_CERT,
                                     TLS_CLIENT_KEY,
                                     TLS_SERVER_ROOT,
                                     SERVER_HOST, TOSTRING(SERVER_PORT), SERVER_PATH_CR)) != 0) {
        PRINTF("failed to initialize p10cr transport context\n");
        mbed_tls_transport_free(&ctx);
        return ret;
    }
    if ((ret = invoke_p10cr_transaction(mbed_tls_send_receive, (void *) &ctx, ctr_drbg)) != 0) {
        PRINTF("failed to execute p10cr transaction\n");
        mbed_tls_transport_free(&ctx);
        return ret;
    }
    mbed_tls_transport_free(&ctx);
    return ret;
}

static int run_cr(mbedtls_ctr_drbg_context *ctr_drbg)
{
    mbed_tls_transport_ctx ctx;
    int ret = -1;
    if ((ret =
             mbed_tls_transport_init(&ctx, USE_PLAIN_HTTP, ctr_drbg, TLS_CLIENT_CERT,
                                     TLS_CLIENT_KEY,
                                     TLS_SERVER_ROOT,
                                     SERVER_HOST, TOSTRING(SERVER_PORT), SERVER_PATH_CR)) != 0) {
        PRINTF("failed to initialize cr transport context\n");
        mbed_tls_transport_free(&ctx);
        return ret;
    }
    /*
     * call invoke_cr_transaction
     */
    if ((ret = invoke_cr_transaction(mbed_tls_send_receive, (void *) &ctx, ctr_drbg)) != 0) {
        PRINTF("failed to execute cr transaction\n");
        mbed_tls_transport_free(&ctx);
        return ret;
    }
    mbed_tls_transport_free(&ctx);
    return ret;
}

static int run_kur(mbedtls_ctr_drbg_context *ctr_drbg)
{
    mbed_tls_transport_ctx ctx;
    int ret = -1;
    /*
     * invoke_kur_transaction
     */
    if ((ret =
             mbed_tls_transport_init(&ctx, USE_PLAIN_HTTP, ctr_drbg, TLS_CLIENT_CERT,
                                     TLS_CLIENT_KEY,
                                     TLS_SERVER_ROOT,
                                     SERVER_HOST, TOSTRING(SERVER_PORT), SERVER_PATH_KUR)) != 0) {
        PRINTF("failed to initialize kur transport context\n");
        mbed_tls_transport_free(&ctx);
        return ret;
    }
    if ((ret = invoke_kur_transaction(mbed_tls_send_receive, (void *) &ctx, ctr_drbg)) != 0) {
        PRINTF("failed to execute kur transaction\n");
        mbed_tls_transport_free(&ctx);
        return ret;
    }
    mbed_tls_transport_free(&ctx);
    return ret;
}

void usage(char *argv[])
{
    PRINTF("Usage: %s [-i][-c][-p][-k]\n", argv[0]);
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

//#ifndef EMBEDDEDCMP_DEBUG
    // Silence everything 
     //cmp_silence_log();
     //CMPERRS("This goes nowhere");
//#endif

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
                if ((ret = run_ir(&ctr_drbg)) != 0) {
                    goto end;
                }
                break;
            case 'c':
                if ((ret = run_cr(&ctr_drbg)) != 0) {
                    goto end;
                }
                break;
            case 'p':
                if ((ret = run_p10cr(&ctr_drbg)) != 0) {
                    goto end;
                }
                break;
            case 'k':
                if ((ret = run_kur(&ctr_drbg)) != 0) {
                    goto end;
                }
                break;
            default:
                usage(argv);
                goto end;
        }
    }
end:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_psa_crypto_free();
    return ret;
}
