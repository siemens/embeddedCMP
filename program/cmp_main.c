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
#include "mbedtls_transport.h"
#include "cmpclient.h"
#include "cmpclient_config.h"
#include "debug_macros.h"

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

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
        PRINTF("failed to initialize transport context");
        mbed_tls_transport_free(&ctx);
        return ret;
    }

    if ((ret = invoke_ir_transaction(mbed_tls_send_receive, (void *) &ctx, ctr_drbg)) != 0) {
        PRINTF("failed to execute transaction");
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
        PRINTF("failed to initialize transport context");
        mbed_tls_transport_free(&ctx);
        return ret;
    }
    /*
     * call invoke_cr_transaction
     */
    if ((ret = invoke_cr_transaction(mbed_tls_send_receive, (void *) &ctx, ctr_drbg)) != 0) {
        PRINTF("failed to execute transaction");
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
        PRINTF("failed to initialize transport context");
        mbed_tls_transport_free(&ctx);
        return ret;
    }
    if ((ret = invoke_kur_transaction(mbed_tls_send_receive, (void *) &ctx, ctr_drbg)) != 0) {
        PRINTF("failed to execute transaction");
        mbed_tls_transport_free(&ctx);
        return ret;
    }
    mbed_tls_transport_free(&ctx);
    return ret;
}

void usage(char *argv[])
{
    PRINTF("Usage: %s [-i][-c][-k]\n", argv[0]);
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
    while ((opt = getopt(argc, argv, "ick")) != -1) {
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
