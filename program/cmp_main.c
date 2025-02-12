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
#include "mbedtls_transport.h"
#include "cmpclient.h"
#include "debug_macros.h"



int main(int argc, char *argv[])
{
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        PRINTF("Failed to initialize PSA Crypto implementation: %d\n",
               (int) status);
        return -1;
    }
    /**
     * init pseudorandom generator
     */
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    int ret = 0;
    const char *pers = "cmp_client";
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        PRINTF(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto end;
    }

    /*
     * init mbedtls transport
     */
    mbed_tls_transport_ctx ctx;
    if ((ret = mbed_tls_transport_init(&ctx, &ctr_drbg)) != 0) {
        PRINTF("failed to initialize transport context");
        mbed_tls_transport_free(&ctx);
        goto end;
    }
    /*
     * call invoke_ir_transaction
     */
    if ((ret = invoke_ir_transaction(mbed_tls_send_receive, (void *) &ctx, &ctr_drbg)) != 0) {
        PRINTF("failed to execute transaction");
        mbed_tls_transport_free(&ctx);
        goto end;
    }
    /*
     * TODO call invoke_cr_transaction, invoke_kur_transaction
     */
end:
    mbed_tls_transport_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_psa_crypto_free();
    return ret;
}
