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
#include "cmpclient_config.h"
#include "cmpclient.h"
#include "cmpcl.h"

#include "ksdk_mbedtls.h"   /* needed for CRYPTO_InitHardware() */
#include "mbedtls_helper.h"
#include "lwip_helper.h"
#include "http_helper.h"
#include "coap_helper.h"

/*******************************************************************************
 * Variables
 ******************************************************************************/
#if !CMP_CLIENT_HTTPD
static const char usage_str_tr[] = "Enter request type (ir|cr|kur), default is kur : ";
static const char usage_str_pr[] = "Enter protocol     (http|coap), default is http: ";
#endif

/* ************************************************************************** */

#if !CMP_CLIENT_HTTPD
static void uart_cli_blocking( void ) {

    cmp_send_receive_cb send_receive_function = http_send_receive;
    invoke_transaction transaction = invoke_kur_transaction;
    uint8_t ch;

    PRINTF("*** CMP client demo CLI. Enter only the first character of chosen option. *** \r\n");

    PRINTF(usage_str_tr);
    ch = GETCHAR();
    PUTCHAR(ch);
    PRINTF("\r\n");

    if (!strncasecmp("ir", (char*) &ch, 1)) {
        transaction = invoke_ir_transaction;
    } else if (!strncasecmp("cr", (char*) &ch, 1)) {
        transaction = invoke_cr_transaction;
    } else if (!strncasecmp("kur", (char*) &ch, 1)) {
        transaction = invoke_kur_transaction;
    } else {
        PRINTF("Unrecognized type, using default (kur)\r\n");
    }

    PRINTF(usage_str_pr);
    ch = GETCHAR();
    PUTCHAR(ch);
    PRINTF("\r\n");

    if (!strncasecmp("http", (char*) &ch, 1)) {
        send_receive_function = http_send_receive;
    } else if (!strncasecmp("coap", (char*) &ch, 1)) {
        send_receive_function = coap_send_receive;
    } else {
        PRINTF("Unrecognized protocol, using default (http)\r\n");
    }

    if (send_receive_function != NULL && transaction != NULL) {
        transaction(send_receive_function);
    }
}
#endif

void httpd_cgi_handler(const char* uri, int iNumParams, char **pcParam,
        char **pcValue) {
    cmp_send_receive_cb send_receive_function = NULL;
    invoke_transaction transaction = NULL;
    for (int i = 0; i < iNumParams; i++) {
        if (!strcasecmp("cmd", pcParam[i])) {
            if (!strcasecmp("ir", pcValue[i])) {
                transaction = invoke_ir_transaction;
            } else if (!strcasecmp("cr", pcValue[i])) {
                transaction = invoke_cr_transaction;
            } else if (!strcasecmp("kur", pcValue[i])) {
                transaction = invoke_kur_transaction;
            }
        }
        if (!strcasecmp("prot", pcParam[i])) {
            if (!strcasecmp("http", pcValue[i])) {
                send_receive_function = http_send_receive;
            } else if (!strcasecmp("coap", pcValue[i])) {
                send_receive_function = coap_send_receive;
            }
        }
    }
    if (send_receive_function != NULL && transaction != NULL) {
        transaction(send_receive_function);
    }
}

int cmp_main(void) {
    int ret;

    /* init mbedTLS */
    CRYPTO_InitHardware();
    if( (ret = mbedtls_init_entropy() ) != 0 ) {
        PRINTF(" failed\r\n  ! mbedtls_ctr_drbg_seed returned %d\r\n", ret);
        return -1;
    }

    /* init lwip */
    setup_lwip();

#if CMP_CLIENT_HTTPD
    if (setup_httpd_tls() < 0) {
        return -1;
    }
#endif

    // LWIP loop
    PRINTF("Enter main processing loop.\r\n");
    while (1) {
        /* Poll the driver, get any outstanding frames */
        poll_lwip_driver();
#if !CMP_CLIENT_HTTPD
        uart_cli_blocking(); /* TODO: this is blocking; might break lwip */
#endif
    }
}
