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
#include "file_helpers.h"
#include "cmpclient_config.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/debug.h"

#include "httpd_mbedtls.h"

/* MBED TLS server configuration */
#define TLS_CREDENTIAL_ROOT "tlssrv/"
#define TLS_SERVER_CRT TLS_CREDENTIAL_ROOT "srvcrt.crt"
#define TLS_SERVER_KEY TLS_CREDENTIAL_ROOT "srvkey.key"
#define TLS_SERVER_CHAIN TLS_CREDENTIAL_ROOT "srvchain.crt"
/*******************************************************************************
 * Variables
 ******************************************************************************/
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
#if CMP_CLIENT_HTTPD
static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_x509_crt srvcert;
static mbedtls_pk_context pkey;
#endif

const char *pers = "ssl_server";

int mbedtls_init_entropy() {

    int ret = -1;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if( ( ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
            (const unsigned char *) pers, strlen(pers)) ) != 0) {
        PRINTF(" FAIL! mbedtls_ctr_drbg_seed returned : 0x04x", -ret);
        return -1;
    }
    return 0;
}

#if CMP_CLIENT_HTTPD
static void mbed_tls_debug(void *ctx, int level, const char *file, int line,
        const char *str) {
    ((void) level);
    PRINTF("%s(%d):%s", file, line, str);
    // PRINTF("\r\n%s, at line %d in file %s\n", str, line, file);
}

int setup_httpd_tls() {
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    static mbedtls_ssl_cache_context cache;
    mbedtls_ssl_cache_init(&cache);
#endif
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(0);
#endif
    /*
     * 1. Load the certificates and private RSA key
     */

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */

    int ret = append_certs_from_pem(&srvcert, TLS_SERVER_CRT);
    if (ret != 0) {
        PRINTF("\r\n error parsing TLS server certificate from %s:%d\r\n",
        TLS_SERVER_CRT, ret);
        return -1;
    }

    ret = append_certs_from_pem(&srvcert, TLS_SERVER_CHAIN);
    if (ret != 0) {
        PRINTF("\r\n error parsing TLS server chain from %s:%d\r\n",
        TLS_SERVER_CHAIN, ret);
        return -1;
    }

    ret = parse_key_from_pem(&pkey, TLS_SERVER_KEY);
    if (ret != 0) {
        PRINTF("\r\n error parsing TLS server key from %s:%d\r\n",
        TLS_SERVER_KEY, ret);
        return -1;
    }

    /*
     * 2. Seeding the random number generator
     * already done in nxp_main.c
     */

    /*
     * 3. Setting up the SSL data.
     */
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
    MBEDTLS_SSL_TRANSPORT_STREAM,
    MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        PRINTF(" failed\r\n  ! mbedtls_ssl_config_defaults returned %d\r\n\r\n",
                ret);
        return -1;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, mbed_tls_debug, NULL);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(&conf, &cache, mbedtls_ssl_cache_get,
            mbedtls_ssl_cache_set);
#endif
    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
        PRINTF(" failed\r\n  ! mbedtls_ssl_conf_own_cert returned %d\r\n\r\n",
                ret);
        return -1;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        PRINTF(" failed\r\n  ! mbedtls_ssl_setup returned %d\r\n\r\n", ret);
        return -1;
    }
    httpd_mbedtls_init(&ssl);
    PRINTF("\r\nMBEDTLS HTTP server initialized.\r\n");
    return 0;
}
#endif
