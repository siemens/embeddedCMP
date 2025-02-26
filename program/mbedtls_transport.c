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
#include "mbedtls/platform.h"
#include "mbedtls/error.h"
#include "mbedtls/ssl.h"
#include "mbedtls/debug.h"
#include "cmpclient_config.h"
#include "cmpcl.h"
#include "credential_storage.h"
#include "debug_macros.h"

/*******************************************************************************
 * Variables
 ******************************************************************************/

#define NEWLINE "\r\n"

#define INPUT_BUF_SIZE 8000
static unsigned char input_buf[INPUT_BUF_SIZE];

static void mbed_tls_debug(void *ctx, int level, const char *file, int line,
                           const char *str)
{
    ((void) level);
    PRINTF("%s(%d):%s", file, line, str);
}


int mbed_tls_transport_init(mbed_tls_transport_ctx *ctx, mbedtls_ctr_drbg_context *ctr_drbg)
{
    /*
     * Initialize the RNG and the session data
     */
    int ret = 1;
    memset(ctx, 0, sizeof(mbed_tls_transport_ctx));
    mbedtls_net_init(&ctx->server_fd);
    mbedtls_ssl_init(&ctx->ssl);
    mbedtls_ssl_config_init(&ctx->conf);
    mbedtls_x509_crt_init(&ctx->trustedserverroots);
    mbedtls_pk_init(&ctx->ownpkey);
    mbedtls_x509_crt_init(&ctx->owncert);

    /*
     * Load the certificates and private RSA key
     */

    ret = append_certs_from_pem(&ctx->trustedserverroots, TLS_SERVER_ROOT);
    if (ret != 0) {
        PRINTF("\r\n error parsing TLS server certificate from %s:%d\r\n",
               TLS_SERVER_ROOT, ret);
        return -1;
    }

    ret = append_certs_from_pem(&ctx->owncert, TLS_CLIENT_CERT);
    if (ret != 0) {
        PRINTF("\r\n error parsing own TLS chain from %s:%d\r\n",
               TLS_CLIENT_CERT, ret);
        return -1;
    }

    ret = parse_key_from_pem(&ctx->ownpkey, TLS_CLIENT_KEY, ctr_drbg);
    if (ret != 0) {
        PRINTF("\r\n error parsing own TLS key from %s:%d\r\n",
               TLS_CLIENT_KEY, ret);
        return -1;
    }

    /*
     * Setting up the SSL data.
     */
    if ((ret = mbedtls_ssl_config_defaults(&ctx->conf, MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        PRINTF(" failed\r\n  ! mbedtls_ssl_config_defaults returned %d\r\n\r\n",
               ret);
        return -1;
    }

    mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, ctr_drbg);
    mbedtls_ssl_conf_dbg(&ctx->conf, mbed_tls_debug, NULL);
    mbedtls_ssl_conf_renegotiation(&ctx->conf, MBEDTLS_SSL_RENEGOTIATION_ENABLED);
    // mbedtls_debug_set_threshold(3);
    mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->trustedserverroots, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->owncert, &ctx->ownpkey)) != 0) {
        PRINTF(" failed\r\n  ! mbedtls_ssl_conf_own_cert returned %s\r\n\r\n",
               mbedtls_high_level_strerr(ret));
        return -1;
    }

    if ((ret = mbedtls_ssl_setup(&ctx->ssl, &ctx->conf)) != 0) {
        PRINTF(" failed\r\n  ! mbedtls_ssl_setup returned %s\r\n\r\n",
               mbedtls_high_level_strerr(ret));
        return -1;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ctx->ssl, SNI_HOSTNAME)) != 0) {
        PRINTF(" failed\n  ! mbedtls_ssl_set_hostname returned %s\n\n",
               mbedtls_high_level_strerr(ret));
        return -1;
    }
    mbedtls_ssl_set_bio(&ctx->ssl, &ctx->server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    return 0;
}

static int write_all(mbedtls_ssl_context *ssl, const unsigned char *buf,
                     size_t len)
{
    do {
        int ret = mbedtls_ssl_write(ssl, buf, len);
        switch (ret) {
            case MBEDTLS_ERR_SSL_WANT_READ:
            case MBEDTLS_ERR_SSL_WANT_WRITE:
            case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
            case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
            case MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET:
                continue;
        }
        if (ret < 0) {
            PRINTF("failed\n  ! mbedtls_ssl_write returned %s\n\n", mbedtls_high_level_strerr(ret));
            return -1;
        }
        buf += ret;
        len -= ret;
    } while (len > 0);
    return 0;
}


int mbed_tls_send_receive(void *cb_context, const unsigned char *outbuf,
                          const size_t outlen, unsigned char **inbuf, size_t *inlen)
{
    mbed_tls_transport_ctx *ctx = (mbed_tls_transport_ctx *) cb_context;
    *inbuf = NULL;
    *inlen = 0;
    int ret = 1;
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
    if ((ret = mbedtls_net_connect(&ctx->server_fd,
                                   SERVER_HOST, TOSTRING(SERVER_PORT),
                                   MBEDTLS_NET_PROTO_TCP)) != 0) {
        PRINTF(" failed\n  ! mbedtls_net_connect returned -0x%x\n\n",
               (unsigned int) -ret);
        return -1;
    }
#undef STRINGIFY
#undef TOSTRING
    mbedtls_ssl_session_reset(&ctx->ssl);
    while ((ret = mbedtls_ssl_handshake(&ctx->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            PRINTF(" failed\n  ! mbedtls_ssl_handshake returned %s\n\n",
                   mbedtls_high_level_strerr(ret));
            return -1;
        }
    }
    /*
     * Verify the server certificate
     */
    uint32_t flags;
    if ((flags = mbedtls_ssl_get_verify_result(&ctx->ssl)) != 0) {
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        PRINTF("%s\n", vrfy_buf);
        return -1;
    }
    /*
     * Write the POST request header
     */
    char header[200];
    sprintf(header,
            "POST %s%s HTTP/1.1" NEWLINE
            "Host: %s" NEWLINE
            "Content-Type: application/pkixcmp" NEWLINE
            "Connection: close" NEWLINE
            "Content-Length: %ld" NEWLINE NEWLINE,
            //
            *SERVER_PATH != '/' ? "/" : "", SERVER_PATH, SERVER_HOST, outlen);
    if (write_all(&ctx->ssl, (unsigned char *) header, strlen(header)) < 0) {
        return -1;
    }
    /*
     * Write the POST request body
     */
    if (write_all(&ctx->ssl, outbuf, outlen) < 0) {
        return -1;
    }
    /*
     * Read the HTTP response
     */
    int read_len = 0;
    do {
        memset(input_buf+read_len, 0, sizeof(input_buf)-read_len);
        ret = mbedtls_ssl_read(&ctx->ssl, input_buf+read_len, INPUT_BUF_SIZE - (read_len+1));
        switch (ret) {
            case MBEDTLS_ERR_SSL_WANT_READ:
            case MBEDTLS_ERR_SSL_WANT_WRITE:
            case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
            case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
            case MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET:
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                continue;
        }
        if (ret < 0) {
            PRINTF("failed\n  ! mbedtls_ssl_read returned %s\n\n", mbedtls_high_level_strerr(ret));
            return -1;
        }
        if (ret == 0) {
            PRINTF("\n\nEOF\n\n");
            break;
        }
        read_len += ret;
    } while (1);
    do {
        ret = mbedtls_ssl_close_notify(&ctx->ssl);
        switch (ret) {
            case MBEDTLS_ERR_SSL_WANT_READ:
            case MBEDTLS_ERR_SSL_WANT_WRITE:
            case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
            case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
            case MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET:
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                continue;
        }
        if (ret < 0) {
            PRINTF("failed\n  ! mbedtls_ssl_close_notify returned %s\n\n",
                   mbedtls_high_level_strerr(ret));
            return -1;
        }
        break;
    } while (1);
    mbedtls_net_close(&ctx->server_fd);
    /*
     * Parse the HTTP response
     */
    unsigned char *header_end = (unsigned char *) strstr((const char *) input_buf, NEWLINE NEWLINE);
    if (header_end == NULL) {
        PRINTF("no valid HTTP response");
        return -1;
    }
    header_end += strlen(NEWLINE NEWLINE);
    *inlen = read_len-(header_end-input_buf);
    *inbuf = header_end;
    return 0;
}


int mbed_tls_transport_free(mbed_tls_transport_ctx *ctx)
{
    mbedtls_net_free(&ctx->server_fd);
    mbedtls_x509_crt_free(&ctx->trustedserverroots);
    mbedtls_x509_crt_free(&ctx->owncert);
    mbedtls_pk_free(&ctx->ownpkey);
    mbedtls_ssl_free(&ctx->ssl);
    mbedtls_ssl_config_free(&ctx->conf);

    return 0;
}
