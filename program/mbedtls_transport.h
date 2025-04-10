/*
 *  Copyright (c) 2019 Siemens AG
 * *
 *  Licensed under the Apache License, Version 2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  mbedtls_transport.h
 *
 *  Created on: 12.07.2019
 */

#ifndef MBEDTLS_TRANSPORT_H_
#define MBEDTLS_TRANSPORT_H_

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/net_sockets.h"


typedef struct {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt trustedserverroots;
    mbedtls_x509_crt owncert;
    mbedtls_pk_context ownpkey;
    mbedtls_net_context server_fd;
    const char *server_fqdn;
    const char *server_port;
    const char *server_path;
    int use_plain_http; // no HTTPS, no TLS
} mbed_tls_transport_ctx;

/**
 * \brief           Initialize a TLS context
 *
 * \param ctx       mbed_tls_transport_ctx context to initialise
 * \param use_plain_http set to \c 1 if TLS layer should be bypassed
 * \param ctr_drbg pseudorandom context to use
 * \param path_to_client_cert path to TLS client certificate
 * \param path_to_client_Key path to TLS client private key
 * \param path_to_server_root path to servers trust root
 * \param server_fqdn TLS server hostname
 * \param server_port TLS server TCP port as string
 * \param server_path HTTP path to access
 */

int mbed_tls_transport_init(
    mbed_tls_transport_ctx *ctx,
    int use_plain_http,
    mbedtls_ctr_drbg_context *ctr_drbg,
    const char *path_to_client_cert,
    const char *path_to_client_Key,
    const char *path_to_server_root,
    const char *server_fqdn,
    const char *server_port,
    const char *server_path);

/**
 * \brief           Free the contents of a mbed_tls_transport_ctx context
 *
 * \param ctx       mbed_tls_transport_ctx context to free
 */

int mbed_tls_transport_free(mbed_tls_transport_ctx *ctx);

/**
 * \brief Transfer function
 * \para cb_context the mbed_tls_transport_ctx context
 * \para outbuf cmp request to send
 * \para outlen length of cmp request to send
 * \para inbuf received cmp response
 * \para inlen length of received cmp response
 */
int mbed_tls_send_receive(void *cb_context, const unsigned char *outbuf,
                          const size_t outlen, unsigned char **inbuf, size_t *inlen);

#endif
