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
} mbed_tls_transport_ctx;

/**
 * \brief           Initialize a TLS context to default values
 *                  Must not be have content
 *
 * \param ctx       mbed_tls_transport_ctx context to initialise
 * \param ctr_drbg pseudorandom context to use
 */

int mbed_tls_transport_init(mbed_tls_transport_ctx *ctx, mbedtls_ctr_drbg_context *ctr_drbg);

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
