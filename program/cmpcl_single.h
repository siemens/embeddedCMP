/*
 *  Copyright (c) 2019 Siemens AG
 * *
 *  Licensed under the Apache License, Version 2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  cmpclient.h
 *
 *  Created on: 05.03.2019
 *      Author: Christian Epple
 */

#ifndef CMPCLIENT_H_
#define CMPCLIENT_H_

/* **************************************************************** */
/* Define */
/* **************************************************************** */
#define MAX_NAME_LENGTH 300 /* arbitrarily chosen; TODO: replace */

/* **************************************************************** */
/* Include */
/* **************************************************************** */

#include "cmpcl_low.h" /* TODO remove after switching to use of high-level API */
#include "cmpcl_high.h"

int invoke_cert_request(const int body_type,
                        const char *ecc_curve,
                        const char *subject_name,
                        OPTIONAL const unsigned char *exts, size_t exts_len,
                        int popo_method, int popo_md_alg,
                        OPTIONAL const unsigned char *p10, size_t p10_len,
                        OPTIONAL const char *sender_name,
                        OPTIONAL const char *recipient_name,
                        OPTIONAL const char *reference,
                        OPTIONAL const char *pbm_secret,
                        void *cb_context,
                        cmp_send_receive_cb send_receive_func,
                        mbedtls_ctr_drbg_context *ctr_drbg,
                        mbedtls_md_type_t owf, mbedtls_md_type_t mac,
                        int prot_md_alg,
                        OPTIONAL const char *path_to_protection_cert,
                        OPTIONAL const char *path_to_protection_key,
                        OPTIONAL const char *path_to_protection_chain,
                        OPTIONAL const char *path_to_protection_trust_anchor,
                        OPTIONAL const char *path_to_protection_crls,
                        OPTIONAL const char *path_to_enrollment_trust_anchor,
                        OPTIONAL const char *path_to_enrollment_crls,
                        const char *path_to_new_cert,
                        const char *path_to_new_key,
                        const char *path_to_new_chain);

#endif
