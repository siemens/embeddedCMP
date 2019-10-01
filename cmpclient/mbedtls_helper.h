/*
 *  Copyright (c) 2019 Siemens AG
 * *
 *  Licensed under the Apache License, Version 2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  mbedtls_helper.h
 *
 *  Created on: 12.07.2019
 */

#ifndef MBEDTLS_HELPER_H_
#define MBEDTLS_HELPER_H_

int mbedtls_init_entropy(void);
#ifdef CMP_CLIENT_HTTPD
int setup_httpd_tls(void);
#endif

#endif
