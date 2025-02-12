/*
 *  Copyright (c) 2019 Siemens AG
 * *
 *  Licensed under the Apache License, Version 2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 * file_helpers.h
 *
 *  Created on: 22.11.2018
 *      Author: z0039e0m
 */

#ifndef CREDENTIAL_STORAGE_H_
#define CREDENTIAL_STORAGE_H_

#include "stdio.h"
#include "mbedtls/x509_crt.h"
#include "cmpcl.h"

int append_certs_from_pem(mbedtls_x509_crt *crt, const char *path_to_pem);

int append_crls_from_pem(mbedtls_x509_crl *crl, const char *path_to_pem);

int parse_key_from_pem(mbedtls_pk_context *pk_ctx,
                       const char *path_to_pem,
                       mbedtls_ctr_drbg_context *ctr_drbg);


int write_private_key_pem(mbedtls_pk_context *key, const char *output_file);

int write_cert_pem(mbedtls_x509_crt *cert, const char *output_file);

#define FILE_ERR_FILE_READ              -0x1001 /** ERROR in reading file  */

#endif /* FILE_HELPERS_H_ */
