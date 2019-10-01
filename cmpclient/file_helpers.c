/*
 *  Copyright (c) 2019 Siemens AG
 * *
 *  Licensed under the Apache License, Version 2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 * file_helpers.c
 *
 *  Created on: 22.11.2018
 *      Author: z0039e0m
 */

#include "file_helpers.h"
#include "cmpcl.h"
#include "pem.h"
#include <stdlib.h>
#include "ff.h"

/* **************************************************************** */

#define MAX_FILE_SIZE 8000

static unsigned char content_buffer[MAX_FILE_SIZE];

/* Read file to (binary) string */
static int read_file(unsigned char **contents, const char *filename) {
	*contents = NULL;
//	CMPDBGV("try to load from file %s, ", filename);
	FILINFO fno;
	FRESULT error = f_stat(_T(filename), &fno);
	if (error) {
		CMPERRV("====ERROR==== f_stat of %s failed: %d\r\n", filename,
				(int) error);
		return -1;
	}
	if (fno.fsize >= MAX_FILE_SIZE) {
		CMPERRV("====ERROR==== file %s too large for loading, len= %d\r\n",
				filename, (int) fno.fsize);
		return -1;
	}
	FIL fat_fileObject;
	error = f_open(&fat_fileObject, _T(filename), (FA_READ));
	if (error) {
		CMPERRV("====ERROR==== f_open of %s failed: %d\r\n", filename,
				(int) error);
		return -1;
	}
	UINT br;
	error = f_read(&fat_fileObject, (void*) content_buffer, fno.fsize, &br);
	if (error) {
		CMPERRV("====ERROR==== f_read of %s failed: %d\r\n", filename,
				(int) error);
		return -1;
	}
	if (fno.fsize != br) {
		CMPERRV("====ERROR==== wrong f_read of %s: %d != %d \r\n", filename,
				(int) br, (int) fno.fsize);
		return -1;
	}
	error = f_close(&fat_fileObject);
	if (error) {
		CMPERRV("====ERROR==== f_close of %s failed: %d\r\n", filename,
				(int) error);
		return -1;
	}
	// always terminate loaded string
	content_buffer[br] = '\0';
	*contents = content_buffer;
//	CMPDBGV("%d bytes loaded\r\n", (int) br);
	return br;
}

static int write_file(unsigned char *content, size_t len, const char *filename,
		int append) {
//	CMPDBGV("try to write to file %s, ", filename);
	FIL fat_fileObject;
	FRESULT error = f_open(&fat_fileObject, _T(filename),
			(FA_WRITE | (append ? FA_OPEN_APPEND : FA_CREATE_ALWAYS)));
	if (error) {
		CMPERRV("====ERROR==== f_open of %s failed: %d\r\n", filename,
				(int) error);
		return -1;
	}
	UINT bw;
	error = f_write(&fat_fileObject, (void*) content, len, &bw);
	if (len != bw) {
		CMPERRV("====ERROR==== wrong f_read of %s: %d != %d \r\n", filename,
				(int) bw, (int) len);
		return -1;
	}
	error = f_close(&fat_fileObject);
	if (error) {
		CMPERRV("====ERROR==== f_close of %s failed: %d\r\n", filename,
				(int) error);
		return -1;
	}
	return len;

}

/* **************************************************************** */
/* Parse certificates from a file */
int append_certs_from_pem(mbedtls_x509_crt *crt, const char *path_to_pem) {
	int ret = 0, len = 0;
	unsigned char *pem_str = NULL;
	len = read_file(&pem_str, path_to_pem);
	if (len < 0) {
		CMPERRV("Loading certs from %s FAILED", path_to_pem);
		return -1; /*TODO: improve error code */
	}

    if( len == 0) {
        CMPDBGV("Empty certs file %s", path_to_pem );
    } else {
        ret = mbedtls_x509_crt_parse(crt, pem_str, len + 1);
    }
	if (ret != 0)
		CMPERRV("parsing certs FAILED - mbedtls_x509_crt_parse returned -0x%04x",
				-ret);
	return (ret);
}

/* **************************************************************** */
/* Parse CRLs from a file */
int append_crls_from_pem(mbedtls_x509_crl *crl, const char *path_to_pem) {
    int ret = 0, len = 0;
    unsigned char *pem_str = NULL;
    len = read_file(&pem_str, path_to_pem);
    if (len < 0) {
        CMPERRV("Loading CRLs from %s FAILED", path_to_pem);
        return -1; /*TODO: improve error code */
    }

    if( len == 0) {
        CMPDBGV("Empty CRLs file %s", path_to_pem );
    } else {
        ret = mbedtls_x509_crl_parse(crl, pem_str, len + 1);
    }
    if (ret != 0)
        CMPERRV("parsing CRLs FAILED - mbedtls_x509_crl_parse returned -0x%04x",
                -ret);
    return (ret);
}

/* **************************************************************** */
/* Parse a private key without password */
int parse_key_from_pem(mbedtls_pk_context *pk_ctx, const char *path_to_pem) {
	unsigned char *pem_str = NULL;
	mbedtls_pk_init(pk_ctx);
	int len = read_file(&pem_str, path_to_pem);
	if (len <= 0) {
		CMPERRV("Loading KEY from %s FAILED", path_to_pem);
		return -1; /*TODO: improve error code */
	}
	int ret = mbedtls_pk_parse_key(pk_ctx, pem_str, len + 1, NULL, 0);
	if (ret != 0)
		CMPERRV("parsing key FAILED - mbedtls_pk_parse_key returned -0x%04x",
				-ret);
	return (ret);
}

/* **************************************************************** */

int write_private_key_pem(mbedtls_pk_context *key, const char *output_file) {

	int ret = mbedtls_pk_write_key_pem(key, content_buffer, MAX_FILE_SIZE - 1);
	if (ret != 0) {
		CMPDBGV(
				"Writing key to pem FAILED, mbedtls_pk_write_key_pem() returned %d",
				ret);
		return (ret);
	}
	content_buffer[MAX_FILE_SIZE - 1] = '\0';
	if (write_file(content_buffer, strlen((char*) content_buffer), output_file,
			0) <= 0) {
		CMPERRV("Writing key to pem FAILED\n %s", output_file);
		return -1;
	}
	CMPINFOV("Private key written to %s", output_file);
	return (0);
}

/* **************************************************************** */

int write_cert_pem(mbedtls_x509_crt* cert, const char *output_file) {

	int i = 0;
	while (cert) {
		size_t olen = 0;
		int ret;
		if ((ret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n",
				"-----END CERTIFICATE-----\n", cert->raw.p, cert->raw.len,
				content_buffer, MAX_FILE_SIZE, &olen)) != 0) {
			CMPDBGV(
					"Writing certificate to pem FAILED, mbedtls_pem_write_buffer() returned %d",
					ret);
			return (ret);
		}
		if (write_file(content_buffer, olen, output_file, i != 0) <= 0) {
			CMPERRV("Writing CERT to file FAILED\n %s", output_file);
			return -1;
		}
		i++;
		cert = cert->next;
	}
	CMPINFOV("%d certificate(s) written to %s", i, output_file);
	return 0;
}

