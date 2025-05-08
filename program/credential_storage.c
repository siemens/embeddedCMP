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

#include "credential_storage.h"

#include "cmpcl.h"
#include "debug_macros.h"
#include "mbedtls/pem.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>

/* **************************************************************** */

#define MAX_FILE_SIZE 8000

static unsigned char content_buffer[MAX_FILE_SIZE];

/* Read file to (binary) string */
static int read_file(unsigned char **contents, const char *filename)
{
    *contents = NULL;
    struct stat statbuf;
    int error = stat(filename, &statbuf);
    if (error) {
        CMPERRV("stat of %s failed: %s\r\n", filename,
                strerror(errno));
        return -1;
    }
    if (statbuf.st_size >= MAX_FILE_SIZE) {
        CMPERRV("file %s too large for loading, len= " SIZEFMT "\r\n",
                filename, statbuf.st_size);
        return -1;
    }
    FILE *fileObject = fopen(filename, "r");
    if (fileObject == NULL) {
        CMPERRV("fopen of %s failed: %s\r\n", filename,
                strerror(errno));
        return -1;
    }
    size_t readBytes = fread(content_buffer, 1, statbuf.st_size, fileObject);
    if (readBytes != statbuf.st_size) {
        CMPERRV("wrong f_read of %s: " SIZEFMT " != " SIZEFMT "\r\n", filename,
                readBytes,  statbuf.st_size);
        return -1;
    }
    error = fclose(fileObject);
    if (error) {
        CMPERRV("f_close of %s failed: %s\r\n", filename,
                strerror(errno));
        return -1;
    }
    // always terminate loaded string
    content_buffer[readBytes] = '\0';
    *contents = content_buffer;
    return readBytes;
}

static int write_file(unsigned char *content, size_t len, const char *filename,
                      int append)
{

    FILE *fileObject = fopen(filename, append ? "a" : "w");
    if (fileObject == NULL) {
        CMPERRV("fopen of %s failed: %s\r\n", filename,
                strerror(errno));
        return -1;
    }
    size_t writtenBytes = fwrite(content, 1, len, fileObject);
    if (len != writtenBytes) {
        CMPERRV("====ERROR==== wrong f_read of %s: " SIZEFMT " != " SIZEFMT " \r\n", filename,
                writtenBytes,  len);
        return -1;
    }
    int error = fclose(fileObject);
    if (error) {
        CMPERRV("f_close of %s failed: %s\r\n", filename,
                strerror(errno));
        return -1;
    }
    return len;

}

/* **************************************************************** */
/* Parse certificates from a file */
int append_certs_from_pem(mbedtls_x509_crt *crt, const char *path_to_pem)
{
    int ret = 0, len = 0;
    unsigned char *pem_str = NULL;
    len = read_file(&pem_str, path_to_pem);
    if (len < 0) {
        CMPERRV("Loading certs from %s FAILED", path_to_pem);
        return FILE_ERR_FILE_READ;
    }

    if (len == 0) {
        CMPDBGV("Empty certs file %s", path_to_pem);
    } else {
        ret = mbedtls_x509_crt_parse(crt, pem_str, len + 1);
    }
    if (ret != 0) {
        CMPERRV("parsing certs FAILED - mbedtls_x509_crt_parse returned -0x%04x",
                -ret);
    }
    return ret;
}

/* **************************************************************** */
/* Parse CRLs from a file */
int append_crls_from_pem(mbedtls_x509_crl *crl, const char *path_to_pem)
{
    int ret = 0, len = 0;
    unsigned char *pem_str = NULL;
    len = read_file(&pem_str, path_to_pem);
    if (len < 0) {
        CMPERRV("Loading CRLs from %s FAILED", path_to_pem);
        return FILE_ERR_FILE_READ;
    }

    if (len == 0) {
        CMPDBGV("Empty CRLs file %s", path_to_pem);
    } else {
        ret = mbedtls_x509_crl_parse(crl, pem_str, len + 1);
    }
    if (ret != 0) {
        CMPERRV("parsing CRLs FAILED - mbedtls_x509_crl_parse returned -0x%04x",
                -ret);
    }
    return ret;
}

/* **************************************************************** */
/* Parse a private key without password */
int parse_key_from_pem(mbedtls_pk_context *pk_ctx,
                       const char *path_to_pem,
                       mbedtls_ctr_drbg_context *ctr_drbg)
{
    unsigned char *pem_str = NULL;
    mbedtls_pk_init(pk_ctx);
    int len = read_file(&pem_str, path_to_pem);
    if (len <= 0) {
        CMPERRV("Loading KEY from %s FAILED", path_to_pem);
        return FILE_ERR_FILE_READ;
    }
    int ret = mbedtls_pk_parse_key(pk_ctx,
                                   pem_str,
                                   len + 1,
                                   NULL,
                                   0);
    if (ret != 0) {
        CMPERRV("parsing key FAILED - mbedtls_pk_parse_key returned -0x%04x",
                -ret);
    }
    return ret;
}

/* **************************************************************** */

int write_private_key_pem(mbedtls_pk_context *key, const char *output_file)
{

    int ret = mbedtls_pk_write_key_pem(key, content_buffer, MAX_FILE_SIZE - 1);
    if (ret != 0) {
        CMPDBGV(
            "Writing key to pem FAILED, mbedtls_pk_write_key_pem() returned %d",
            ret);
        return ret;
    }
    content_buffer[MAX_FILE_SIZE - 1] = '\0';
    if (write_file(content_buffer, strlen((char *) content_buffer), output_file,
                   0) <= 0) {
        CMPERRV("Writing key to pem FAILED\n %s", output_file);
        return -1;
    }
    CMPINFOV("Private key written to %s", output_file);
    return 0;
}

/* **************************************************************** */

int write_cert_pem(mbedtls_x509_crt *cert, const char *output_file)
{

    int i = 0;
    while (cert) {
        size_t olen = 0;
        int ret;
        if ((ret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n",
                                            "-----END CERTIFICATE-----\n", cert->raw.p,
                                            cert->raw.len,
                                            content_buffer, MAX_FILE_SIZE, &olen)) != 0) {
            CMPDBGV(
                "Writing certificate to pem FAILED, mbedtls_pem_write_buffer() returned %d",
                ret);
            return ret;
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
