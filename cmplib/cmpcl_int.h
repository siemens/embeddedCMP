/*
 *  Copyright (c) 2016-2017, Nokia, All rights reserved.
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

#define DEVELOPMENT

/* TODO: HARDCODED - that's not in mbedtls/include/mbedtls/oid.h */
#define PBM_OID "\x2a\x86\x48\x86\xf6\x7d\x07\x42\x0d"
#define IMPLICITCONFIRM_OID "\x2b\x06\x01\x05\x05\x07\x04\x0d"

#ifndef CMPCL_INT_H
#define CMPCL_INT_H
#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_free       free
#define mbedtls_calloc     calloc
#define mbedtls_snprintf   snprintf
#endif


/* for debugging of heap memory usage */
#if 0
# define HEAP_USAGE_DEBUG_MSG
# undef mbedtls_calloc
# define mbedtls_calloc(count, size) debug_calloc(count, size, __FILE__, __LINE__, __func__)
# undef mbedtls_free
# define mbedtls_free(ptr)	debug_free(ptr, __FILE__, __LINE__, __func__)
#endif

#include "cmpcl.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"

/* TODO: check this buffer size */
#define OUTPUT_BUF_SIZE 8000

/* **************************************************************** */
/* HELPERS */
/* **************************************************************** */
void cmp_asn1_sequence_free( mbedtls_asn1_sequence *asn1_sequence );
void cmp_asn1_bitstring_free( mbedtls_asn1_bitstring *asn1_bitstring);
int setStr( unsigned char **dst, const unsigned char *src, const size_t len);
char *strndup(const char *s, size_t n);
char *strdup(const char *src);
int write_to_file( char *output_file, const unsigned char *data, size_t len);

#ifdef HEAP_USAGE_DEBUG_MSG
static inline void *debug_calloc(size_t nmemb, size_t size, const char *file,
		int line, const char *func){

	int* loc;
	loc = (int*)calloc(nmemb, size);
	if( !loc ) {
		CMPERRS("Error allocating memory!");
	} else {
		PRINTF("MEM: ####alloc### at addr=0x%x size=%d in %s:%d %s\r\n", loc, size, file, line, func);
	}
	return (void *)loc;
}

static inline void debug_free(void *ptr, const char *file,
		int line, const char *func) {

	PRINTF("MEM: freed at addr=0x%x in %s:%d %s\r\n", ptr, file, line, func);
	free(ptr);
}
#endif

/* **************************************************************** */
/* PasswordBasedMac PBM */
/* **************************************************************** */
/**
 * \brief          calculate PBM
 *
 * \param pbmp      initialized PBMParameter
 * \param msg
 * \param msg_len
 * \param secret
 * \param secret_len
 * \param mac
 * \param mac_len
 */
int cmp_PBM_new(const cmp_PBMParameter *pbmp, const unsigned char *secret,
        size_t secret_len, const unsigned char *msg, size_t msg_len,
        unsigned char *mac, size_t *mac_len);

/* **************************************************************** */
/* CRMF */
/* **************************************************************** */

/*! Certificate Request Message Format (CRMF) (RFC 4211)
 * Container for writing a CertReqMsg
 *
 * RFC SECTION 3:  CertReqMsg
 *
 * CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
 *
 * CertReqMsg ::= SEQUENCE {
 *  certReq   CertRequest,
 *  popo      ProofOfPossession                               OPTIONAL,
 *   -- content depends upon key type
 *  regInfo   SEQUENCE SIZE(1..MAX) of AttributeTypeAndValue  OPTIONAL
 *
 *
 * RFC4211 SECTION 5:  CertRequest
 *
 * CertRequest ::= SEQUENCE {
 *  certReqId        INTEGER,            -- ID for matching request and reply
 *  certTemplate     CertTemplate,       -- Selected fields of cert to be issued
 *  controls         Controls OPTIONAL } -- Attributes affecting issuance
 *
 * CertTemplate ::= SEQUENCE {
 *  version      [0] Version               OPTIONAL,
 *  serialNumber [1] INTEGER               OPTIONAL,
 *  signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
 *  issuer       [3] Name                  OPTIONAL,
 *  validity     [4] OptionalValidity      OPTIONAL,
 *  subject      [5] Name                  OPTIONAL,
 *  publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
 *  issuerUID    [7] UniqueIdentifier      OPTIONAL,
 *  subjectUID   [8] UniqueIdentifier      OPTIONAL,
 *  extensions   [9] Extensions            OPTIONAL }
 *
 *
 * RFC4211 SECTION 4: POP
 *
 * ProofOfPossession ::= CHOICE {
 *  raVerified        [0] NULL,
 *   -- used if the RA has already verified that the requester is in
 *   -- possession of the private key
 *  signature         [1] POPOSigningKey,
 *  keyEncipherment   [2] POPOPrivKey,
 *  keyAgreement      [3] POPOPrivKey }
 *
 * RFC4211 SECTION 4.1: Signature Key POP
 *
 * POPOSigningKey ::= SEQUENCE {
 *  poposkInput         [0] POPOSigningKeyInput OPTIONAL,
 *  algorithmIdentifier     AlgorithmIdentifier,
 *  signature               BIT STRING }
 *
 *
 */

/**
 * \brief           Write a built up CertReqMsg to a DER structure
 */
int cmpcl_CRMFwrite_CertReqMsg_der(unsigned char **p, unsigned char *start,
        cmp_ctx *ctx);

/**
 * \brief           Write a built up CertRequest to a DER structure
 */
int cmpcl_CRMFwrite_CertRequest_der(unsigned char **p, unsigned char *start,
        cmp_ctx *ctx);

/**
 * \brief           Write a built up CertConfirmContent to a DER structure
 */
int cmpcl_CMPwrite_CertConfCont_der(unsigned char **p, unsigned char *start,
        cmp_ctx *ctx);

/* **************************************************************** */
/* CMP */
/* **************************************************************** */

#define MBEDTLS_CMP_VERSION_1             1
#define MBEDTLS_CMP_VERSION_2             2


/**
 * Type-length-value structure that allows for ASN1 using DER.
 */
typedef mbedtls_asn1_buf cmp_buf;

/**
 * CMP PKIStatusInfo
 */
typedef struct cmp_PKIStatusInfo {
    int PKIStatus;
    mbedtls_asn1_sequence *statusString; /* PKIFreetext = Sequence of UTF8String */
    mbedtls_asn1_bitstring PKIFailureInfo;
} cmp_PKIStatusInfo;

/**
 * CMP CertResponse
 */
typedef struct cmp_CertifiedKeyPair {
    mbedtls_x509_crt *cert;
    cmp_buf cert_d; /**< The raw msg data (DER). */
    /* TODOenccert? */
} cmp_CertifiedKeyPair;

/**
 * CMP ErrorMsgContent
 */
typedef struct cmp_ErrorMsgContent {
    cmp_PKIStatusInfo pKIStatusInfo;
    int errorCode; /* OPTIONAL */
    mbedtls_asn1_sequence *errorDetails; /* OPTIONAL PKIFreetext */
} cmp_ErrorMsgContent;

/**
 * CMP CertResponse
 */
typedef struct cmp_CertResponse {
    int certReqId;
    cmp_PKIStatusInfo status;
    cmp_CertifiedKeyPair *certifiedKeyPair;
} cmp_CertResponse;

/**
 * CMP certRepmessage
 */
typedef struct cmp_CertRepMessage {
    cmp_CertResponse *response; /* TODO how to best handle more than one? */
} cmp_CertRepMessage;

/**
 * CMP PKIMessage structure
 */
typedef struct cmp_pkimessage {
    cmp_buf raw; /**< The raw msg data (DER). */

    cmp_buf body; /**< The raw msg data (DER). */
    cmp_buf header; /**< The raw msg data (DER). */
    cmp_CertRepMessage *crep; /* The CertRepMessage in case of IP/CP/KUP */
    cmp_ErrorMsgContent *error; /* An Error */

    mbedtls_asn1_bitstring *protection; /**< The raw msg data (DER). */
    cmp_buf extraCerts; /**< The raw msg data (DER). */

    cmp_buf sender_raw; /**< The raw sender data (DER). */
    mbedtls_x509_name sender; /**< The parsed sender data (named information object). */

    cmp_buf recipient_raw; /**< The raw recipient data (DER). */
    mbedtls_x509_name recipient; /**< The parsed recipient data (named information object). */

    cmp_PBMParameter *pbmp;

    mbedtls_md_type_t sig_md; /**< Internal representation of the MD algorithm of the signature algorithm, e.g. MBEDTLS_MD_SHA256 */
    mbedtls_pk_type_t sig_pk; /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. MBEDTLS_PK_RSA */

    int implicit_conf_granted;

} cmp_pkimessage;

/* TODO describe */
void cmp_CertifiedKeyPair_free(cmp_CertifiedKeyPair *certifiedKeyPair);
void cmp_CertResponse_free(cmp_CertResponse *response);
void cmp_CertRepMessage_free(cmp_CertRepMessage *crep);

int cmp_pkimessage_parse_check_der(cmp_ctx *ctx, int expected_type, cmp_pkimessage *cmp, unsigned char *buf,
        size_t buflen);
void cmp_pkimessage_init(cmp_pkimessage *msg);
void cmp_pkimessage_free(cmp_pkimessage *msg);

/*!
 * \brief           Write a built up PKIMessage to a DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * PKIMessage ::= SEQUENCE {
 *  header    PKIHeader,
 *  body      PKIBody,
 *  protection    [0]    PKIProtection                              OPTIONAL,
 *  extraCerts    [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate }    OPTIONAL
 *
 *  PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage
 */
int cmpcl_CMPwrite_PKIMessage_der(cmp_ctx *ctx, unsigned char *buf, size_t size,
        unsigned char **myp, int unprotected);
/* TODO that random stuff for ECDSA... */

/**
 * \brief           Write a message protection for a given range
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 */
int cmpcl_CMPwrite_PKIMessage_protection_der(unsigned char **p,
        unsigned char *start, cmp_ctx *ctx, const unsigned char* input,
        const size_t in_len);
/* TODO that random stuff for ECDSA... */

/**
 * \brief           Write a built up PKIHeader to a DER structure
 */
int cmpcl_CMPwrite_PKIHeader_der(unsigned char **p, unsigned char *start,
        cmp_ctx *ctx, int unprotected);

#ifdef __cplusplus
}
#endif

#endif /* cmpcl_int.h */
