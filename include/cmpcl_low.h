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

#ifndef CMPCL_LOW_H
#define CMPCL_LOW_H

#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"

#ifdef __cplusplus
extern "C" {
#endif

/* API-level PKIBODY TYPES */
#define MBEDTLS_CMP_PKIBODY_IR                0
#define MBEDTLS_CMP_PKIBODY_CR                2
#define MBEDTLS_CMP_PKIBODY_KUR               7



/* **************************************************************** */
/* PasswordBasedMac PBM */
/* **************************************************************** */

typedef struct cmp_PBMParameter cmp_PBMParameter;

/**
 * \brief          Initialize PBMParameter for PBM calculation
 *
 * \param pbmp           PBMParameter to initialize
 * \param ctr_drbg       The CTR_DRBG context used for random salt generation
 * \param salt_len       length of salt to used for PBM
 * \param owf            OWF to use
 * \param iterationCount iteration count to use
 * \param mac            MAC to use
 * \return               negative value in case of error
 */
#if 1
int cmp_PBMParameter_init(cmp_PBMParameter *pbmp,
                          mbedtls_ctr_drbg_context *ctr_drbg, size_t salt_len,
                          mbedtls_md_type_t owf, int iterationCount, mbedtls_md_type_t mac);

/**
 * \brief          Unallocate all PBMParameter data
 *
 * \param pbmp      PBMParameter to free
 */
void cmp_PBMParameter_free(cmp_PBMParameter *pbmp);
#endif

/* **************************************************************** */
/* Transfer */
/* **************************************************************** */
/**
 * \brief Layer 4 function used to send and receive DER encoded PKIMessages
 * \param cb_context opaque configuration context for cmp_send_receive_cb
 * \param outbuf DER encoded PKIMessage to send
 * \param outlen length of DER encoded PKIMessage to send
 * \param returned buffer containing a received DER encoded PKIMessage
 * \param inlen length of received message
 * \return negative value in case of error
 */
typedef int (*cmp_send_receive_cb)(void *cb_context,
                                   const unsigned char *outbuf, const size_t outlen,
                                   unsigned char **inbuf,
                                   size_t *inlen);

typedef struct cmp_ctx cmp_ctx;

    /**
 * \brief           Initialize a CMP context to default values
 *                  Must not be have content
 *
 * \param ctx       cmpctx context to initialise
 * \param ctr_drbg   CTR_DRBG context structure used for random byte generation
 * \param cb_context opaque configuration context for send_receive_func
 * \param send_receive_func Layer 4 send/receive function to use
 * \param popo_method Proof of Possession method t use,
 *        CMP_CTX_POPO_RAVERIFIED or CMP_CTX_POPO_SIGNATURE
 * \param prot_md_alg protection algorithm to use
 * \param popo_md_alg POPO algorithm to use
 * \return negative value in case of error
 */
cmp_ctx *cmp_ctx_init(mbedtls_ctr_drbg_context *ctr_drbg,
                 void *cb_context, cmp_send_receive_cb send_receive_func,
                 int popo_method, int prot_md_alg, int popo_md_alg);
/**
 * \brief           Free the contents of a cmpctx write context
 *
 * \param ctx       cmpctx context to free
 */
void cmp_ctx_free(cmp_ctx *ctx);

#if 1
#define CMP_CTX_POPO_RAVERIFIED       0
#define CMP_CTX_POPO_SIGNATURE        1

/**
 * \brief           Set the POPO Method to use
 *
 * \param ctx       CMP context
 * \param popo_method popo_method to use
 */
void cmp_ctx_set_popo_method(cmp_ctx *ctx, int popo_method);

/**
 * \brief           Set the MD algorithm used to protect the PKIMessage
 *
 * \param ctx       CMP context
 * \param md_alg    MD algorithm to use
 */
void cmp_ctx_set_sig_prot_md_alg(cmp_ctx *ctx, mbedtls_md_type_t md_alg);

/**
 * \brief           Set the hash algorithm for POPO
 *
 * \param ctx       CMP context
 * \param popo_method popo_method to use
 */
void cmp_ctx_set_popo_md_alg(cmp_ctx *ctx, mbedtls_md_type_t md_alg);
#endif

/**
 * \brief           Set the key used to protect the PKIMessage
 *
 * \param ctx       CMP context
 * \param key       key to use
 */
void cmp_ctx_set_prot_key(cmp_ctx *ctx, mbedtls_pk_context *key);

/**
 * \brief           Set the certificate used to protect the PKIMessage,
 *                  will be included in extraCerts
 *
 * \param ctx       CMP context
 * \param crt       certificate to use
 */
void cmp_ctx_set_prot_crt(cmp_ctx *ctx, mbedtls_x509_crt *crt);

/**
 * \brief           Set the chain of the certificate used to protect the
 *                  PKIMessage, will be included in extraCerts
 *
 * \param ctx       CMP context
 * \param crt       certificate (chain) to use
 */
void cmp_ctx_set_prot_crt_chain(cmp_ctx *ctx, mbedtls_x509_crt *crt);

/**
 * \brief           Set the PBM parameter
 *                  Consumes the pointer
 *
 * \param ctx       CMP context
 * \param pbmp      PBM Parameter to use
 */
void cmp_ctx_set_pbmp(cmp_ctx *ctx, cmp_PBMParameter *pbmp);

/**
 * \brief           Set the shared secret to use for PBM
 *
 * \param ctx       CMP context
 * \param ctr_drbg  The CTR_DRBG context to use
 * \param owf		owf to use
 * \param mac		mac to use (must be MBEDTLS_MD_*)
 * \param sec       secret, gets copied
 * \param len       length of secret in bytes
 */
int cmp_ctx_set_prot_pbm_secret(cmp_ctx *ctx,
                                mbedtls_ctr_drbg_context *ctr_drbg,
                                mbedtls_md_type_t owf, mbedtls_md_type_t mac,
                                const unsigned char *sec,
                                size_t len);

/**
 * \brief           Set the reference (sender KID) to use for PBM
 *
 * \param ctx       CMP context
 * \param ref       reference, gets copied
 * \param len       length in bytes
 */
int cmp_ctx_set_senderKID(cmp_ctx *ctx, const unsigned char *ref,
                          size_t len);


/**
 * \brief           Set the sender name for a PKIMessage
 *                  Subject names should contain a comma-separated list
 *                  of OID types and values:
 *                  e.g. "C=FI,O=Nokia,CN=IoT Device 1"
 *
 * \param ctx           CMP context to use
 * \param subject_name  subject name to set
 *
 * \return          0 if subject name was parsed successfully, or
 *                  a specific error code
 */
int cmp_ctx_set_sender_name(cmp_ctx *ctx, const char *sender_name);

/**
 * \brief           Set the recipient name for a PKIMessage
 *                  Subject names should contain a comma-separated list
 *                  of OID types and values:
 *                  e.g. "C=FI,O=Nokia,CN=CMP Server 1"
 *
 * \param ctx           CMP context to use
 * \param subject_name  subject name to set
 *
 * \return          0 if subject name was parsed successfully, or
 *                  a specific error code
 */
int cmp_ctx_set_recipient_name(cmp_ctx *ctx, const char *recipient_name);

/**
 * \brief           Set the subject name for the requested certificate
 *                  Subject names should contain a comma-separated list
 *                  of OID types and values:
 *                  e.g. "C=FI,O=Nokia,CN=CMP EE"
 *
 * \param ctx           CMP context to use
 * \param subject_name  subject name to set
 *
 * \return          0 if subject name was parsed successfully, or
 *                  a specific error code
 */
int cmp_ctx_set_subject_name(cmp_ctx *ctx, const char *subject_name);
/**
 * \brief           Set the key to create a CertReqMsg for
 *
 * \param ctx       CMP context
 * \param key       key to use
 */
void cmp_ctx_set_new_key(cmp_ctx *ctx, mbedtls_pk_context *new_key);


/**
 * \brief           Set the chain of the trusted protection CA certificates
 *
 * \param ctx       CMP context
 * \param crt       certificate (chain) to use
 */
void cmp_ctx_set_prot_trust_anchor(cmp_ctx *ctx, mbedtls_x509_crt *crt);

/**
 * \brief           Set the CRL of the trusted protection CA certificates
 *
 * \param ctx       CMP context
 * \param crt       certificate (chain) to use
 */
#if 1
void cmp_ctx_set_prot_crls(cmp_ctx *ctx, mbedtls_x509_crl *crl);
#endif

/**
 * \brief           Set the chain of the trusted enrollment CA certificates
 *
 * \param ctx       CMP context
 * \param crt       certificate (chain) to use
 */
void cmp_ctx_set_enrol_trust_anchor(cmp_ctx *ctx, mbedtls_x509_crt *crt);

/**
 * \brief           Set the CRL of the trusted enrollment CA certificates
 *
 * \param ctx       CMP context
 * \param crt       certificate (chain) to use
 */
#if 1
void cmp_ctx_set_enrol_crls(cmp_ctx *ctx, mbedtls_x509_crl *crl);

/**
 * \brief           Set whether to use implicitConfirm
 *
 * \param ctx       CMP context
 * \param ic        0=false, 1=true
 */
void cmp_ctx_set_implicit_confirm(cmp_ctx *ctx, int ic);
#endif

/**
 * \brief           Set whether to allow unprotected negative responses and PKIConf
 *
 * \param ctx       CMP context
 * \param ic        0=false, 1=true
 */
void cmp_ctx_set_unprotected_errors(cmp_ctx *ctx, int allow);

/**
 * \brief           Set whether to cache extra certs during one transaction
 *
 * \param ctx       CMP context
 * \param cache     0=false, 1=true
 */
#if 1
void cmp_ctx_set_cache_extracerts(cmp_ctx *ctx, int cache);

/**
 * \brief           Set whether to send unprotected ir or not
 *
 * \param ctx       CMP context
 * \param unprot    0=false, 1=true
 */
void cmp_ctx_set_unprotected_ir(cmp_ctx *ctx, int unprot);
#endif

mbedtls_x509_crt *cmp_ctx_get_new_cert(const cmp_ctx *ctx);
mbedtls_x509_crt *cmp_ctx_get_extraCerts(const cmp_ctx *ctx);

/* **************************************************************** */
/* CMP transactions */
/* **************************************************************** */

/**
 * \brief initate a CMP transaction
 * \param ctx parameter context to use
 * \param body_type IR, CR or KUR
 */
int cmpcl_do_transaction(cmp_ctx *ctx, const int body_type);



#ifdef __cplusplus
}
#endif

#endif /* CMPCL_LOW_H */
