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

#include "mbedtls/ctr_drbg.h"
#include "cmpcl_high.h"

#ifdef __cplusplus
extern "C" {
#endif

/* **************************************************************** */
/* Transfer */
/* **************************************************************** */
/**
 * \brief Layer-4 function used to send and receive DER-encoded PKIMessages
 * \param cb_context application-defined configuration context for cmp_send_receive_cb
 * \param outbuf PKIMessage to send
 * \param outlen length of PKIMessage to send
 * \param returned buffer containing a received PKIMessage
 * \param inlen length of received message
 * \return negative value in case of error
 */
typedef int (*cmp_send_receive_cb)(void *cb_context,
                                   const unsigned char *outbuf, const size_t outlen,
                                   unsigned char **inbuf, size_t *inlen);

typedef struct cmp_ctx cmp_ctx;

#define CMP_CTX_POPO_RAVERIFIED       0
#define CMP_CTX_POPO_SIGNATURE        1

/**
 * \brief           Prepare a fresh CMP context with default values
 *
 * \param ctr_drbg   CTR_DRBG context structure used for random byte generation
 * \param cb_context application-defined configuration context for send_receive_func
 * \param send_receive_func Layer-4 send/receive function to use
 * \param popo_method Proof of Possession method to use (CMP_CTX_POPO_SIGNATURE or CMP_CTX_POPO_RAVERIFIED)
 * \param prot_md_alg protection hash algorithm to use
 * \param popo_md_alg POPO hash algorithm to use
 * \return the new CMP context, NULL on error
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

/**
 * \brief           Set the key to use to when protection a PKIMessage by a signature
 *
 * \param ctx       CMP context
 * \param key       key to use for signature-based protection
 */
void cmp_ctx_set_prot_key(cmp_ctx *ctx, const mbedtls_pk_context *key);

/**
 * \brief           Set the certificate used with signature-based protection
 *                  will be included in extraCerts
 *
 * \param ctx       CMP context
 * \param crt       certificate to use for signature-based protection
 */
void cmp_ctx_set_prot_crt(cmp_ctx *ctx, const mbedtls_x509_crt *crt);

/**
 * \brief           Set the certificate and chain used with signature-based protection,
 *                  which must include the protection cert, will be included in extraCerts
 *
 * \param ctx       CMP context
 * \param crt       certificate chain to use for signature-based protection
 */
void cmp_ctx_set_prot_crt_chain(cmp_ctx *ctx, const mbedtls_x509_crt *crt_chain);

/**
 * \brief           Select the use of Password-Based MAC (PBM) with shared secret
 *
 * \param ctx       CMP context
 * \param ctr_drbg  The CTR_DRBG context used for random salt generation, length fixed to 16
 * \param owf       One-way function (OWF) to use, iteration count fixed to 1000
 * \param mac       Message Authentication Code (MAC) function to use
 * \param secret    secret to use, gets copied
 * \param len       length of secret in bytes
 */
int cmp_ctx_set_prot_pbm_secret(cmp_ctx *ctx,
                                mbedtls_ctr_drbg_context *ctr_drbg,
                                mbedtls_md_type_t owf, mbedtls_md_type_t mac,
                                const unsigned char *secret,
                                size_t len);

/**
 * \brief           Set the reference (sender KID) to use with PBM-based message protection
 *
 * \param ctx       CMP context
 * \param ref       reference byte string, gets copied
 * \param len       reference length in bytes
 */
int cmp_ctx_set_senderKID(cmp_ctx *ctx, const unsigned char *ref, size_t len);


/**
 * \brief           Set the sender Distinguished Name (DN) of PKIMessages.
 *                  DNs should contain a comma-separated list
 *                  of Relative Distinguished Name (RDN) OID types and values:
 *                  e.g. "C=FI,O=Nokia,CN=IoT Device 1"
 *                  Due to Mbed TLS limitation, cannot use multi-RDNs.
 *
 * \param ctx           CMP context
 * \param sender_name   sender name to set, gets copied
 *
 * \return          0 if subject name was parsed successfully,
 *                  or a specific error code
 */
int cmp_ctx_set_sender_name(cmp_ctx *ctx, const char *sender_name);

/**
 * \brief           Set the recipient Distinguished Name (DN) of PKIMessages.
 *                  DNs should contain a comma-separated list
 *                  of Relative Distinguished Name (RDN) OID types and values:
 *                  e.g. "C=FI,O=Nokia,CN=CMP Server 1"
 *                  Due to Mbed TLS limitation, cannot use multi-RDNs.
 *
 * \param ctx             CMP context
 * \param recipient_name  recipient name to set, gets copied
 *
 * \return          0 if subject name was parsed successfully, or
 *                  a specific error code
 */
int cmp_ctx_set_recipient_name(cmp_ctx *ctx, const char *recipient_name);

/**
 * \brief           Set the subject Distinguished Name (DN) for the requested certificate.
 *                  DNs should contain a comma-separated list
 *                  of Relative Distinguished Name (RDN) OID types and values:
 *                  e.g. "C=FI,O=Nokia,CN=CMP EE"
 *                  Due to Mbed TLS limitation, cannot use multi-RDNs.
 *
 * \param ctx           CMP context
 * \param subject_name  subject name to set, gets copied
 *
 * \return          0 if subject name was parsed successfully, or
 *                  a specific error code
 */
int cmp_ctx_set_subject_name(cmp_ctx *ctx, const char *subject_name);
/**
 * \brief           Set the key to create a CertReqMsg for
 *
 * \param ctx       CMP context
 * \param key       key to use in CSR
 */
void cmp_ctx_set_new_key(cmp_ctx *ctx, const mbedtls_pk_context *new_key);


/**
 * \brief           Set the (typically, root CA) certificates to trust for message protection validation
 *
 * \param ctx       CMP context
 * \param crt       certificates to trust for message protection validation
 */
void cmp_ctx_set_prot_trust_anchor(cmp_ctx *ctx, const mbedtls_x509_crt *crt);

/**
 * \brief           Set the Certificate Revocation Lists (CRLs) to use
 *
 * \param ctx       CMP context
 * \param crt       CRLs to use
 */

void cmp_ctx_set_prot_crls(cmp_ctx *ctx, OPTIONAL const mbedtls_x509_crl *crl);


/**
 * \brief           Set the (typically, root CA) certificates to trust for validating newly enrolled certificates
 *
 * \param ctx       CMP context
 * \param crt       certificate to trust for checking newly enrolled certificates
 */
void cmp_ctx_set_enrol_trust_anchor(cmp_ctx *ctx, OPTIONAL const mbedtls_x509_crt *crt);

/**
 * \brief           Set the CRLs to use when validating newly enrolled certificates
 *
 * \param ctx       CMP context
 * \param crt       CRLs to use
 */

void cmp_ctx_set_enrol_crls(cmp_ctx *ctx, OPTIONAL const mbedtls_x509_crl *crl);

/**
 * \brief           Set whether to request implicitConfirm
 *
 * \param ctx       CMP context
 * \param ic        0=false, 1=true
 */
void cmp_ctx_set_implicit_confirm(cmp_ctx *ctx, int ic);

/**
 * \brief           Set whether to allow unprotected negative responses and PKIConf
 *
 * \param ctx       CMP context
 * \param allow     0=false, 1=true
 */
void cmp_ctx_set_unprotected_errors(cmp_ctx *ctx, int allow);

/**
 * \brief           Set whether to cache extra certs during a transaction
 *
 * \param ctx       CMP context
 * \param cache     0=false, 1=true
 */

void cmp_ctx_set_cache_extracerts(cmp_ctx *ctx, int cache);

/**
 * \brief           Set whether to send unprotected request messages or not
 *
 * \param ctx       CMP context
 * \param unprot    0=false, 1=true
 */
void cmp_ctx_set_unprotected_requests(cmp_ctx *ctx, int unprot);


/**
 * \brief                   Set raw extensions to use in CRMF template
 * \param ctx               CMP context
 * \param exts              DER-encoded list of extensions to add, or NULL
 * \param len               length of exts in bytes, or 0 if exts == NULL
 *
 */
void cmp_ctx_set_crmf_extension(cmp_ctx *ctx,
                                const unsigned char *exts, size_t len);

/* **************************************************************** */
/* CMP transactions */
/* **************************************************************** */

/**
 * \brief initate a CMP transaction
 * \param ctx parameter context to use
 * \param body_type IR, CR or KUR
 */
int cmpcl_do_transaction(cmp_ctx *ctx, const int body_type);

mbedtls_x509_crt *cmp_ctx_get_new_cert(const cmp_ctx *ctx);
mbedtls_x509_crt *cmp_ctx_get_extraCerts(const cmp_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CMPCL_LOW_H */
