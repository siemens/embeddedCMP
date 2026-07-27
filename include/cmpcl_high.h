/*
 * @file   cmpcl_high.h
 * @brief  embedded CMP client high-level API
 *
 * @author David von Oheimb, Siemens AG, David.von.Oheimb@siemens.com
 *
 *  Copyright (c) 2026 Siemens AG
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

#ifndef CMPCL_HIGH_H
#define CMPCL_HIGH_H

#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"
// #include "cmpcl_low.h" /* for cmp_send_receive_cb */

#ifdef __cplusplus
extern "C" {
#endif

#define OPTIONAL /* parameter may be NULL */

/*!
 * \brief generate a new asymmetric key pair
 *
 * The key_type string determines the algorithm and parameters:
 *   - "RSA:<nbits>" generates an RSA key with the given bit length
 *     (e.g. "RSA:2048", "RSA:4096")
 *   - "EC:<curve_name>" generates an EC key on the named curve
 *     (e.g. "EC:secp256r1", "EC:secp384r1")
 *   - For backward compatibility, a bare curve name without prefix
 *     (e.g. "secp256r1") is treated as "EC:<curve_name>"
 *
 * \param key_type key type specification string as described above
 * \param ctr_drbg random number generator context to use
 * \param pkey on success, receives a pointer to the newly allocated key
 *        to be freed by th caller;  on failure, *pkey is set to NULL.
 * \retval 0 OK
 */
int generate_key(const char *key_type,
                 mbedtls_ctr_drbg_context *ctr_drbg,
                 mbedtls_pk_context **pkey);

/*!
 * \brief print details of a certificate
 * \param cert_prefix prepend the printout with this prefix
 * \param line_prefix prepend every line of the prefix with this string
 * \param crt the certificate to print
 * \retval 0 OK
 */
int print_certinfo(const char *cert_prefix, const char *line_prefix, const mbedtls_x509_crt *crt);

/* API-level PKIBODY TYPES */
#define MBEDTLS_CMP_PKIBODY_IR                0
#define MBEDTLS_CMP_PKIBODY_CR                2
#define MBEDTLS_CMP_PKIBODY_KUR               7

typedef struct cmp_ctx cmp_ctx;

/*!
 * \brief create an initialized cmp_ctx context, calls lower-level cmp_ctx_init()
 * After calling this, cmp_client_set_http() can be used to set up HTTP(S)-based transport.
 * \param sender_name RDN used as CMP sender in all transactions related to returned context
 * \param recipient_name  RDN used as CMP recipient in all transactions related to returned context
 * \param allow_unprotected_errors if 1 accept unprotected ERROR responses from CMP upstream
 *        entity, otherwise 0
 * \return initialized cmp_ctx, all parameter set to default or NULL in case of error.
 */
cmp_ctx *cmp_client_init(OPTIONAL const char *sender_name,
                         OPTIONAL const char *recipient_name,
                         int allow_unprotected_errors);

typedef int (*cmp_send_receive_cb)(void *cb_context,
                                   const unsigned char *outbuf, const size_t outlen,
                                   unsigned char **inbuf, size_t *inlen);

/*!
 * \brief may be used to set in a CMP a custom transport mechanism
 * \param ctx already allocated cmp_ctx
 * \param cb_context opaque context passed to send_receive_func
 * \param send_receive_func function used to send and receive DER-encoded PKIMessages
 */
void cmp_client_set_transport(cmp_ctx *ctx, void *cb_context,
                              cmp_send_receive_cb send_receive_func);

/*!
 * \brief set up HTTP(S)-based transport for a CMP context
 * \param ctx already allocated cmp_ctx with ctr_drbg initialized
 * \param server FQDN of upstream CMP entity
 * \param port TCP port number as string, or NULL for default (80/443)
 * \param path HTTP path part of server URL
 * \param tls_key TLS client key path, or NULL for not authenticating as TLS client
 * \param tls_cert TLS client certificate path, or NULL for not authenticating as TLS client
 * \param tls_trusted TLS trusted certificates path, or NULL for plain HTTP
 * \retval 0 OK
 */
int cmp_client_set_http(cmp_ctx *ctx,
                        const char *server, OPTIONAL const char *port,
                        const char *path,
                        OPTIONAL const char *tls_key, OPTIONAL const char *tls_cert,
                        OPTIONAL const char *tls_trusted);

/*!
 * \brief enable the use of signature-based protection for requests and/or responses.
 *        cmp_client_enable_signature_protection() and/or cmp_client_set_pbm_protection()
 *        should be called.
 *
 * \param ctx already initialized context
 * \param md_alg message digest algorithm to be used for protection, or 0 for default
 * \param key path of private key to use for protecting request messages
          unless password-based protection is set up in addition;
          can be NULL if unprotected request shall be used
 * \param crt path of certificate to use in case the private key is used,
          can be NULL only if key is NULL, otherwise must match the key
 * \param crt_chain path of the chain of crt, must be NULL if crt is NULL
 * \param trusted path of trust anchor certificates
 *        to use validating response messages with signature-based protection,
          can be NULL if signature-based protection validation is not required
 * \param crls CRLs to use in protection validation, must be NULL if trusted is NULL
 * \retval 0 OK
 *
 */
int cmp_client_enable_signature_protection(cmp_ctx *ctx, int md_alg,
                                           OPTIONAL const mbedtls_pk_context *key,
                                           OPTIONAL const char *crt,
                                           OPTIONAL const char *crt_chain,
                                           OPTIONAL const char *trusted,
                                           OPTIONAL const char *crls);

/*!
 * \brief set the use of password-based protection for requests and/or responses.
 *        cmp_client_enable_signature_protection() and/or cmp_client_set_pbm_protection
 *        should be called.
 *
 * \param ctx already initialized context
 * \param secret the shareds secret to use for protecting request messages
 *        (even if cmp_client_enable_signature_protection() is called as well)
 *        and for validating response messages with password-based protection.
 * \param len length of secret
 * \param ref senderKID to set in request messages, or NULL for none
 * \param ref_len length of ref, ignored if ref is NULL
 * \param salt_len length of salt to use for protection, or 0 for default
 * \param owf one-way function to use for protection, or 0 for default
 * \param mac message digest function to build the message authentication code, or 0 for default
 * \param  iterationCount iteration count to use with the MAC function
 * \retval 0 OK
 */
int cmp_client_set_pbm_protection(cmp_ctx *ctx,
                                  const unsigned char *secret, size_t len,
                                  OPTIONAL const unsigned char *ref, size_t ref_len,
                                  size_t salt_len, /* mbedtls_md_type_t */ int owf,
                                  /* mbedtls_md_type_t */ int mac, int iterationCount);


/*!
 * \brief generate a new asymmetric key pair
 *
 * The key_type string determines the algorithm and parameters:
 *   - "EC:<curve_name>" generates an EC key on the named curve
 *     (e.g. "EC:secp256r1", "EC:secp384r1")
 *   - "RSA:<nbits>" generates an RSA key with the given bit length
 *     (e.g. "RSA:2048", "RSA:4096")
 *   - For backward compatibility, a bare curve name without prefix
 *     (e.g. "secp256r1") is treated as "EC:<curve_name>"
 *
 * \param key_type key type specification string as described above
 * \param ctr_drbg random number generator context to use
 * \param pkey on success, receives a pointer to the newly allocated key;
 *        on failure, *pkey is set to NULL. The caller must free with
 *        mbedtls_pk_free() and mbedtls_free().
 * \retval 0 OK
 */
int generate_key(const char *key_type,
                 mbedtls_ctr_drbg_context *ctr_drbg,
                 mbedtls_pk_context **pkey);

/*!
 * \brief start an enrollment transaction
 * \param ctx already initialized context
 * \param request_body_type MBEDTLS_CMP_PKIBODY_IR, MBEDTLS_CMP_PKIBODY_CR
 *        or MBEDTLS_CMP_PKIBODY_KUR
 * \param subject RDN of certificate to enroll
 * \param new_key_type key type specification for generating a new key
 *        (e.g. "EC:secp256r1", "RSA:2048", or bare curve name for backward compat),
 *        or NULL to use *pkey as given (unless pkey is NULL)
 * \param pkey pointer to keypair for enrollment (input/output) unless NULL:
 *        - if new_key_type is given, the generated key is returned in *pkey on success
 *          (NULL on failure)
 *        - if new_key_type is NULL, *pkey is used as input key for enrollment
 * \param key_file file path to store the private key (generated or given) on success,
 *        or NULL to not write the key to a file
 * \param popo_md_alg message digest algorithm used for POPO, 0 for default
 * \param enrol_trusted path to trust anchors used for verifying enrolled certificate
 * \param enrol_crls path to CRLs anchors used for verifying enrolled certificate
 * \param implicit_confirm use implicit confirmation in CMP transaction, otherwise 0
 * \param new_cert path to store enrolled certificate
 * \param extraCerts path to store extra certificates received during enrollment
 * \retval 0 OK
 */
int cmp_client_enroll_cert(cmp_ctx *ctx, int request_body_type,
                           const char *subject,
                           OPTIONAL const char *new_key_type,
                           OPTIONAL mbedtls_pk_context **pkey,
                           OPTIONAL const char *key_file,
                           // TODO OPTIONAL const ... extensions,
                           int popo_md_alg,
                           OPTIONAL const char *enrol_trusted,
                           OPTIONAL const char *enrol_CRLs,
                           int implicit_confirm,
                           const char *new_cert, const char *extraCerts);

/**
 * \brief start a enrollment transaction
 * \param ctx already initialized context
 * \param p10 DER encoded PKCS#10 CSR
 * \param p10_len length of p10
 * \param enrol_trusted path to trust anchors used for verifying enrolled certificate
 * \param enrol_crls path to CRLs anchors used for verifying enrolled certificate
 * \param implicit_confirm use implicit confirmation in CMP transaction, otherwise 0
 * \param new_cert path to store enrolled certificate
 * \param extraCerts path to store extra certificates received during enrollment
 * \retval 0 OK
 */
int cmp_client_enroll_p10(cmp_ctx *ctx,
                          const unsigned char *p10, size_t p10_len,
                          OPTIONAL const char *enrol_trusted,
                          OPTIONAL const char *enrol_CRLs,
                          int implicit_confirm,
                          char *new_cert, char *extraCerts);

/**
 * \brief deallocate an initalized context
 * \param ctx initialized context
 */
void cmp_client_free(cmp_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CMPCL_HIGH_H */
