/*
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

/**
 * \brief high-level CMP client API
 *
 *  If HARCODED_CREDS are in use, a path is an access token to the hard coded certificate or key,
 *   otherwise a name of a file holding a PEM encoded certificate or key.
 */

#include "mbedtls/x509_crt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OPTIONAL /* parameter may be NULL */

/**
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
 * \brief create an initialized cmp_ctx context, calls cmp_ctx_init()
 * \param server FQDN of upstream CMP entity
 * \param server port TCP portnumber as string of the upstream CMP entity,
 *        if NULL use 80 for HTTP or 443 for HTTPS
 * \param http path part of server URL
 * \param tls_key TLS client key path Must be NULL, if mutual authentication is not required.
 * \param tls_cert TLC client certificate path used for mutual authentication.  Must be NULL if
 *        mutual authentication is not required.
 * \param sender_name RDN used as CMP sender in all transactions related to returned context
 * \param recipient_name  RDN used as CMP recipient in all transactions related to returned context
 * \param allow_unprotected_errors if 1 accept unprotected ERROR responses from CMP upstream
 *        entity, otherwise 0
 * \return initialized cmp_ctx, all parameter set to default or NULL in case of error.
 */
cmp_ctx *cmp_client_init(const char *server, OPTIONAL const char *port,
                         const char *path,
                         OPTIONAL const char *tls_key, OPTIONAL const char *tls_cert,
                         OPTIONAL const char *tls_trusted,
                         OPTIONAL const char *sender_name,
                         OPTIONAL const char *recipient_name,
                         int allow_unprotected_errors);

/**
 * \brief enable use of signature based protection for transaction,
 *        either mp_client_set_signature_protection() or cmp_client_set_pbm_protection should
 *        be called for an initialized context
 *
 * \param ctx already initialized context
 * \param md_alg message digest algorithm to be used for protection, or 0 for default
 * \param key path of private key used for protection,
          can be NULL if unprotected request shall be used
 * \param crt path of certificate used for protection,
          can be NULL if unprotected request shall be used.
          If non-NULL also the key must be non-NULL and must match the crt
 * \param crt_chain path of the chain of crt, or NULL
 * \param trusted path of trust anchor certificates used for protection validation,
          can be NULL only if protection validation is not required
 * \param crls CRLs to use in protection validation, must be NULL if trusted is NULL
 * \retval 0 OK
 *
 */
int cmp_client_set_signature_protection(cmp_ctx *ctx, int md_alg,
                                        OPTIONAL const mbedtls_pk_context *key,
                                        OPTIONAL const char *crt,
                                        OPTIONAL const char *crt_chain,
                                        OPTIONAL const char *trusted,
                                        OPTIONAL const char *crls);

/* either cmp_client_set_signature_protection() or cmp_client_set_pbm_protection should be called */

/**
 * \brief enable use of password based protection for transaction,
 *        either mp_client_set_signature_protection() or cmp_client_set_pbm_protection should
 *        be called for an initialized context
 *
 * \param ctx already initialized context
 * \param salt_len length of salt used for protection, or 0 for default
 * \param owf one way function used for protection, or 0 for default
 * \param mac message digest function to build the message authentication code, or 0 for default
 * \param secret secret used for protection
 * \param length len length of secret
 * \param ref sender key id used in transaction, or NULL for none
 * \param ref_len length of ref, ignored if ref is NULL
 * \retval 0 OK
 */
int cmp_client_set_pbm_protection(cmp_ctx *ctx,
                                  size_t salt_len, /* mbedtls_md_type_t */ int owf,
                                  /* mbedtls_md_type_t */ int mac, int iterationCount,
                                  const unsigned char *secret, size_t len,
                                  OPTIONAL const unsigned char *ref, size_t ref_len);


/**
 * \brief start a enrollment transaction
 * \param ctx already initialized context
 * \param request_body_type MBEDTLS_CMP_PKIBODY_IR, MBEDTLS_CMP_PKIBODY_CR
 *        or MBEDTLS_CMP_PKIBODY_KUR
 * \param subject RDN of certificate to enroll
 * \param key keypair of certificate to enroll
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
                           const mbedtls_pk_context *key,
                           // TODO OPTIONAL const ... extensions,
                           int popo_md_alg,
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
