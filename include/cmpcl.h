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

#ifndef CMPCL_H
#define CMPCL_H

#include "cmpcl_error.h"
#include "mbedtls/asn1.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CMPCL_ASN1_CHK_ADD(g, f) do { if ((ret = f) < 0) \
                                      { CMPERRV("ret=%d\n", ret); \
                                        goto err; }       \
                                      else g += ret; } while (0)

/* PKIBODY TYPES */
#define MBEDTLS_CMP_PKIBODY_IR                0
#define MBEDTLS_CMP_PKIBODY_IP                1
#define MBEDTLS_CMP_PKIBODY_CR                2
#define MBEDTLS_CMP_PKIBODY_CP                3
#define MBEDTLS_CMP_PKIBODY_P10CR             4
#define MBEDTLS_CMP_PKIBODY_POPDECC           5
#define MBEDTLS_CMP_PKIBODY_POPDECR           6
#define MBEDTLS_CMP_PKIBODY_KUR               7
#define MBEDTLS_CMP_PKIBODY_KUP               8
#define MBEDTLS_CMP_PKIBODY_KRR               9
#define MBEDTLS_CMP_PKIBODY_KRP              10
#define MBEDTLS_CMP_PKIBODY_RR               11
#define MBEDTLS_CMP_PKIBODY_RP               12
#define MBEDTLS_CMP_PKIBODY_CCR              13
#define MBEDTLS_CMP_PKIBODY_CCP              14
#define MBEDTLS_CMP_PKIBODY_CKUANN           15
#define MBEDTLS_CMP_PKIBODY_CANN             16
#define MBEDTLS_CMP_PKIBODY_RANN             17
#define MBEDTLS_CMP_PKIBODY_CRLANN           18
#define MBEDTLS_CMP_PKIBODY_PKICONF          19
#define MBEDTLS_CMP_PKIBODY_NESTED           20
#define MBEDTLS_CMP_PKIBODY_GENM             21
#define MBEDTLS_CMP_PKIBODY_GENP             22
#define MBEDTLS_CMP_PKIBODY_ERROR            23
#define MBEDTLS_CMP_PKIBODY_CERTCONF         24
#define MBEDTLS_CMP_PKIBODY_POLLREQ          25
#define MBEDTLS_CMP_PKIBODY_POLLREP          26


/* PKIStatus values
 *
 *
 * PKIStatus ::= INTEGER {
 *        accepted                (0),
 *        -- you got exactly what you asked for
 *        grantedWithMods        (1),
 *        -- you got something like what you asked for; the
 *        -- requester is responsible for ascertaining the differences
 *        rejection              (2),
 *        -- you don't get it, more information elsewhere in the message
 *        waiting                (3),
 *        -- the request body part has not yet been processed; expect to
 *        -- hear more later (note: proper handling of this status
 *        -- response MAY use the polling req/rep PKIMessages specified
 *        -- in Section 5.3.22; alternatively, polling in the underlying
 *        -- transport layer MAY have some utility in this regard)
 *        revocationWarning      (4),
 *        -- this message contains a warning that a revocation is
 *        -- imminent
 *        revocationNotification (5),
 *        -- notification that a revocation has occurred
 *        keyUpdateWarning       (6)
 *        -- update already done for the oldCertId specified in
 *        -- CertReqMsg
 *    }
 */

#define CMP_PKISTATUS_ACCEPTED                  0
#define CMP_PKISTATUS_GRANTEDWITHMODS           1
#define CMP_PKISTATUS_REJECTION                 2
#define CMP_PKISTATUS_WAITING                   3
#define CMP_PKISTATUS_REVOCATIONWARNING         4
#define CMP_PKISTATUS_REVOCATIONNOTIFICATION    5
#define CMP_PKISTATUS_KEYUPDATEWARNING          6

/*
 * PKIFailureInfo ::= BIT STRING {
 *      -- since we can fail in more than one way!
 *      -- More codes may be added in the future if/when required.
 *    badAlg              (0),
 *       -- unrecognized or unsupported Algorithm Identifier
 *    badMessageCheck     (1),
 *       -- integrity check failed (e.g., signature did not verify)
 *    badRequest          (2),
 *       -- transaction not permitted or supported
 *    badTime             (3),
 *       -- messageTime was not sufficiently close to the system time,
 *    badCertId           (4),
 *    badDataFormat       (5),
 *       -- the data submitted has the wrong format
 *    wrongAuthority      (6),
 *       -- the authority indicated in the request is different from the
 *       -- one creating the response token
 *    incorrectData       (7),
 *       -- the requester's data is incorrect (for notary services)
 *    missingTimeStamp    (8),
 *       -- when the timestamp is missing but should be there
 *       -- (by policy)
 *    badPOP              (9),
 *       -- the proof-of-possession failed
 *    certRevoked         (10),
 *       -- the certificate has already been revoked
 *    certConfirmed       (11),
 *       -- the certificate has already been confirmed
 *    wrongIntegrity      (12),
 *       -- invalid integrity, password based instead of signature or
 *       -- vice versa
 *    badRecipientNonce   (13),
 *       -- invalid recipient nonce, either missing or wrong value
 *    timeNotAvailable    (14),
 *       -- the TSA's time source is not available
 *    unacceptedPolicy    (15),
 *       -- the requested TSA policy is not supported by the TSA.
 *    unacceptedExtension (16),
 *       -- the requested extension is not supported by the TSA.
 *    addInfoNotAvailable (17),
 *       -- the additional information requested could not be
 *       -- understood or is not available
 *    badSenderNonce      (18),
 *       -- invalid sender nonce, either missing or wrong size
 *    badCertTemplate     (19),
 *       -- invalid cert. template or missing mandatory information
 *    signerNotTrusted    (20),
 *       -- signer of the message unknown or not trusted
 *    transactionIdInUse  (21),
 *       -- the transaction identifier is already in use
 *    unsupportedVersion  (22),
 *       -- the version of the message is not supported
 *    notAuthorized       (23),
 *       -- the sender was not authorized to make the preceding
 *       -- request or perform the preceding action
 *    systemUnavail       (24),
 *    -- the request cannot be handled due to system unavailability
 *    systemFailure       (25),
 *    -- the request cannot be handled due to system failure
 *    duplicateCertReq    (26)
 *    -- certificate cannot be issued because a duplicate
 *    -- certificate already exists
 *    }
 */
#define CMP_PKIFAILINFO_BADALG              0
#define CMP_PKIFAILINFO_BADMESSAGECHECK     1
#define CMP_PKIFAILINFO_BADREQUEST          2
#define CMP_PKIFAILINFO_BADTIME             3
#define CMP_PKIFAILINFO_BADCERTID           4
#define CMP_PKIFAILINFO_BADDATAFORMAT       5
#define CMP_PKIFAILINFO_WRONGAUTHORITY      6
#define CMP_PKIFAILINFO_INCORECTDATA        7
#define CMP_PKIFAILINFO_MISSINGTIMESTAMP    8
#define CMP_PKIFAILINFO_BADPOP              9
#define CMP_PKIFAILINFO_CERTREVOKED         10
#define CMP_PKIFAILINFO_CERTCONFIMRED       11
#define CMP_PKIFAILINFO_WRONGINTEGRITY      12
#define CMP_PKIFAILINFO_BADRECIPIENTNONCE   13
#define CMP_PKIFAILINFO_TIMENOTAVAILABLE    14
#define CMP_PKIFAILINFO_UNACCEPTEDPOLICY    15
#define CMP_PKIFAILINFO_UNACCEPTEDEXTENSION 16
#define CMP_PKIFAILINFO_ADDINFONOTAVAILABLE 17
#define CMP_PKIFAILINFO_BADSENDERNONCE      18
#define CMP_PKIFAILINFO_BADCERTTEMPLATE     19
#define CMP_PKIFAILINFO_SIGNERNOTTRUSTED    20
#define CMP_PKIFAILINFO_TRANSACTIONIDINUSE  21
#define CMP_PKIFAILINFO_UNSUPPORTEDVERSION  22
#define CMP_PKIFAILINFO_NOTAUTHORIZED       23
#define CMP_PKIFAILINFO_SYSTEMUNAVAIL       24
#define CMP_PKIFAILINFO_SYSTEMFAILURE       25
#define CMP_PKIFAILINFO_DUPLICATECERTREQ    26



/* **************************************************************** */
/* PasswordBasedMac PBM */
/* **************************************************************** */
typedef struct cmp_PBMParameter {
    unsigned char *salt;
    size_t salt_len;
    mbedtls_md_type_t owf;
    int iterationCount;
    mbedtls_md_type_t mac; /* this is normally wrong as HMAC-SHA1 is not
                              covered by this mbedtls_md_type_t */
} cmp_PBMParameter;

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
int cmp_PBMParameter_init(cmp_PBMParameter *pbmp,
                          mbedtls_ctr_drbg_context *ctr_drbg, size_t salt_len,
                          mbedtls_md_type_t owf, int iterationCount, mbedtls_md_type_t mac);

/**
 * \brief          Unallocate all PBMParameter data
 *
 * \param pbmp      PBMParameter to free
 */
void cmp_PBMParameter_free(cmp_PBMParameter *pbmp);

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


/* **************************************************************** */
/* Context */
/* **************************************************************** */

typedef struct cmp_ctx {

    void *cb_context; /*!< transport provider context */

    cmp_send_receive_cb send_receive_func; /*!< transport provider send/receive function */

    mbedtls_ctr_drbg_context *ctr_drbg; /*!< RNG context*/

    /**
     *  header
     */

    /* PKIHeader ::= SEQUENCE {
     * pvno         INTEGER { cmp1999(1), cmp2000(2) },
     * sender       GeneralName,
     * recipient    GeneralName,
     * messageTime    [0] GeneralizedTime     OPTIONAL,
     * protectionAlg  [1] AlgorithmIdentifier OPTIONAL,
     * senderKID      [2] KeyIdentifier       OPTIONAL,
     * recipKID       [3] KeyIdentifier       OPTIONAL,
     * transactionID  [4] OCTET STRING        OPTIONAL,
     * senderNonce    [5] OCTET STRING        OPTIONAL,
     * recipNonce     [6] OCTET STRING        OPTIONAL,
     * freeText       [7] PKIFreeText         OPTIONAL,
     * generalInfo    [8] SEQUENCE SIZE (1..MAX) OFInfoTypeAndValue OPTIONAL
     * }
     *
     * PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
     */

    mbedtls_x509_name *sender;
    mbedtls_x509_name *recipient;

    char *messageTime;

    unsigned char *transactionID;
    size_t transactionID_len;

    unsigned char *senderNonce;
    size_t senderNonce_len;

    unsigned char *recipNonce;
    size_t recipNonce_len;

    int implicitConfirm;

    /* body */
    int certReqId;
    int body_type;

    mbedtls_x509_name *subject;

    int popo_method;
    mbedtls_md_type_t popo_md_alg;

    /* footer */
    mbedtls_x509_crt *extraCerts;

    int cache_extracerts;   /* allow to cache extra certs during one transaction */

    /* holds PKIFailureInfo if new cert could not be verified */
    uint32_t cert_conf_fail_info;

    /* protection */
    int unprotected_errors; /* allow negative responses without protection */
    int unprotected_ir;  /* allow sending of unprotected ir */
    mbedtls_md_type_t sig_prot_md_alg; /*  hashing algorithm */

    /* password based protection */
    cmp_PBMParameter *pbmp;
    unsigned char *senderKID; /* shared secret */
    size_t reference_len;
    unsigned char *prot_secret; /* shared secret */
    size_t secret_len;


    /* signature based protection */
    mbedtls_x509_crt *prot_trust_anchor;
    mbedtls_x509_crl *prot_crls;
    mbedtls_pk_context *prot_key;
    mbedtls_x509_crt *prot_cert;
    mbedtls_x509_crt *prot_chain;

    /* enrollment */
    mbedtls_x509_crt *enrol_trust_anchor;
    mbedtls_x509_crl *enrol_crls;
    mbedtls_pk_context *new_key;
    mbedtls_x509_crt *new_cert;

} cmp_ctx;

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
int cmp_ctx_init(cmp_ctx *ctx, mbedtls_ctr_drbg_context *ctr_drbg,
                 void *cb_context, cmp_send_receive_cb send_receive_func,
                 int popo_method, int prot_md_alg, int popo_md_alg);
/**
 * \brief           Free the contents of a cmpctx write context
 *
 * \param ctx       cmpctx context to free
 */
void cmp_ctx_free(cmp_ctx *ctx);

/**
 * \brief           Set the MD algorithm used to protect the PKIMessage
 *
 * \param ctx       CMP context
 * \param md_alg    MD algorithm to use
 */
void cmp_ctx_set_sig_prot_md_alg(cmp_ctx *ctx, mbedtls_md_type_t md_alg);

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
 * \brief           Set the messageTime
 *                  Timestamps should be in string format for UTC timezone
 *                  i.e. "YYYYMMDDhhmmss"
 *                  e.g. "20131231235959" for December 31st 2013
 *                       at 23:59:59
 *
 * \param ctx       CMP context to use
 * \param msgTime   messageTime timestamp
 *
 * \return          0 if timestamp was parsed successfully, or
 *                  a specific error code
 */
int cmp_ctx_set_messageTime(cmp_ctx *ctx, const char *msgTime);

/**
 * \brief           Set the transactionID to be included
 *
 * \param ctx       CMP context
 * \param len       length in bytes (typically 16 bytes)
 */
int cmp_ctx_set_transactionID(cmp_ctx *ctx,
                              size_t len);

/**
 * \brief           Set the SenderNonce to be included
 * bodytype
 * \param ctx       CMP context
 * \param len       length in bytes (typically 16 bytes)
 */
int cmp_ctx_set_senderNonce(cmp_ctx *ctx,
                            size_t len);

/**
 * \brief           Set the recipNonce to be included
 *
 * \param ctx       CMP context
 * \param nonce     recip nonce
 * \param len       length in bytes (typically 16 bytes)
 */
int cmp_ctx_set_recipNonce(cmp_ctx *ctx, unsigned char *nonce, size_t len);

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
 * \brief           Set the flag to allow unprotected negative responses
 *
 * \param ctx       CMP context
 * \param allow     flag
 */
void cmp_ctx_set_unprotected_errors(cmp_ctx *ctx, int allow);

#define CMP_CTX_POPO_RAVERIFIED       0
#define CMP_CTX_POPO_SIGNATURE        1
#define CMP_CTX_POPO_KEYENCIPHERMENT  2
#define CMP_CTX_POPO_KEYAGREEMENT     3

/**
 * \brief           Set the POPO Method to use
 *
 * \param ctx       CMP context
 * \param popo_method popo_method to use
 */
void cmp_ctx_set_popo_method(cmp_ctx *ctx, int popo_method);

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
void cmp_ctx_set_prot_crls(cmp_ctx *ctx, mbedtls_x509_crl *crl);

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
void cmp_ctx_set_enrol_crls(cmp_ctx *ctx, mbedtls_x509_crl *crl);

/**
 * \brief           Set the hash algorithm for POPO
 *
 * \param ctx       CMP context
 * \param popo_method popo_method to use
 */
void cmp_ctx_set_popo_md_alg(cmp_ctx *ctx, mbedtls_md_type_t md_alg);

/**
 * \brief           Set the PBM parameter
 *                  Consumes the pointer
 *
 * \param ctx       CMP context
 * \param pbmp      PBM Parameter to use
 */
void cmp_ctx_set_pbmp(cmp_ctx *ctx, cmp_PBMParameter *pbmp);

/**
 * \brief           Set the next bodytype to send (e.g. IR)
 *
 * \param ctx       CMP context
 * \param next_body bodytype to use for next written msg
 */
void cmp_ctx_set_body_type(cmp_ctx *ctx, int next_body);

/**
 * \brief           Set whether to use implicitConfirm
 *
 * \param ctx       CMP context
 * \param ic        0=false, 1=true
 */
void cmp_ctx_set_implicit_confirm(cmp_ctx *ctx, int ic);

/**
 * \brief           Set failInfo in certConf
 * \param ctx       CMP context
 * \param fail_info CMP_PKIFAILINFO_* to add
 *
 */
void cmp_ctx_set_failinfo(cmp_ctx *ctx, int fail_info);

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
void cmp_ctx_set_cache_extracerts(cmp_ctx *ctx, int cache);

/**
 * \brief           Set whether to send unprotected ir or not
 *
 * \param ctx       CMP context
 * \param unprot    0=false, 1=true
 */
void cmp_ctx_set_unprotected_ir(cmp_ctx *ctx, int unprot);

/* **************************************************************** */
/* CMP transactions */
/* **************************************************************** */

/**
 * \brief initate a CMP transaction
 * \param ctx parameter context to use
 * \param body_type IR, CR or KUR
 */
int cmpcl_do_transaction(cmp_ctx *ctx, const int body_type);



/* **************************************************************** */
/* CMP helpers */
/* **************************************************************** */
/**
 * \brief allocate bytestring and fill it with random bytes
 * \param str new allocated string, will be freed before if not NULL
 * \param str_len length of allocated string
 * \param ctr_drbg CTR_DRBG context used for random byte generation
 * \param len required length of random string
 */
int cmp_ctx_set_rndm_str(unsigned char **str, size_t *str_len,
                         mbedtls_ctr_drbg_context *ctr_drbg, size_t len);
/*
 * \brief Custom wrapper for mbedtls_x509_crt_verify_with_profile()
 *
 * Verify the certificate validity, with built-in custom profile
 *
 * This function:
 *  - checks the requested CN (if any)
 *  - checks the type and size of the EE cert's key,
 *    as that isn't done as part of chain building/verification currently
 *  - builds and verifies the chain
 *
 *  \param crt certificate to verify
 *  \param trust_ca truted certificates
 *  \param ca_crl CRLs to use
 *  \param exp_name expected subject name or NULL
 *  \return negative value in case of error
 */

int cmp_x509_crt_verify(mbedtls_x509_crt *crt,
                        mbedtls_x509_crt *trust_ca,
                        mbedtls_x509_crl *ca_crl,
                        mbedtls_x509_name *exp_name);



#ifdef __cplusplus
}
#endif

#endif /* cmpcl.h */
