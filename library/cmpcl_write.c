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


#include "cmpcl_int.h"

/*
 * TODO defined in x509_internal.h, but not exported
 */

int mbedtls_x509_write_sig(unsigned char **p, unsigned char *start,
                           const char *oid, size_t oid_len,
                           unsigned char *sig, size_t size,
                           mbedtls_pk_type_t pk_alg);

int mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                             mbedtls_asn1_named_data *first);


/* **************************************************************** */
int cmpcl_CMPwrite_CertConfCont_der(unsigned char **p,
                                    unsigned char *start, cmp_ctx *ctx)
{
    int ret = 0;
    size_t len = 0;
    size_t hash_len;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];

    /*
     * CertConfirmContent ::= SEQUENCE OF CertStatus
     *
     *    CertStatus ::= SEQUENCE {
     *       certHash    OCTET STRING,
     *       certReqId   INTEGER,
     *       statusInfo  PKIStatusInfo OPTIONAL
     *    }
     */

    /* statusInfo  PKIStatusInfo OPTIONAL
     *
     *  PKIStatusInfo ::= SEQUENCE {
     *      status        PKIStatus,
     *      statusString  PKIFreeText     OPTIONAL,
     *      failInfo      PKIFailureInfo  OPTIONAL
     *  }
     */

    /* failInfo      PKIFailureInfo  OPTIONAL
     * -- MUST be present if status is "rejection"
     * -- MUST be absent if the status is "accepted"
     *
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
    if (ctx->cert_conf_fail_info != 0) {
        CMPCL_ASN1_CHK_ADD(len,
                           mbedtls_asn1_write_bitstring(p, start,
                                                        (unsigned char *) &ctx->cert_conf_fail_info,
                                                        26));
    }


    /* statusString  PKIFreeText     OPTIONAL
     * -- MAY be any human-readable text for debugging or logging
     */


    /* status        PKIStatus        REQUIRED (Lightweight Industrial CMP Profile)
     * -- positive values allowed: "accepted"
     * -- negative values allowed: "rejection"
     */

    /* PKIStatus ::= INTEGER */
    CMPCL_ASN1_CHK_ADD(len,
                       mbedtls_asn1_write_int(p, start,
                                              ctx->cert_conf_fail_info ? CMP_PKISTATUS_REJECTION :
                                              CMP_PKISTATUS_ACCEPTED));

    /* PKIStatusInfo ::= SEQUENCE */
    CMPCL_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    CMPCL_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                   MBEDTLS_ASN1_SEQUENCE));


    /* certReqId   INTEGER, */
    CMPCL_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(p, start, ctx->certReqId));

    /*
     * certHash    OCTET STRING,
     *  -- the hash of the certificate, using the same hash algorithm
     *  -- as is used to create and verify the certificate signature
     */
    CMPCL_ASN1_CHK_ADD(ret,
                       mbedtls_md(mbedtls_md_info_from_type(ctx->new_cert->MBEDTLS_PRIVATE(sig_md)),
                                  ctx->new_cert->raw.p, ctx->new_cert->raw.len, hash));

    hash_len =
        mbedtls_md_get_size(mbedtls_md_info_from_type(ctx->new_cert->MBEDTLS_PRIVATE(sig_md)));

    CMPCL_ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string(p, start, hash, hash_len));


    /* CertStatus ::= SEQUENCE */
    CMPCL_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    CMPCL_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                   MBEDTLS_ASN1_SEQUENCE));

    /* CertConfirmContent ::= SEQUENCE OF CertStatus */
    CMPCL_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    CMPCL_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                   MBEDTLS_ASN1_SEQUENCE));

err:
    return (int) len;
}


/* **************************************************************** */
int cmpcl_CRMFwrite_CertReqMessages_der(unsigned char **p, unsigned char *start,
                                        cmp_ctx *ctx)
{
    int ret = 0;
    size_t len = 0;

    unsigned char *saved_p = NULL;
    int popo_input_len = 0;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];

    const char *sig_oid = NULL;
    size_t sig_oid_len = 0;
    unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
    size_t sig_and_oid_len = 0;
    size_t sig_len = 0;
    mbedtls_pk_type_t pk_alg = { 0 };

    memset(sig, 0, sizeof(sig));
    memset(hash, 0, sizeof(hash));

    /* regInfo   SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue OPTIONAL */


    /* Popo */


    switch (ctx->popo_method) {
        case CMP_CTX_POPO_RAVERIFIED:
            CMPCL_ASN1_CHK_ADD(len, mbedtls_asn1_write_null(p, start));
            len--; /* -1 is as we're intentionally overwriting the SEQUENCE TAG from the function for IMPLICIT */
            (*p)++;   /* +1 is as we're intentionally overwriting the SEQUENCE TAG from the function for IMPLICIT */
            CMPCL_ASN1_CHK_ADD(len,
                               mbedtls_asn1_write_tag(p, start,
                                                      MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                      MBEDTLS_ASN1_CONSTRUCTED |
                                                      0 /* raVerified */));
            break;
        case CMP_CTX_POPO_SIGNATURE:
            /*
             * save old output buffer state, use buffer for POPO calculation
             */
            saved_p = *p;

            /*
             * cmpcl_CRMFwrite_CertRequest_der() called just to get input for popo
             */
            CMPCL_ASN1_CHK_ADD(popo_input_len,
                               cmpcl_CRMFwrite_CertRequest_der(p, start, ctx));

            /* create hash of popo_input */
            CMPCL_ASN1_CHK_ADD(ret,
                               mbedtls_md(mbedtls_md_info_from_type(ctx->popo_md_alg), *p,
                                          popo_input_len, hash));

            CMPCL_ASN1_CHK_ADD(ret,
                               mbedtls_pk_sign(ctx->new_key, ctx->popo_md_alg, hash, 0, sig,
                                               MBEDTLS_MPI_MAX_SIZE,
                                               &sig_len));
            /*
             * restore output buffer state
             */
            *p = saved_p;
            /*
             * Write data to output buffer
             */
            pk_alg = mbedtls_pk_get_type(ctx->new_key);
            if (pk_alg == MBEDTLS_PK_ECKEY) {
                pk_alg = MBEDTLS_PK_ECDSA;
            }
            if ((ret =
                     mbedtls_oid_get_oid_by_sig_alg(pk_alg, ctx->popo_md_alg, &sig_oid,
                                                    &sig_oid_len)) != 0) {
                CMPERRS("ERROR getting OID\n");
            }

            CMPCL_ASN1_CHK_ADD(sig_and_oid_len,
                               mbedtls_x509_write_sig(p, start, sig_oid, sig_oid_len, sig, sig_len,
                                                      pk_alg));
            len += sig_and_oid_len;

            CMPCL_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, sig_and_oid_len));
            CMPCL_ASN1_CHK_ADD(len,
                               mbedtls_asn1_write_tag(p, start,
                                                      MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                      MBEDTLS_ASN1_CONSTRUCTED |
                                                      1 /* signature */));

            break;
        /* TODO: maybe add further POP methods: keyEncipherment, keyAgreement */
        default:
            CMPERRV("POPO method %d not supported", ctx->popo_method);
            len = CMPCL_ERR_POPO_METHOD;
            goto err;
    }

    /* Cert Request */
    CMPCL_ASN1_CHK_ADD(len, cmpcl_CRMFwrite_CertRequest_der(p, start, ctx));

    /*
     * CertReqMsg ::= SEQUENCE
     */
    CMPCL_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    CMPCL_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                   MBEDTLS_ASN1_SEQUENCE));
    /* CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_tag(p, start,
                                                MBEDTLS_ASN1_CONSTRUCTED |
                                                MBEDTLS_ASN1_SEQUENCE));

err:
    return (int) len;
}


/* **************************************************************** */
/* RFC4211 SECTION 5:  CertRequest
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
 */

int cmpcl_CRMFwrite_CertRequest_der(unsigned char **p, unsigned char *start,
                                    cmp_ctx *ctx)
{
    int ret;
    size_t len = 0;
    size_t ctrl_len = 0; /* controls */
    size_t subj_len = 0;
    size_t pub_len = 0;
    size_t tmpl_len = 0; /* template length */

    /* Controls
     * Controls ::= SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue
     *
     * AttributeTypeAndValue ::= SEQUENCE {
     * type OBJECT IDENTIFIER,
     * value ANY DEFINED BY type }
     */

    /*
     * id-regCtrl-oldCertID OBJECT IDENTIFIER ::= { id-regCtrl 5 }
     * CertId ::= SEQUENCE {
     *  issuer GeneralName,
     *  serialNumber INTEGER
     * }
     */

    if ((ctx->body_type == MBEDTLS_CMP_PKIBODY_KUR)) {
        if (ctx->prot_cert == NULL) {
            CMPERRS("No client cert provided; KUR ONLY with OldCert!");
            return CMPCL_ERR_KUR_OLDCERT;
        }
        CMPDBGS("Include OldCertId")
        /* oldCertId */

        /* serialNumber INTEGER */
        MBEDTLS_ASN1_CHK_ADD(ctrl_len,
                             mbedtls_asn1_write_raw_buffer(p, start, ctx->prot_cert->serial.p,
                                                           ctx->prot_cert->serial.len));
        MBEDTLS_ASN1_CHK_ADD(ctrl_len,
                             mbedtls_asn1_write_len(p, start, ctx->prot_cert->serial.len));
        MBEDTLS_ASN1_CHK_ADD(ctrl_len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_INTEGER));
        int ser_len = ctrl_len;

        /*  issuer GeneralName */
        MBEDTLS_ASN1_CHK_ADD(ctrl_len,
                             mbedtls_asn1_write_raw_buffer(p, start, ctx->prot_cert->issuer_raw.p,
                                                           ctx->prot_cert->issuer_raw.len));
        /* clCert->issuer_raw is already DER encoded with tag and length */

        /* TODO: find out why this tag is necessary */
        MBEDTLS_ASN1_CHK_ADD(ctrl_len, mbedtls_asn1_write_len(p, start, ctrl_len - ser_len));
        MBEDTLS_ASN1_CHK_ADD(ctrl_len,
                             mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    MBEDTLS_ASN1_CONSTRUCTED | 4));

        /* CertId ::= SEQUENCE */
        MBEDTLS_ASN1_CHK_ADD(ctrl_len, mbedtls_asn1_write_len(p, start, ctrl_len));
        MBEDTLS_ASN1_CHK_ADD(ctrl_len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                              MBEDTLS_ASN1_SEQUENCE));
        /* type OBJECT IDENTIFIER */
#define OLD_CERT_ID_OID "\x2B\x06\x01\x05\x05\x07\x05\x01\x05" /* 1.3.6.1.5.5.7.5.1.5 */
        MBEDTLS_ASN1_CHK_ADD(ctrl_len,
                             mbedtls_asn1_write_oid(p, start, OLD_CERT_ID_OID,
                                                    strlen(OLD_CERT_ID_OID)));

        /* AttributeTypeAndValue ::= SEQUENCE */
        MBEDTLS_ASN1_CHK_ADD(ctrl_len, mbedtls_asn1_write_len(p, start, ctrl_len));
        MBEDTLS_ASN1_CHK_ADD(ctrl_len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                              MBEDTLS_ASN1_SEQUENCE));

    }
    /*
       Controls ::= SEQUENCE
     */

    MBEDTLS_ASN1_CHK_ADD(ctrl_len, mbedtls_asn1_write_len(p, start, ctrl_len));
    MBEDTLS_ASN1_CHK_ADD(ctrl_len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                          MBEDTLS_ASN1_SEQUENCE));
    len += ctrl_len;

    /* certTemplate */
    /*
       certTemplate  CertTemplate,  -- Selected fields of cert to be issued
     */

    /* extensions   [9] Extensions            OPTIONAL */
    /* subjectUID   [8] UniqueIdentifier      OPTIONAL */
    /* issuerUID    [7] UniqueIdentifier      OPTIONAL */


    /* publicKey    [6] SubjectPublicKeyInfo  OPTIONAL */
    if (ctx->new_key) {

        MBEDTLS_ASN1_CHK_ADD(pub_len, mbedtls_pk_write_pubkey_der(ctx->new_key, start, *p - start));
        pub_len -= 1; /* -1 is as we're intentionally overwriting the SEQUENCE TAG from the function for IMPLICIT */
        *p -= pub_len; /* mbedtls_pk_write_pubkey_der() did not update *p */
        MBEDTLS_ASN1_CHK_ADD(pub_len,
                             mbedtls_asn1_write_tag(p, start,
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    MBEDTLS_ASN1_CONSTRUCTED |
                                                    6 /* SubjectPublicKeyInfo */));
        tmpl_len += pub_len;
    }

    /* subject      [5] Name                  OPTIONAL */
    if (ctx->subject) {
        MBEDTLS_ASN1_CHK_ADD(subj_len, mbedtls_x509_write_names(p, start, ctx->subject));
        MBEDTLS_ASN1_CHK_ADD(subj_len, mbedtls_asn1_write_len(p, start, subj_len));
        MBEDTLS_ASN1_CHK_ADD(subj_len,
                             mbedtls_asn1_write_tag(p, start,
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    MBEDTLS_ASN1_CONSTRUCTED | 5));
        tmpl_len += subj_len;
    }

    /* validity     [4] OptionalValidity      OPTIONAL */
    /* issuer       [3] Name                  OPTIONAL */
    /* signingAlg   [2] AlgorithmIdentifier   OPTIONAL */
    /* serialNumber [1] INTEGER               OPTIONAL */
    /* version      [0] Version               OPTIONAL */


    /*
       CertTemplate ::= SEQUENCE
     */
    MBEDTLS_ASN1_CHK_ADD(tmpl_len, mbedtls_asn1_write_len(p, start, tmpl_len));
    MBEDTLS_ASN1_CHK_ADD(tmpl_len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                          MBEDTLS_ASN1_SEQUENCE));
    len += tmpl_len;
    /*
       certReqId     INTEGER,          -- ID for matching request and reply
     */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(p, start, ctx->certReqId));

    /*
     * CertRequest ::= SEQUENCE
     */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}


/* **************************************************************** */
/* DER-writing functions */
/* **************************************************************** */

static int msg_sig_alg_prot(cmp_ctx *ctx,
                            const unsigned char *input,
                            size_t in_len,
                            unsigned char *sig,
                            size_t *sig_len)
{
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    int hash_len = 0;

    hash_len = mbedtls_md(mbedtls_md_info_from_type(ctx->sig_prot_md_alg), input, in_len, hash);

    return mbedtls_pk_sign(ctx->prot_key,
                           ctx->sig_prot_md_alg,
                           hash,
                           hash_len,
                           sig,
                           MBEDTLS_MPI_MAX_SIZE,
                           sig_len);
}

/* **************************************************************** */
int cmpcl_CMPwrite_PKIMessage_protection_der(unsigned char **p,
                                             unsigned char *start,
                                             cmp_ctx *ctx,
                                             const unsigned char *input,
                                             const size_t in_len)
{
    int ret;
    size_t len = -1;
    unsigned char prot[MBEDTLS_MPI_MAX_SIZE];
    size_t prot_len = 0;


    memset(prot, 0, sizeof(prot));

    if (ctx->prot_secret && ctx->pbmp) { /* MSG_MAC_ALG */
        if ((ret = cmp_PBM_new(ctx->pbmp,
                               ctx->prot_secret,
                               ctx->secret_len,
                               input,
                               in_len,
                               prot,
                               &prot_len)) != 0) {
            goto err;
        }
    } else if (ctx->prot_key && ctx->sig_prot_md_alg) {/* MSG_SIG_ALG */
        if ((ret = msg_sig_alg_prot(ctx,
                                    input,
                                    in_len,
                                    prot,
                                    &prot_len)) != 0) {
            goto err;
        }
    } else {
        CMPWARNS("No credentials for protection. Message unprotected!");
        return 0;
    }

    if (*p < start || (size_t) (*p - start) < prot_len) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    len = prot_len;
    (*p) -= len;
    memcpy(*p, prot, len);

    if (*p - start < 1) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    *--(*p) = 0;
    len += 1;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_BIT_STRING));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_tag(p, start,
                                                MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                MBEDTLS_ASN1_CONSTRUCTED | 0));

err:
    return (int) len;
}

static int mbedtls_asn1_buf_cmp(mbedtls_asn1_buf *buf1, mbedtls_asn1_buf *buf2)
{
    if (buf1 == NULL && buf2 == NULL) {
        return 0;
    }
    if (buf1 == NULL) {
        return -1;
    }
    if (buf2 == NULL) {
        return 1;
    }
    if (buf1->len != buf2->len) {
        return buf1->len - buf2->len;
    }
    return memcmp(buf1->p, buf2->p, buf1->len);
}

static int same_cert(mbedtls_x509_crt *crt1, mbedtls_x509_crt *crt2)
{
    if (crt1 == NULL || crt2 == NULL) {
        return crt1 == crt2;
    }
    return mbedtls_asn1_buf_cmp(&crt1->serial, &crt2->serial) == 0 &&
           mbedtls_asn1_buf_cmp(&crt1->issuer_raw, &crt2->issuer_raw) == 0;
}

static size_t cmpcl_CMPwrite_ExtraCerts_der(unsigned char **p,
                                            unsigned char *start,
                                            cmp_ctx *ctx)
{
    int ret = 0;
    int len = 0;
    mbedtls_x509_crt *crt = ctx->prot_chain;
    /*
     * ir, cr, kur and rr are posible initial ReqMessages for one transaction.
     * In case of no initial ReqMessage and cache_extracerts flag set,
     * no further transmit of extra certs is needed.
     */
    if (ctx->cache_extracerts == 0 ||
        ctx->body_type == MBEDTLS_CMP_PKIBODY_IR ||
        ctx->body_type == MBEDTLS_CMP_PKIBODY_CR ||
        ctx->body_type == MBEDTLS_CMP_PKIBODY_KUR ||
        ctx->body_type == MBEDTLS_CMP_PKIBODY_RR) {
        while (crt) {
            if (mbedtls_asn1_buf_cmp(&crt->issuer_raw, &crt->subject_raw) != 0 &&
                !same_cert(crt, ctx->prot_cert)) {
                MBEDTLS_ASN1_CHK_ADD(len,
                                     mbedtls_asn1_write_raw_buffer(p, start, crt->raw.p,
                                                                   crt->raw.len));
            }
            crt = crt->next;
        }
        if (ctx->prot_cert) {
            MBEDTLS_ASN1_CHK_ADD(len,
                                 mbedtls_asn1_write_raw_buffer(p, start, ctx->prot_cert->raw.p,
                                                               ctx->prot_cert->raw.len));
        }
    }
    if (len > 0) {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(p, start,
                                                    MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE));

        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(p, start,
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    MBEDTLS_ASN1_CONSTRUCTED | 1));
    }
    return len;
}


/* **************************************************************** */
int cmpcl_CMPwrite_PKIMessage_der(unsigned char **p, unsigned char *start,
                                  cmp_ctx *ctx, int unprotected)
{
    int ret;
    size_t len = 0;
    size_t extraCerts_len = 0;
    size_t prot_len = 0;
    size_t body_len = 0;
    size_t header_len = 0;
    size_t payload_len = 0;
    size_t protPart_len = 0;
    unsigned char *header_start = NULL;
    unsigned char *extra_certs_start = NULL;
    unsigned char *protected_part_start = NULL;

    /*
     * PKIMessage ::= SEQUENCE {
     *  header              PKIHeader,
     *  body                PKIBody,
     *  protection  [0]     PKIProtection                               OPTIONAL,
     *  extraCerts  [1]     SEQUENCE SIZE (1..MAX) OF CMPCertificate    OPTIONAL }
     *
     * PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage
     *
     * NOTE: buffer below is filled backwards
     */

    /*
     * extraCerts    [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate }    OPTIONAL
     */
    MBEDTLS_ASN1_CHK_ADD(extraCerts_len, cmpcl_CMPwrite_ExtraCerts_der(p, start, ctx));
    extra_certs_start = *p;

    // temporarily reserve max room for protection
    (*p) -= (MBEDTLS_MPI_MAX_SIZE+100);


    switch (ctx->body_type) {
        case MBEDTLS_CMP_PKIBODY_IR:
        case MBEDTLS_CMP_PKIBODY_CR:
        case MBEDTLS_CMP_PKIBODY_KUR:
            /* Adding one *single* CertReqest here */
            MBEDTLS_ASN1_CHK_ADD(body_len, cmpcl_CRMFwrite_CertReqMessages_der(p, start, ctx));
            break;
        case MBEDTLS_CMP_PKIBODY_PKICONF: /* the client does not need to send that - but easiest for first testing ;-) */
            MBEDTLS_ASN1_CHK_ADD(body_len, mbedtls_asn1_write_null(p, start));
            break;
        case MBEDTLS_CMP_PKIBODY_CERTCONF:
            MBEDTLS_ASN1_CHK_ADD(body_len, cmpcl_CMPwrite_CertConfCont_der(p, start, ctx));
            break;
        default:
            CMPERRV("NOT SUPPORTED PKIBody_type %d\n", ctx->body_type);
            return CMPCL_ERR_UNSUPPORTED_BODYTYPE;
    }

    /* [x] */
    MBEDTLS_ASN1_CHK_ADD(body_len, mbedtls_asn1_write_len(p, start, body_len));
    MBEDTLS_ASN1_CHK_ADD(body_len,
                         mbedtls_asn1_write_tag(p, start,
                                                MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                MBEDTLS_ASN1_CONSTRUCTED | ctx->body_type));


    /*
     *   header           PKIHeader
     */
    MBEDTLS_ASN1_CHK_ADD(header_len, cmpcl_CMPwrite_PKIHeader_der(p, start, ctx, unprotected));

    /* temporary sequence TL for calculating the protection
        ProtectedPart ::= SEQUENCE {
            header    PKIHeader,
            body      PKIBody
        }
     */

    /*
     * header and body are written now --> save current pos & prot_len as input for protection
     */
    payload_len = header_len + body_len;
    protPart_len = payload_len;
    header_start = *p;

    /**
     * write protected part sequence
     */
    MBEDTLS_ASN1_CHK_ADD(protPart_len, mbedtls_asn1_write_len(p, start, payload_len));
    MBEDTLS_ASN1_CHK_ADD(protPart_len,
                         mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                MBEDTLS_ASN1_SEQUENCE));

    protected_part_start = *p;

    if (!unprotected) {     /* start setting protection */
        MBEDTLS_ASN1_CHK_ADD(prot_len, cmpcl_CMPwrite_PKIMessage_protection_der(&extra_certs_start,
                                                                                start,
                                                                                ctx,
                                                                                protected_part_start,
                                                                                protPart_len));
    }
    *p = extra_certs_start - payload_len;
    memcpy(*p, header_start, payload_len);

    /* total message length */
    len = payload_len + prot_len + extraCerts_len;
    /* write over the temporary sequence TL
     * PKIMessage ::= SEQUENCE
     */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    return (int) len;
}

/* **************************************************************** */
static int cmpcl_CMPwrite_PBMParameter_der(unsigned char **p, unsigned char *start,
                                           cmp_PBMParameter *pbmp)
{
    /*
       PBMParameter ::= SEQUENCE {
         salt                OCTET STRING,
         owf                 AlgorithmIdentifier,
         iterationCount      INTEGER,
         mac                 AlgorithmIdentifier
         )
     */

    int ret;
    size_t len = 0;
    size_t sub_len = 0;
    const char *oid;
    size_t oid_len = 0;

    /* mac AlgorithmIdentifier */

#define setoid(_oid) { oid = _oid; oid_len = sizeof(_oid)-1; break; }

    switch (pbmp->mac) {
        case MBEDTLS_MD_RIPEMD160: setoid(MBEDTLS_OID_HMAC_RIPEMD160);
        case MBEDTLS_MD_SHA1: setoid(RFC4210_HMAC_SHA1_OID);
        case MBEDTLS_MD_SHA224: setoid(MBEDTLS_OID_HMAC_SHA224);
        case MBEDTLS_MD_SHA256: setoid(MBEDTLS_OID_HMAC_SHA256);
        case MBEDTLS_MD_SHA384: setoid(MBEDTLS_OID_HMAC_SHA384);
        case MBEDTLS_MD_SHA512: setoid(MBEDTLS_OID_HMAC_SHA512);
        case MBEDTLS_MD_SHA3_224: setoid(MBEDTLS_OID_HMAC_SHA3_224);
        case MBEDTLS_MD_SHA3_256: setoid(MBEDTLS_OID_HMAC_SHA3_256);
        case MBEDTLS_MD_SHA3_384: setoid(MBEDTLS_OID_HMAC_SHA3_384);
        case MBEDTLS_MD_SHA3_512: setoid(MBEDTLS_OID_HMAC_SHA3_384);
        default:
            return -1;
    }
#undef setoid

    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_algorithm_identifier(p, start, oid, strlen(oid),
                                                                 0));

    //MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( p, start, HMAC_SHA256_OID, strlen( HMAC_SHA256_OID), 0 ) );

    /* iterationCount      INTEGER, */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(p, start, pbmp->iterationCount));

    /* owf                 AlgorithmIdentifier, */
    if ((ret = mbedtls_oid_get_oid_by_md(pbmp->owf, &oid, &oid_len)) != 0) {
        return ret;
    }

    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_algorithm_identifier(p, start, oid, strlen(oid),
                                                                 0));

    /* salt                OCTET STRING, */
    sub_len = 0;
    MBEDTLS_ASN1_CHK_ADD(sub_len,
                         mbedtls_asn1_write_raw_buffer(p, start, pbmp->salt, pbmp->salt_len));
    len += sub_len;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, sub_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OCTET_STRING));

    /* PBMParameter ::= SEQUENCE { */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    return len;
}


/* **************************************************************** */

int cmpcl_CMPwrite_PKIHeader_der(unsigned char **p, unsigned char *start,
                                 cmp_ctx *ctx, int unprotected)
{
    int ret;
    const char *sig_oid;
    size_t sig_oid_len = 0;
    size_t len = 0;
    size_t sub_len = 0;

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

    /*
         generalInfo     [8] SEQUENCE SIZE (1..MAX) OF InfoTypeAndValue     OPTIONAL
         this field contains implicitConfirm

         implicitConfirm OBJECT IDENTIFIER ::= {id-it 13}
          ImplicitConfirmValue ::= NULL
     */

    if (ctx->implicitConfirm) {
        sub_len = 0;
        size_t par_len = 0;
        MBEDTLS_ASN1_CHK_ADD(par_len, mbedtls_asn1_write_null(p, start));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_algorithm_identifier(
                                 p, start, IMPLICITCONFIRM_OID,
                                 strlen(IMPLICITCONFIRM_OID), par_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_tag(p, start,
                                                             MBEDTLS_ASN1_CONSTRUCTED |
                                                             MBEDTLS_ASN1_SEQUENCE));

        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_tag(p, start,
                                                             MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                             MBEDTLS_ASN1_CONSTRUCTED | 8));
        len += sub_len;
    }
    /*
         freeText        [7] PKIFreeText             OPTIONAL,
         PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
     */

    /*
         recipNonce      [6] OCTET STRING            OPTIONAL,
     */
    if (ctx->recipNonce) {
        sub_len = 0;
        MBEDTLS_ASN1_CHK_ADD(sub_len,
                             mbedtls_asn1_write_raw_buffer(p, start, ctx->recipNonce,
                                                           ctx->recipNonce_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OCTET_STRING));
        len += sub_len;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(p, start,
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    MBEDTLS_ASN1_CONSTRUCTED | 6));
    }
    /*
         senderNonce     [5] OCTET STRING            OPTIONAL,
     */
    if (ctx->senderNonce) {
        sub_len = 0;
        MBEDTLS_ASN1_CHK_ADD(sub_len,
                             mbedtls_asn1_write_raw_buffer(p, start, ctx->senderNonce,
                                                           ctx->senderNonce_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OCTET_STRING));
        len += sub_len;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(p, start,
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    MBEDTLS_ASN1_CONSTRUCTED | 5));
    }

    /*
         transactionID   [4] OCTET STRING            OPTIONAL,
     */
    if (ctx->transactionID) {
        sub_len = 0;
        MBEDTLS_ASN1_CHK_ADD(sub_len,
                             mbedtls_asn1_write_raw_buffer(p, start, ctx->transactionID,
                                                           ctx->transactionID_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OCTET_STRING));
        len += sub_len;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(p, start,
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    MBEDTLS_ASN1_CONSTRUCTED | 4));
    }
    /*
         recipKID        [3] KeyIdentifier           OPTIONAL,
     */

    /*
         senderKID       [2] KeyIdentifier           OPTIONAL,
     */

    if (ctx->prot_cert != NULL && ctx->prot_cert->subject_key_id.p != NULL) {
        if ((ret =
                 cmp_ctx_set_senderKID(ctx, ctx->prot_cert->subject_key_id.p,
                                       ctx->prot_cert->subject_key_id.len))) {
            return ret;
        }
    }
    if (ctx->senderKID) {
        sub_len = 0;
        MBEDTLS_ASN1_CHK_ADD(sub_len,
                             mbedtls_asn1_write_raw_buffer(p, start, ctx->senderKID,
                                                           ctx->reference_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OCTET_STRING));
        len += sub_len;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(p, start,
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    MBEDTLS_ASN1_CONSTRUCTED | 2));
    }

    /*
         protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
     */
    if (unprotected) {
        /* no protection */
    } else if (ctx->prot_key /* && ctx->sig_prot_md_alg */) {
        mbedtls_pk_type_t pk_alg;
        pk_alg = mbedtls_pk_get_type(ctx->prot_key);
        if (pk_alg == MBEDTLS_PK_ECKEY) {
            pk_alg = MBEDTLS_PK_ECDSA;
        }

        if ((ret =
                 mbedtls_oid_get_oid_by_sig_alg(pk_alg, ctx->sig_prot_md_alg, &sig_oid,
                                                &sig_oid_len)) != 0) {
            return ret;
        }

        sub_len = 0;
        MBEDTLS_ASN1_CHK_ADD(sub_len,
                             mbedtls_asn1_write_algorithm_identifier(p, start, sig_oid,
                                                                     strlen(sig_oid), 0));
        len += sub_len;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(p, start,
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    MBEDTLS_ASN1_CONSTRUCTED | 1));
    } else if (ctx->prot_secret && ctx->pbmp) { /* PBM */
        /*
           id-PasswordBasedMAC OBJECT IDENTIFIER ::= { 1 2 840 113533 7 66 13} */
        size_t par_len = 0;
        MBEDTLS_ASN1_CHK_ADD(par_len, cmpcl_CMPwrite_PBMParameter_der(p, start, ctx->pbmp));

        sub_len = 0;

/* PBM OID defined in cmpcl_int.h
 * HARDCODED as it is not defined in mbedtls */
        MBEDTLS_ASN1_CHK_ADD(sub_len,
                             mbedtls_asn1_write_algorithm_identifier(p, start, PBM_OID,
                                                                     strlen(PBM_OID), par_len));
        len += sub_len;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(p, start,
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    MBEDTLS_ASN1_CONSTRUCTED | 1));
    } else {
        CMPERRS("No protection credentials configured!");
    }

    /*
         messageTime     [0] GeneralizedTime         OPTIONAL,
     */
    if (ctx->messageTime) {
        sub_len = 0;
        MBEDTLS_ASN1_CHK_ADD(sub_len,
                             mbedtls_asn1_write_raw_buffer(p, start,
                                                           (const unsigned char *) ctx->messageTime,
                                                           MBEDTLS_X509_RFC5280_UTC_TIME_LEN));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len,
                             mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_GENERALIZED_TIME));
        len += sub_len;
        /* [0] */
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(p, start,
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    MBEDTLS_ASN1_CONSTRUCTED | 0));
    }

    /*
         recipient           GeneralName,
     */
    sub_len = 0;
    MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_x509_write_names(p, start, ctx->recipient));
    len += sub_len;
    /* Explicit */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, sub_len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_tag(p, start,
                                                MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                MBEDTLS_ASN1_CONSTRUCTED |
                                                MBEDTLS_ASN1_OCTET_STRING));

    /*
         sender              GeneralName,
     */
    sub_len = 0;
    MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_x509_write_names(p, start, ctx->sender));
    len += sub_len;
    /* Explicit */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, sub_len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_tag(p, start,
                                                MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                MBEDTLS_ASN1_CONSTRUCTED |
                                                MBEDTLS_ASN1_OCTET_STRING));

    /*
     *   pvno                INTEGER     { cmp1999(1), cmp2000(2) },
     */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(p, start, MBEDTLS_CMP_VERSION_2));

    /*
     * PKIHeader ::= SEQUENCE
     */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    return (int) len;
}
