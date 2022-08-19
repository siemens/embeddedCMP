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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "cmpcl_int.h"

#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/sha1.h"
#include "mbedtls/ecdsa.h" /* for MBEDTLS_ECDSA_MAX_LEN */

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_free       free
#define mbedtls_calloc     calloc
#define mbedtls_snprintf   snprintf
#endif


static size_t g_wr_len_header = 0;
static size_t g_wr_len_extraCerts = 0;
static size_t g_wr_n_extraCerts = 0;
static size_t g_wr_len_certTemplate = 0;
static size_t g_wr_len_popo = 0;
static size_t g_wr_prot_len = 0;


/* **************************************************************** */
int cmpcl_CMPwrite_CertConfCont_der( unsigned char **p,
        unsigned char *start, cmp_ctx *ctx)
{
    int ret;
    size_t len = 0;
    size_t hash_len;
    unsigned char *hash;

    /*
     * CertConfirmContent ::= SEQUENCE OF CertStatus
     *
     *    CertStatus ::= SEQUENCE {
     *       certHash    OCTET STRING,
     *       certReqId   INTEGER,
     *       statusInfo  PKIStatusInfo OPTIONAL
     *    }
     */

    hash = mbedtls_calloc(1, MBEDTLS_MD_MAX_SIZE);
    if (!hash) {
        len = -1;
        goto err;
    }

    /* only positive case implemented
     * TODO: check if cert should actually be accepted and
     *  implement appropriate negative certConf
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
    if( ctx->new_cert_fail_info != 0 )
        CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_bitstring(p, start, (unsigned char *) &ctx->new_cert_fail_info, 26 ), ret );


    /* statusString  PKIFreeText     OPTIONAL
     * -- MAY be any human-readable text for debugging or logging
     */


    /* status        PKIStatus        REQUIRED (Lightweight Industrial CMP Profile)
     * -- positive values allowed: "accepted"
     * -- negative values allowed: "rejection"
     */

    /* PKIStatus ::= INTEGER */
    CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_int(p, start, ctx->new_cert_fail_info ? CMP_PKISTATUS_REJECTION : CMP_PKISTATUS_ACCEPTED ), ret );

    /* PKIStatusInfo ::= SEQUENCE */
    CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_len(p, start, len ), ret );
    CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ), ret );


    /* certReqId   INTEGER, */
    CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_int(p, start, ctx->certReqId ), ret );

    /*
     * certHash    OCTET STRING,
     *  -- the hash of the certificate, using the same hash algorithm
     *  -- as is used to create and verify the certificate signature
     */
    /* TODO: how to best access the received cert? */
    CMPCL_ASN1_CHK_ADD( ret, mbedtls_md(mbedtls_md_info_from_type( ctx->new_cert->sig_md ),
            ctx->new_cert->raw.p, ctx->new_cert->raw.len, hash ), ret );

    hash_len = mbedtls_md_get_size(mbedtls_md_info_from_type( ctx->new_cert->sig_md ) );

    CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_octet_string(p, start, hash, hash_len), ret );


    /* CertStatus ::= SEQUENCE */
    CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_len(p, start, len ), ret );
    CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ), ret );

    /* CertConfirmContent ::= SEQUENCE OF CertStatus */
    CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_len(p, start, len ), ret );
    CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ), ret );

    err:
    mbedtls_free(hash);
    return( (int) len );
}


/* **************************************************************** */
int cmpcl_CRMFwrite_CertReqMsg_der( unsigned char **p, unsigned char *start,
                                      cmp_ctx *ctx)
{
    int ret;
    size_t len = 0;

    unsigned char *popo_input_buf;
    unsigned char *popo_input_p;
    int popo_input_len = 0;
    unsigned char *hash;

    const char *sig_oid;
    size_t sig_oid_len = 0;
    unsigned char *sig;
    size_t sig_and_oid_len = 0, sig_len;
    mbedtls_pk_type_t pk_alg;

#define POPO_INPUT_BUF_SIZE 1024 /* TODO: that is not overly effective, but what to do? */
    popo_input_buf = mbedtls_calloc(1, POPO_INPUT_BUF_SIZE);
    if (!popo_input_buf) {
        len = CMPCL_ERR_MEMORY_ALLOCATION;
        goto err;
    }

    sig = mbedtls_calloc(1, MBEDTLS_MPI_MAX_SIZE);
    if (!sig) {
        len = CMPCL_ERR_MEMORY_ALLOCATION;
        goto err;
    }

    hash = mbedtls_calloc(1, MBEDTLS_MD_MAX_SIZE);
    if (!hash) {
        len = CMPCL_ERR_MEMORY_ALLOCATION;
        goto err;
    }


    /* regInfo   SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue OPTIONAL */


    /* Popo */


    switch (ctx->popo_method) {
      case CMP_CTX_POPO_RAVERIFIED:
        CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_null( p, start ), len );
        len--; /* -1 is as we're intentionally overwriting the SEQUENCE TAG from the function for IMPLICIT */
        (*p)++;       /* +1 is as we're intentionally overwriting the SEQUENCE TAG from the function for IMPLICIT */
        CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start,
                MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 /* raVerified */ ), len );
        break;
      case CMP_CTX_POPO_SIGNATURE:
        /* TODO
           poposkInput contains the data to be signed, when present.  This
           field MUST be present when the certificate template does not
           contain both the public key value and a subject name value.

           So far this implements RFC4211 section 4.1.3 with omitted poposkInput
         */
        popo_input_p = popo_input_buf+POPO_INPUT_BUF_SIZE;

        /*
         * cmpcl_CRMFwrite_CertRequest_der() called just to get input for popo
         */
        CMPCL_ASN1_CHK_ADD( popo_input_len, cmpcl_CRMFwrite_CertRequest_der( &popo_input_p, popo_input_buf, ctx ), len );

        /* create hash of popo_input */
        CMPCL_ASN1_CHK_ADD(ret, mbedtls_md(mbedtls_md_info_from_type( ctx->popo_md_alg ), popo_input_p, popo_input_len, hash ), len);

        /* TODO the last parameters f_rng and p_rng need to come from outside for EC keys... */
        CMPCL_ASN1_CHK_ADD(ret, mbedtls_pk_sign( ctx->new_key, ctx->popo_md_alg, hash, 0, sig, &sig_len, NULL, NULL ), len);

        /*
         * Write data to output buffer
         */
        pk_alg = mbedtls_pk_get_type( ctx->new_key );
        if( pk_alg == MBEDTLS_PK_ECKEY )
          pk_alg = MBEDTLS_PK_ECDSA;
        if( ( ret = mbedtls_oid_get_oid_by_sig_alg( pk_alg, ctx->popo_md_alg, &sig_oid, &sig_oid_len ) ) != 0 )
          CMPERRS("ERROR getting OID\n");

        CMPCL_ASN1_CHK_ADD( sig_and_oid_len, mbedtls_x509_write_sig( p, start, sig_oid, sig_oid_len, sig, sig_len), len );
        len += sig_and_oid_len;
        g_wr_len_popo = sig_and_oid_len;


        CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sig_and_oid_len ), len );
        CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start,
                MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 /* signature */), len );

        break;
        /* TODO: maybe add further POP methods: keyEncipherment, keyAgreement */
      default:
        CMPERRV("POPO method %d not supported", ctx->popo_method);
        len = CMPCL_ERR_POPO_METHOD;
        goto err;
    }

    /* Cert Request */
    CMPCL_ASN1_CHK_ADD( len, cmpcl_CRMFwrite_CertRequest_der( p, start, ctx ), len );

    /*
     * CertReqMsg ::= SEQUENCE
     */
    CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ), len );
    CMPCL_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ), len );

err:
    /* cleanup */
    mbedtls_free(popo_input_buf);
    mbedtls_free(sig);
    mbedtls_free(hash);
    return( (int) len );
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

int cmpcl_CRMFwrite_CertRequest_der( unsigned char **p, unsigned char *start,
                                       cmp_ctx *ctx)
{
    int ret;
    size_t len = 0;
    size_t ctrl_len = 0; /* controls */
    size_t subj_len = 0;
    size_t pub_len = 0;
    size_t tmpl_len = 0; /* template length */


    /* TODO: check whether necessary fields are populated in context
     * TODO: add error handling     */

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

    if( (ctx->body_type == MBEDTLS_CMP_PKIBODY_KUR) ) {
        if( ctx->cl_cert == NULL) {
            CMPERRS("No client cert provided; KUR ONLY with OldCert!");
            return CMPCL_ERR_KUR_OLDCERT;
        }
//        CMPDBGS("Include OldCertId")
        /* oldCertId */

        /* serialNumber INTEGER */
        MBEDTLS_ASN1_CHK_ADD( ctrl_len, mbedtls_asn1_write_raw_buffer( p, start, ctx->cl_cert->serial.p, ctx->cl_cert->serial.len ) );
        MBEDTLS_ASN1_CHK_ADD( ctrl_len, mbedtls_asn1_write_len( p, start, ctx->cl_cert->serial.len ) );
        MBEDTLS_ASN1_CHK_ADD( ctrl_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_INTEGER ) );
        int ser_len = ctrl_len;

        /*  issuer GeneralName */
        MBEDTLS_ASN1_CHK_ADD( ctrl_len, mbedtls_asn1_write_raw_buffer( p, start, ctx->cl_cert->issuer_raw.p, ctx->cl_cert->issuer_raw.len ) );
        /* clCert->issuer_raw is already DER encoded with tag and length */

        /* TODO: find out why this tag is necessary */
        MBEDTLS_ASN1_CHK_ADD( ctrl_len, mbedtls_asn1_write_len( p, start, ctrl_len - ser_len ) );
        MBEDTLS_ASN1_CHK_ADD( ctrl_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                                MBEDTLS_ASN1_CONSTRUCTED | 4 ) );

        /* CertId ::= SEQUENCE */
        MBEDTLS_ASN1_CHK_ADD( ctrl_len, mbedtls_asn1_write_len( p, start, ctrl_len ) );
        MBEDTLS_ASN1_CHK_ADD( ctrl_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                           MBEDTLS_ASN1_SEQUENCE ) );
        /* type OBJECT IDENTIFIER */
#define OLD_CERT_ID_OID "\x2B\x06\x01\x05\x05\x07\x05\x01\x05" /* 1.3.6.1.5.5.7.5.1.5 */
        MBEDTLS_ASN1_CHK_ADD( ctrl_len, mbedtls_asn1_write_oid( p, start, OLD_CERT_ID_OID, strlen(OLD_CERT_ID_OID) ) );

        /* AttributeTypeAndValue ::= SEQUENCE */
        MBEDTLS_ASN1_CHK_ADD( ctrl_len, mbedtls_asn1_write_len( p, start, ctrl_len ) );
        MBEDTLS_ASN1_CHK_ADD( ctrl_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                                MBEDTLS_ASN1_SEQUENCE ) );

    }
    /*
       Controls ::= SEQUENCE
    */

    MBEDTLS_ASN1_CHK_ADD( ctrl_len, mbedtls_asn1_write_len( p, start, ctrl_len ) );
    MBEDTLS_ASN1_CHK_ADD( ctrl_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                       MBEDTLS_ASN1_SEQUENCE ) );
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

      MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_pk_write_pubkey_der( ctx->new_key, start, *p - start ) );
      pub_len -= 1; /* -1 is as we're intentionally overwriting the SEQUENCE TAG from the function for IMPLICIT */
      *p -= pub_len; /* mbedtls_pk_write_pubkey_der() did not update *p */
      MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_asn1_write_tag( p, start,
              MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 6 /* SubjectPublicKeyInfo */) );
      tmpl_len += pub_len;
    }

    /* subject      [5] Name                  OPTIONAL */
    if (ctx->subject) {
      MBEDTLS_ASN1_CHK_ADD( subj_len, mbedtls_x509_write_names( p, start, ctx->subject ) );
      MBEDTLS_ASN1_CHK_ADD( subj_len, mbedtls_asn1_write_len( p, start, subj_len ) );
      MBEDTLS_ASN1_CHK_ADD( subj_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 5 ) );
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
    MBEDTLS_ASN1_CHK_ADD( tmpl_len, mbedtls_asn1_write_len( p, start, tmpl_len ) );
    MBEDTLS_ASN1_CHK_ADD( tmpl_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                            MBEDTLS_ASN1_SEQUENCE ) );
    len += tmpl_len;
    g_wr_len_certTemplate = tmpl_len;

    /*
       certReqId     INTEGER,          -- ID for matching request and reply
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( p, start, ctx->certReqId ) );

    /*
     * CertRequest ::= SEQUENCE
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}


/* **************************************************************** */
/* DER-writing functions */
/* **************************************************************** */

static int msg_sig_alg_prot( mbedtls_pk_context *key,
                             mbedtls_md_type_t md,
                             const unsigned char* input,
                             size_t in_len,
                             unsigned char *sig,
                             size_t *sig_len)
{
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];

    mbedtls_md( mbedtls_md_info_from_type( md ), input, in_len, hash );

    /* TODO the last parameters f_rng and p_rng need to come from outside for EC keys... */

    return mbedtls_pk_sign( key, md, hash, 0, sig, sig_len, NULL, NULL );
}

/* **************************************************************** */
int cmpcl_CMPwrite_PKIMessage_protection_der( unsigned char **p,
                                              unsigned char *start,
                                              cmp_ctx *ctx,
                                              const unsigned char* input,
                                              const size_t in_len) /* TODO that random stuff for ECDSA... */
{
    int ret;
    size_t len = -1;
    unsigned char *prot;
    size_t prot_len = 0;

    prot = mbedtls_calloc(1, MBEDTLS_MPI_MAX_SIZE);
    if (!prot)
        goto err;


    if (ctx->secret && ctx->pbmp) { /* MSG_MAC_ALG */
       if ( (ret = cmp_PBM_new( ctx->pbmp,
                          ctx->secret,
                          ctx->secret_len,
                          input,
                          in_len,
                          prot,
                          &prot_len)) != 0)
           goto err;
    } else if (ctx->cl_key && ctx->sig_prot_md_alg) {/* MSG_SIG_ALG */
        if ( (ret = msg_sig_alg_prot( ctx->cl_key,
                          ctx->sig_prot_md_alg,
                          input,
                          in_len,
                          prot,
                          &prot_len)) != 0)
            goto err;
    } else {
        CMPWARNS( "No credentials for protection. Message unprotected!");
        mbedtls_free(prot);
        return 0;
    }

    if (*p < start || (size_t)( *p - start ) < prot_len )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    len = prot_len;
    (*p) -= len;
    memcpy( *p, prot, len );

    if (*p - start < 1 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    *--(*p) = 0;
    len += 1;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_BIT_STRING ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) );

err:
    mbedtls_free(prot);
    return( (int) len );
}

static int mbedtls_asn1_buf_cmp(mbedtls_asn1_buf *buf1, mbedtls_asn1_buf *buf2)
{
	if (buf1 == NULL && buf2 == NULL)
		return 0;
	if (buf1 == NULL)
		return -1;
	if (buf2 == NULL)
		return 1;
	if (buf1->len != buf2->len)
		return buf1->len - buf2->len;
	return memcmp( buf1->p, buf2->p, buf1->len );
}

static int same_cert(mbedtls_x509_crt *crt1, mbedtls_x509_crt *crt2)
{
	return mbedtls_asn1_buf_cmp( &crt1->serial, &crt2->serial ) == 0 &&
           mbedtls_asn1_buf_cmp( &crt1->issuer_raw, &crt2->issuer_raw ) == 0; // TODO use better DN comparison
}

static size_t cmpcl_CMPwrite_ExtraCerts_der( unsigned char **p,
                                            unsigned char *start,
                                            cmp_ctx *ctx)
{
    int ret;
    size_t len = 0;
    mbedtls_x509_crt *crt = ctx->cl_chain;
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
        while(crt)
            {
                if (mbedtls_asn1_buf_cmp( &crt->issuer_raw, &crt->subject_raw ) != 0 && // TODO use better DN comparison
                    !same_cert(crt, ctx->cl_cert)) {
                    size_t sub_len = 0;
                    MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, crt->raw.p, crt->raw.len ));
                    len += sub_len;
                    g_wr_n_extraCerts++;
                }
                crt = crt->next;
            }
            if(ctx->cl_cert)
            {
                size_t sub_len = 0;
                MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, ctx->cl_cert->raw.p, ctx->cl_cert->raw.len ));
                len += sub_len;
                g_wr_n_extraCerts++;
            }
    }
    if(len) {
        g_wr_len_extraCerts = len; /* to print out extraCerts total size */

        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 ) );
    }

    return len;
}


/* **************************************************************** */
int cmpcl_CMPwrite_PKIMessage_der( cmp_ctx *ctx, unsigned char *start,
        size_t size, unsigned char **myp, int unprotected)  /* TODO that random stuff for ECDSA... */
{
    int ret;
    unsigned char *x;
    unsigned char **p;
    size_t len = 0;
    size_t extraCerts_len = 0;
    size_t body_len = 0;
    size_t cr_len = 0; /* needed for length of CertReqest sequence */
    unsigned char *prot_end_p;
    size_t prot_len = 0;
    size_t protPart_len = 0;
    unsigned char *protPart_p;

    /* needed to print sizes of chosen parts of the message
     * initialize to zero for each new PKIMessage
     */
    g_wr_len_extraCerts = 0;
    g_wr_n_extraCerts = 0;
    g_wr_len_certTemplate = 0;
    g_wr_len_popo = 0;

    /* the end of the buffer */
    x = start + size;
    /* helps to keep all the same variable names in the ASN1 writer functions */
    p = &x;

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
    MBEDTLS_ASN1_CHK_ADD( extraCerts_len, cmpcl_CMPwrite_ExtraCerts_der( p, start, ctx));
    g_wr_n_extraCerts = 0; /* to avoid that the static var is being incremented in this "dummy" call */


    /*
     * protection    [0]    PKIProtection OPTIONAL
     * The input to the calculation of PKIProtection is the DER encoding of
     * the following data structure:
     *
     * ProtectedPart ::= SEQUENCE {
     *  header PKIHeader,
     *  body PKIBody }
     *
     *  --> body and header not yet known, therefore just reserve space for protection
     *
     */
    prot_end_p = *p; /* from this point the real signature will need to be written later */
    /* MBEDTLS_ECDSA_MAX_LEN is max ECDSA len, ECDSA signatures have variable size */

    if( ctx->cl_key && (mbedtls_pk_get_type(ctx->cl_key) == MBEDTLS_PK_ECKEY) ) {
        prot_len = MBEDTLS_ECDSA_MAX_LEN; /* preliminary (maximal) length */
        *p -= prot_len; // pointer decremented to reserve space in output buffer
    } else if (!unprotected) {
        /* figure out sig length - and write there. TODO TODO TODO: doing that two times is highly inefficient, but how to figure out the length otherwise? */
        MBEDTLS_ASN1_CHK_ADD( prot_len, cmpcl_CMPwrite_PKIMessage_protection_der( p, start, ctx, (const unsigned char*) "", 0) );
    }

    /*
     * body PKIBody
     */

    /*
     * PKIBody ::= CHOICE {
     * ir        [0] CertReqMessages, --Initialization Req
     * ip        [1] CertRepMessage, --Initialization Resp
     * cr        [2] CertReqMessages, --Certification Req
     * cp        [3] CertRepMessage, --Certification Resp
     * p10cr     [4] CertificationRequest, --PKCS #10 Cert. Req.
     * popdecc   [5] POPODecKeyChallContent --pop Challenge
     * popdecr   [6] POPODecKeyRespContent, --pop Response
     * kur       [7] CertReqMessages, --Key Update Request
     * kup       [8] CertRepMessage, --Key Update Response
     * krr       [9] CertReqMessages, --Key Recovery Req
     * krp      [10] KeyRecRepContent, --Key Recovery Resp
     * rr       [11] RevReqContent, --Revocation Request
     * rp       [12] RevRepContent, --Revocation Response
     * ccr      [13] CertReqMessages, --Cross-Cert. Request
     * ccp      [14] CertRepMessage, --Cross-Cert. Resp
     * ckuann   [15] CAKeyUpdAnnContent, --CA Key Update Ann.
     * cann     [16] CertAnnContent, --Certificate Ann.
     * rann     [17] RevAnnContent, --Revocation Ann.
     * crlann   [18] CRLAnnContent, --CRL Announcement
     * pkiconf  [19] PKIConfirmContent, --Confirmation
     * nested   [20] NestedMessageContent, --Nested Message
     * genm     [21] GenMsgContent, --General Message
     * genp     [22] GenRepContent, --General Response
     * error    [23] ErrorMsgContent, --Error Message
     * certConf [24] CertConfirmContent, --Certificate confirm
     * pollReq  [25] PollReqContent, --Polling request
     * pollRep  [26] PollRepContent --Polling response
     * }
     */
    switch (ctx->body_type) {
      case MBEDTLS_CMP_PKIBODY_IR:
      case MBEDTLS_CMP_PKIBODY_CR:
      case MBEDTLS_CMP_PKIBODY_KUR:
          /* Adding one *single* CertReqest here */
          MBEDTLS_ASN1_CHK_ADD( cr_len, cmpcl_CRMFwrite_CertReqMsg_der( p, start, ctx ) );
          body_len += cr_len;
          /* CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg */
          MBEDTLS_ASN1_CHK_ADD( body_len, mbedtls_asn1_write_len( p, start, cr_len ) );
          MBEDTLS_ASN1_CHK_ADD( body_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );
          break;
      case MBEDTLS_CMP_PKIBODY_PKICONF: /* the client does not need to send that - but easiest for first testing ;-) */
        MBEDTLS_ASN1_CHK_ADD( body_len, mbedtls_asn1_write_null( p, start ) );
        break;
        /* TODO: add additional body types */
      case MBEDTLS_CMP_PKIBODY_CERTCONF:
          MBEDTLS_ASN1_CHK_ADD( body_len, cmpcl_CMPwrite_CertConfCont_der( p, start, ctx ) );
          break;
      default:
        CMPERRV("NOT SUPPORTED PKIBody_type %d\n", ctx->body_type);
        return CMPCL_ERR_UNSUPPORTED_BODYTYPE;
    }
    protPart_len += body_len; // both header and body are protected

    /* [x] */
    MBEDTLS_ASN1_CHK_ADD( protPart_len, mbedtls_asn1_write_len( p, start, body_len ) );
    MBEDTLS_ASN1_CHK_ADD( protPart_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | ctx->body_type ) );


    /*
     *   header           PKIHeader
     */
    g_wr_len_header = protPart_len;
    MBEDTLS_ASN1_CHK_ADD( protPart_len, cmpcl_CMPwrite_PKIHeader_der( p, start, ctx, unprotected ) );
    g_wr_len_header = protPart_len - g_wr_len_header;

    /* temporary sequence TL for calculating the protection
        ProtectedPart ::= SEQUENCE {
            header    PKIHeader,
            body      PKIBody
        }
     */

    /*
     * header and body are written now --> save current pos & prot_len as input for protection
     */
    protPart_p = *p;
    size_t content_len = protPart_len;
    MBEDTLS_ASN1_CHK_ADD( protPart_len, mbedtls_asn1_write_len( &protPart_p, start, protPart_len ) );
    MBEDTLS_ASN1_CHK_ADD( protPart_len, mbedtls_asn1_write_tag( &protPart_p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );

    if (!unprotected) {     /* start setting protection */
        /* ECDSA has variable signature length */
        if( ctx->cl_key && (mbedtls_pk_get_type( ctx->cl_key) == MBEDTLS_PK_ECKEY) ) {
            size_t real_prot_len = 0;
            /* TODO TODO TODO: done twice, highly inefficient */
            unsigned char *real_prot_end_p = prot_end_p;
            real_prot_len = cmpcl_CMPwrite_PKIMessage_protection_der( &real_prot_end_p, start, ctx, protPart_p, protPart_len);
            if (real_prot_len < 0)
                return real_prot_len;
            real_prot_end_p = prot_end_p - (prot_len - real_prot_len);
            ret = cmpcl_CMPwrite_PKIMessage_protection_der( &real_prot_end_p, start, ctx, protPart_p, protPart_len);
            if (ret < 0)
                return ret;

            /*
             * as length of protection was unknown before extraCerts need to be rewritten to obtain coherent buffer
             */

            /* rewrite ExtraCerts at right position */
            unsigned char *real_extra_end_p = prot_end_p - (prot_len - real_prot_len) + extraCerts_len;
            cmpcl_CMPwrite_ExtraCerts_der( &real_extra_end_p, start, ctx);
            prot_len = real_prot_len;
        } else {
            /* write the real protection over the mock one, calling the function a second time
             * because now the header and body contents are known */
            ret = cmpcl_CMPwrite_PKIMessage_protection_der( &prot_end_p, start, ctx, protPart_p, protPart_len);
            if (ret < 0)
                return ret;
        }
    }
    g_wr_prot_len = prot_len;

    /* total message length */
    len = content_len + prot_len + extraCerts_len;
    /* write over the temporary sequence TL
     * PKIMessage ::= SEQUENCE
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );
    *myp = *p; // this is used by calling function to determine start of output buffer

#ifdef DEVELOPMENT /* for debugging */
    write_to_file("PKIMessage.der", *p, len);
#endif

#ifdef DEBUG_ASN1
    int i;
    CMPINFOV("\r\n **Request** \r\n");
    for(i = 0; i < len; i++)
    	PRINTF("0x%02X ", *(*p+i));
#endif


    CMPINFOV("produced PKIMessage header length: %d", g_wr_len_header);
    if( g_wr_len_certTemplate > 0 )
        CMPINFOV("produced CertTemplate length: %d", g_wr_len_certTemplate);
    if( g_wr_len_popo > 0 ) {
        CMPINFOV("produced ProofOfPossession length: %d", g_wr_len_popo);
        CMPINFOV("%s""requesting implicit confirmation",  ctx->implicitConfirm ? "" : "not ");
    }
    if (ctx->secret && ctx->pbmp && !unprotected)
        CMPINFOV("PBM-based protection");
    else if (ctx->cl_key && ctx->sig_prot_md_alg && !unprotected)
        CMPINFOV("signature-based protection with %d extraCerts with total length: %d", g_wr_n_extraCerts, g_wr_len_extraCerts);
    else
        CMPINFOV("no protection");
    CMPINFOV("request PKIMessage protection length: %d", g_wr_prot_len);
    CMPINFOV("request PKIMessage overhead (excl. template, POPO, and certs): %d", len - g_wr_len_certTemplate - g_wr_len_extraCerts - g_wr_len_popo);
    CMPINFOV("request PKIMessage total length: %d", len);
    CMPINFOV("----"); // begin of transmission

    return( (int) len );
}

#if 0
/* FIND THE KEY IDENTIFIER EXTENSION NEEDED FOR senderKID */
/* TODO doesn't work as I don't find the key identifier from extensions :-/ */
static int getExtension( mbedtls_x509_buf *v3_ext)
{
CMPDBG
    int ret;
    size_t len;
    unsigned char *end_ext_data, *end_ext_octet;
    unsigned char *c, *end;
    unsigned char **p;

    p = &c;
    *p = v3_ext->p;
    end = *p + v3_ext->len;

    /* the outermost sequence needs to be taken away ... */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        CMPERRS("ERROR with extension\n");;

    while( *p < end )
    {
        /*
         * Extension  ::=  SEQUENCE  {
         *      extnID      OBJECT IDENTIFIER,
         *      critical    BOOLEAN DEFAULT FALSE,
         *      extnValue   OCTET STRING  }
         */
        mbedtls_x509_buf extn_oid = {0, 0, NULL};
        int is_critical = 0; /* DEFAULT FALSE */
        int ext_type = 0;

        if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

        end_ext_data = *p + len;

        /* Get extension ID */
        extn_oid.tag = **p;

        if( ( ret = mbedtls_asn1_get_tag( p, end, &extn_oid.len, MBEDTLS_ASN1_OID ) ) != 0 )
        {
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
            }

        extn_oid.p = *p;
        *p += extn_oid.len;

        if( ( end - *p ) < 1 )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                    MBEDTLS_ERR_ASN1_OUT_OF_DATA );

        /* Get optional critical */
        if( ( ret = mbedtls_asn1_get_bool( p, end_ext_data, &is_critical ) ) != 0 &&
            ( ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG ) )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

        /* Data should be octet string type */
        if( ( ret = mbedtls_asn1_get_tag( p, end_ext_data, &len,
                MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

        end_ext_octet = *p + len;

        if( end_ext_octet != end_ext_data )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

        /*
         * Detect supported extensions
         */
        ret = mbedtls_oid_get_x509_ext_type( &extn_oid, &ext_type ); /* TODO This does NOT give the ID if the extension is not supported :-/ */

CMPDBGV("Ext type %d, ret %d\n", ext_type, ret);

        switch( ext_type )
        {
        case MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER:
            break;

        default:
            *p = end_ext_octet;
        }
    }

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

CMPDBG
    return( 0 );
}
#endif /* 0 */

/* **************************************************************** */
static int cmpcl_CMPwrite_PBMParameter_der( unsigned char **p, unsigned char *start,
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
    const char *sig_oid;
    size_t sig_oid_len = 0;

    /* mac                 AlgorithmIdentifier */
/* TODO: HARDCODED - that's not in mbedtls/include/mbedtls/oid.h - MBEDTLS_OID_HMAC_SHA1 is not correct*/
/* RFC 4210: HMAC-SHA1 {1 3 6 1 5 5 8 1 2} */
#define HMAC_SHA1_OID "\x2b\x06\x01\x05\x05\x08\x01\x02"
    /* RFC 4231:
       rsadsi OBJECT IDENTIFIER ::=
       {iso(1) member-body(2) us(840) rsadsi(113549)}

       digestAlgorithm   OBJECT IDENTIFIER ::= {rsadsi 2}

       id-hmacWithSHA224 OBJECT IDENTIFIER ::= {digestAlgorithm 8}
       id-hmacWithSHA256 OBJECT IDENTIFIER ::= {digestAlgorithm 9}
       id-hmacWithSHA384 OBJECT IDENTIFIER ::= {digestAlgorithm 10}
       id-hmacWithSHA512 OBJECT IDENTIFIER ::= {digestAlgorithm 11}
     */
#define HMAC_SHA256_OID "\x2A\x86\x48\x86\xF7\x0D\x02\x09"
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( p, start, HMAC_SHA1_OID, strlen( HMAC_SHA1_OID), 0 ) );
    //MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( p, start, HMAC_SHA256_OID, strlen( HMAC_SHA256_OID), 0 ) );

    /* iterationCount      INTEGER, */
    /* TODO: PROBLEM: mbedtls_asn1_write_int does only support up to 128... */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( p, start, pbmp->iterationCount ) );

    /* owf                 AlgorithmIdentifier, */
    if( ( ret = mbedtls_oid_get_oid_by_md( pbmp->owf, &sig_oid, &sig_oid_len ) ) != 0 )
        return( ret );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( p, start, sig_oid, strlen( sig_oid ), 0 ) );

    /* salt                OCTET STRING, */
    sub_len = 0;
    MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, pbmp->salt, pbmp->salt_len ) );
    len += sub_len;
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OCTET_STRING ) );

    /* PBMParameter ::= SEQUENCE { */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

    return len;
}


/* **************************************************************** */

int cmpcl_CMPwrite_PKIHeader_der( unsigned char **p, unsigned char *start,
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

    if (ctx->implicitConfirm )
    {
        sub_len = 0;
        size_t par_len = 0;
        MBEDTLS_ASN1_CHK_ADD( par_len, mbedtls_asn1_write_null( p, start ) );
        MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_algorithm_identifier(
                    p, start, IMPLICITCONFIRM_OID,
                    strlen( IMPLICITCONFIRM_OID ), par_len ) );
        MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_len( p, start, sub_len ) );
        MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

        MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_len( p, start, sub_len ) );
        MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start,
                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 8 ) );
        len += sub_len;
    }
    /*
         freeText        [7] PKIFreeText             OPTIONAL,
         PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
     */

    /*
         recipNonce      [6] OCTET STRING            OPTIONAL,
     */
    if (ctx->recipNonce )
    {
      sub_len = 0;
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, ctx->recipNonce, ctx->recipNonce_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OCTET_STRING ) );
      len += sub_len;
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 6 ) );
    }
    /*
         senderNonce     [5] OCTET STRING            OPTIONAL,
     */
    if (ctx->senderNonce )
    {
      sub_len = 0;
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, ctx->senderNonce, ctx->senderNonce_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OCTET_STRING ) );
      len += sub_len;
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 5 ) );
    }

    /*
         transactionID   [4] OCTET STRING            OPTIONAL,
     */
    if (ctx->transactionID )
    {
      sub_len = 0;
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, ctx->transactionID, ctx->transactionID_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OCTET_STRING ) );
      len += sub_len;
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 4 ) );
    }
    /*
         recipKID        [3] KeyIdentifier           OPTIONAL,
     */

    /*
         senderKID       [2] KeyIdentifier           OPTIONAL,
     */
/* doesn't work as I don't find the key identifier from extensions :-/ */
#if 0
    if (ctx->cl_cert)
    {
      sub_len = 0;
     // MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER
      getExtension( &ctx->cl_cert->v3_ext);
      len += sub_len;
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 2 ) );
    }
#endif
    if (ctx->reference)
    {
      sub_len = 0;
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, ctx->reference, ctx->reference_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OCTET_STRING ) );
      len += sub_len;
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 2 ) );
    }

    /*
         protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
     */
    if(unprotected) {
        /* no protection */
    } else if (ctx->cl_key/* && ctx->sig_prot_md_alg */) {
      mbedtls_pk_type_t pk_alg;
      pk_alg = mbedtls_pk_get_type( ctx->cl_key);
      if( pk_alg == MBEDTLS_PK_ECKEY )
          pk_alg = MBEDTLS_PK_ECDSA;

      if( ( ret = mbedtls_oid_get_oid_by_sig_alg( pk_alg, ctx->sig_prot_md_alg, &sig_oid, &sig_oid_len ) ) != 0 )
          return( ret );

      sub_len = 0;
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_algorithm_identifier( p, start, sig_oid, strlen( sig_oid ), 0 ) );
      len += sub_len;
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 ) );
    } else if (ctx->secret && ctx->pbmp) { /* PBM */
        /*
      id-PasswordBasedMAC OBJECT IDENTIFIER ::= { 1 2 840 113533 7 66 13} */
        size_t par_len = 0;
        MBEDTLS_ASN1_CHK_ADD( par_len, cmpcl_CMPwrite_PBMParameter_der( p, start, ctx->pbmp) );

        sub_len = 0;

/* PBM OID defined in cmpcl_int.h
 * HARDCODED as it is not defined in mbedtls */
        MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_algorithm_identifier( p, start, PBM_OID, strlen( PBM_OID ), par_len ) );
        len += sub_len;
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 ) );
    } else {
        CMPERRS( "No protection credentials configured!");
    }

    /*
         messageTime     [0] GeneralizedTime         OPTIONAL,
     */
    if (ctx->messageTime) {
      sub_len = 0;
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, (const unsigned char *) ctx->messageTime, MBEDTLS_X509_RFC5280_UTC_TIME_LEN ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_GENERALIZED_TIME ) );
      len += sub_len;
      /* [0] */
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) );
    }

    /*
         recipient           GeneralName,
     */
    sub_len = 0;
    MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_x509_write_names( p, start, ctx->recipient ) );
    len += sub_len;
    /* Explicit */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_OCTET_STRING ) );

    /*
         sender              GeneralName,
     */
    sub_len = 0;
    MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_x509_write_names( p, start, ctx->sender ) );
    len += sub_len;
    /* Explicit */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_OCTET_STRING ) );

    /*
     *   pvno                INTEGER     { cmp1999(1), cmp2000(2) },
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( p, start, MBEDTLS_CMP_VERSION_2 ) );

    /*
     * PKIHeader ::= SEQUENCE
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );
    return( (int) len );
}

