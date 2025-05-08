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

int mbedtls_x509_get_name(unsigned char **p, const unsigned char *end,
                          mbedtls_x509_name *cur);

#define PARSE_ASN1_CONSTRUCTED_TAG(expected) ((ret = \
                                                   mbedtls_asn1_get_tag(&p, end, &len, \
                                                                        MBEDTLS_ASN1_CONSTRUCTED | \
                                                                        expected)) != 0)

#define MBEDTLS_ERR(ret)  \
    do { \
        char err_buf[CMPCL_ER_BUF_LEN]; \
        mbedtls_strerror(ret, err_buf, CMPCL_ER_BUF_LEN); \
    } while (0);

static size_t g_rc_len_extraCerts = 0;
static size_t g_rc_n_extraCerts = 0;
static size_t g_rc_len_caPubs = 0;
static size_t g_rc_len_cert = 0;


/*
 * Reads and parses extraCerts from the received PKIMessage to the local CMP context
 */
static int cmp_extra_certs_parse_check(cmp_ctx *ctx, cmp_pkimessage *cmp)
{

    int ret = -1;

    if (cmp->extraCerts.p && cmp->extraCerts.len != 0) {

        unsigned char *p = cmp->extraCerts.p;
        const unsigned char *end = cmp->extraCerts.p + cmp->extraCerts.len;
        if (*p != (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
            CMPERRS("wrong tagged extra certs");
            ret = -1;
            goto err;
        }
        p++;
        size_t cert_sequence_len;
        if ((ret = mbedtls_asn1_get_len(&p, end, &cert_sequence_len)) != 0) {
            CMPERRV("mbedtls_asn1_get_len(): 0x%04x", -ret);
            goto err;
        }

        if (cert_sequence_len == 0) {
            CMPDBGS("Empty sequence of extraCerts received");
            return 0;
        }
        if (ctx->extraCerts) {
            mbedtls_x509_crt_free(ctx->extraCerts);
            mbedtls_free(ctx->extraCerts);
        }
        ctx->extraCerts = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));
        if (!ctx->extraCerts) {
            CMPERRS("calloc");
            goto err;
        }

        mbedtls_x509_crt_init(ctx->extraCerts);
        while (p < end) {
            g_rc_n_extraCerts++;
            size_t cert_len;
            const unsigned char *cert_start = p;
            // skip SEQUENCE tag
            p++;
            if ((ret = mbedtls_asn1_get_len(&p, end, &cert_len)) != 0) {
                CMPERRV("mbedtls_asn1_get_len(): 0x%04x", -ret);
                goto err;
            }
            unsigned char *next_cert = p + cert_len;
            if ((ret = mbedtls_x509_crt_parse_der(ctx->extraCerts, cert_start,
                                                  cert_sequence_len)) != 0) {
                CMPERRV("mbedtls_x509_crt_parse_der(extraCerts): 0x%04x", -ret);
                goto err;
            }
            p = next_cert;
        }
        g_rc_len_extraCerts = cert_sequence_len;
        return 0;
    }


err:
    cmp_pkimessage_free(cmp);
    mbedtls_free(cmp);

    return ret;
}

/*
 * Verify received protection
 */
#define ASN1_SEQ_TAG_LEN    10 /* maybe 5 would be sufficient */
static int cmp_prot_check(cmp_ctx *ctx, cmp_pkimessage *cmp)
{

    int ret = -1;
    unsigned char **p;
    unsigned char *start = NULL;
    unsigned char *x;
    size_t prot_part_len = 0;
    unsigned char *mac = NULL;
    size_t mac_len = 0;
    unsigned char *md = NULL;

    /* build up ProtectedPart as input for MAC algorithm */

    /* ProtectedPart ::= SEQUENCE {
            header    PKIHeader,
            body      PKIBody
        }
     */
    prot_part_len = cmp->header.len + cmp->body.len;
    start = mbedtls_calloc(1, prot_part_len + ASN1_SEQ_TAG_LEN);
    if (start == NULL) {
        CMPERRS("Out of memory!");
        ret = -1;
        goto err;
    }
    x = start + ASN1_SEQ_TAG_LEN; /* start to copy temporary ProtectedPart sequence from here and leave ASN1_SEQ_TAG_LEN bytes for ASN1 DER Tag and Length fields */
    p = &x;
    memcpy(*p, cmp->header.p, prot_part_len);  /* copy header and body */

    MBEDTLS_ASN1_CHK_ADD(prot_part_len, mbedtls_asn1_write_len(p, start, prot_part_len));
    MBEDTLS_ASN1_CHK_ADD(prot_part_len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                               MBEDTLS_ASN1_SEQUENCE));

    /* verify PBM protection */
    if (cmp->pbmp != NULL) {

        mac = mbedtls_calloc(1, MBEDTLS_MPI_MAX_SIZE);
        if (mac == NULL) {
            CMPERRS("Out of memory!");
            ret = -1;
            goto err;
        }

        /* calculate verification MAC */
        if (ctx->prot_secret == NULL) {
            CMPERRS("No secret provided, therefore no calculation of MAC possible.");
            goto err;
        }

        if ((ret = cmp_PBM_new(cmp->pbmp,
                               ctx->prot_secret, ctx->secret_len,
                               *p, prot_part_len,
                               mac, &mac_len))
            != 0) {
            CMPERRS("Failed to calculate MAC value for protection verification!");
            goto err;
        }
        ;

        /* compare */
        if ((ret = memcmp(mac, cmp->protection->p, cmp->protection->len)) != 0) {
            CMPERRV("MAC does not match! memcmp ret: %d", ret);
            ret = -1;
        }
    } else { /* check sig prot */

        /* parsing of extraCerts already done; use pk_ctx directly from there */
        if (ctx->extraCerts == NULL) {
            CMPERRS("No extraCerts found! Abort signature protection verification!");
            ret = -1;
            goto err;
        }

        /* check if signer key type matches algorithm provided in protectionAlg */
        if (!mbedtls_pk_can_do(&ctx->extraCerts->pk, cmp->sig_pk)) {
            CMPERRS(
                "Protection algorithm in protAlg field does not match key type of first cert in extraCerts!");
            ret = -1;
            goto err;
        }


        /* get hash of ProtPart */
        const mbedtls_md_info_t *md_info;
        size_t md_len;

        md_info = mbedtls_md_info_from_type(cmp->sig_md);
        md_len = mbedtls_md_get_size(md_info);

        md = (unsigned char *) mbedtls_calloc(1, md_len);
        if (md == NULL) {
            CMPERRS("Out of memory!");
            ret = -1;
            goto err;
        }

        if ((ret = mbedtls_md(md_info,
                              *p,
                              prot_part_len,
                              md)) != 0) {
            CMPERRV("mbedtls_md returned 0x%04x", -ret);
            goto err;
        }

        /* verify signature */
        if ((ret = mbedtls_pk_verify(&ctx->extraCerts->pk,
                                     mbedtls_md_get_type(md_info),
                                     md,
                                     md_len,
                                     cmp->protection->p,
                                     cmp->protection->len)) != 0) {
            CMPERRS(
                "Signature protection could not be verified (assuming first extraCert is signer cert)!");
            CMPERRV("mbedtls_pk_verify returned: 0x%04x", -ret);
            goto err;
        }
        CMPDBGS("Signature protection verification was successful")
    }

err:
    mbedtls_free(start);
    mbedtls_free(mac);
    mbedtls_free(md);
    return ret;
}

/*
 * Parse CMP PKIHeader in DER format
 */
static int cmp_header_parse_check_der(cmp_ctx *ctx, cmp_pkimessage *cmp,
                                      unsigned char *p, unsigned char *end)
{
    /*
       PKIHeader ::= SEQUENCE {
             pvno                INTEGER     { cmp1999(1), cmp2000(2) },
             sender              GeneralName,
             recipient           GeneralName,
             messageTime     [0] GeneralizedTime         OPTIONAL,
             protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
             senderKID       [2] KeyIdentifier           OPTIONAL,
             recipKID        [3] KeyIdentifier           OPTIONAL,
             transactionID   [4] OCTET STRING            OPTIONAL,
             senderNonce     [5] OCTET STRING            OPTIONAL,
             recipNonce      [6] OCTET STRING            OPTIONAL,
             freeText        [7] PKIFreeText             OPTIONAL,
             generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
                                 InfoTypeAndValue     OPTIONAL
         }
     */

    int ret;
    size_t len;

    /*
     *   pvno                INTEGER     { cmp1999(1), cmp2000(2) },
     */
    int pvno;

    if ((ret = mbedtls_asn1_get_int(&p, end, &pvno)) != 0) {
        cmp_pkimessage_free(cmp);
        return MBEDTLS_ERR_X509_INVALID_VERSION + ret;
    }

    /*
     *   sender              GeneralName,
     *   -- identifies the sender
     */
    if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_OCTET_STRING)) {
        cmp_pkimessage_free(cmp);
        return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;
    }

    cmp->sender_raw.p = p;

    if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_SEQUENCE)) {
        cmp_pkimessage_free(cmp);
        return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;
    }

    if ((ret = mbedtls_x509_get_name(&p, p + len, &cmp->sender)) != 0) {
        CMPWARNS("response PKIHeader sender field contains empty RDN sequence (NULL DN).");
    }

    cmp->sender_raw.len = p - cmp->sender_raw.p;

    /*
     *   recipient           GeneralName,
     *   -- identifies the intended recipient
     */
    if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_OCTET_STRING)) {
        cmp_pkimessage_free(cmp);
        return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;
    }

    cmp->recipient_raw.p = p;

    if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_SEQUENCE)) {
        cmp_pkimessage_free(cmp);
        return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;
    }

    if ((ret = mbedtls_x509_get_name(&p, p + len, &cmp->recipient)) != 0) {
        CMPDBGV("response PKIHeader recipient field is empty!");
        cmp_pkimessage_free(cmp);
        return ret;
    }

    cmp->recipient_raw.len = p - cmp->recipient_raw.p;


    if (p == end) {
        return 0;     /* no optional fields present */


    }
    /* messageTime     [0] GeneralizedTime         OPTIONAL */
    if (!PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC  | 0)) {
        if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                        MBEDTLS_ASN1_GENERALIZED_TIME)) != 0) {
            cmp_pkimessage_free(cmp);
            return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;
        }
        p = p + len; // ignore messageTime for now

    } // no messageTime field present



    /* protectionAlg   [1] AlgorithmIdentifier     OPTIONAL */
    if (!PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC |  1)) {
        mbedtls_asn1_buf prot_alg_buf;
        mbedtls_asn1_buf prot_alg_params_buf;
        mbedtls_asn1_buf tmp_alg_buf; /* used for deeper layers within protectionAlg */
        size_t sublen = 0;

        if ((ret = mbedtls_asn1_get_alg(&p, end, &prot_alg_buf,
                                        &prot_alg_params_buf)) != 0) {
            cmp_pkimessage_free(cmp);
            return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;
        }

        /* PBM */
        if (memcmp(prot_alg_buf.p, PBM_OID, prot_alg_buf.len) == 0) {

            /* allocate memory */
            cmp->pbmp = (cmp_PBMParameter *) mbedtls_calloc(1, sizeof(cmp_PBMParameter));
            if (cmp->pbmp == NULL) {
                CMPERRS("Out of memory!");
                cmp_pkimessage_free(cmp);
                return CMPCL_ERR_MEMORY_ALLOCATION;
            }

            /*
               PBMParameter ::= SEQUENCE {
                 salt                OCTET STRING,
                 owf                 AlgorithmIdentifier,
                 iterationCount      INTEGER,
                 mac                 AlgorithmIdentifier
                 )
             */

            /*salt                OCTET STRING */
            if ((ret = mbedtls_asn1_get_tag(&prot_alg_params_buf.p,
                                            prot_alg_params_buf.p + prot_alg_params_buf.len,
                                            &sublen,
                                            MBEDTLS_ASN1_OCTET_STRING)) != 0) {
                cmp_pkimessage_free(cmp);
                return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;
            }
            cmp->pbmp->salt = (unsigned char *) mbedtls_calloc(1, sublen);
            if (cmp->pbmp->salt == NULL) {
                CMPERRS("Out of memory!");
                cmp_pkimessage_free(cmp);
                return CMPCL_ERR_MEMORY_ALLOCATION;
            }
            cmp->pbmp->salt_len = sublen;
            memcpy(cmp->pbmp->salt, prot_alg_params_buf.p, cmp->pbmp->salt_len);

            prot_alg_params_buf.p += sublen;
            prot_alg_params_buf.len -= sublen;  /* remaining length */

            /* owf AlgorithmIdentifier */
            if ((ret = mbedtls_asn1_get_alg_null(&prot_alg_params_buf.p,
                                                 prot_alg_params_buf.p + prot_alg_params_buf.len,
                                                 &tmp_alg_buf)) != 0) {
                cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_BADALG);
                cmp_pkimessage_free(cmp);
                return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;
            }
            prot_alg_params_buf.len -= tmp_alg_buf.len;

            if ((ret = mbedtls_oid_get_md_alg(&tmp_alg_buf, &cmp->pbmp->owf)) != 0) {
                CMPERRV("Could not parse PBM owf! ret: 0x%04x", -ret);
                cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_BADALG);
                cmp_pkimessage_free(cmp);
                return ret;
            }

            /* iterationCount      INTEGER */
            if ((ret = mbedtls_asn1_get_int(&prot_alg_params_buf.p,
                                            prot_alg_params_buf.p + prot_alg_params_buf.len,
                                            &cmp->pbmp->iterationCount)) != 0) {
                CMPERRV("Could not parse PBM iteration count! ret: 0x%04x", -ret);
                cmp_pkimessage_free(cmp);
                return ret;
            }

            /* mac                 AlgorithmIdentifier */
            if ((ret = mbedtls_asn1_get_alg_null(&prot_alg_params_buf.p,
                                                 prot_alg_params_buf.p + prot_alg_params_buf.len,
                                                 &tmp_alg_buf)) != 0) {
                CMPERRV("Could not parse PBM mac! ret: 0x%04x", -ret);
                cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_BADALG);
                cmp_pkimessage_free(cmp);
                return ret;
            }
            if ((ret = mbedtls_oid_get_md_hmac(&tmp_alg_buf, &cmp->pbmp->mac))
                != 0) {
                // be a little bit sloppy about hmac and digest OIDs
                if ((ret = mbedtls_oid_get_md_alg(&tmp_alg_buf, &cmp->pbmp->mac))
                    != 0) {
                    if (tmp_alg_buf.len == (sizeof(RFC4210_HMAC_SHA1_OID) -1) &&
                        memcmp(tmp_alg_buf.p, RFC4210_HMAC_SHA1_OID,
                               (sizeof(RFC4210_HMAC_SHA1_OID) -1)) == 0) {
                        cmp->pbmp->mac = MBEDTLS_MD_SHA1;
                    } else {
                        CMPERRV("Could not parse PBM mac! ret: 0x%04x", -ret);
                        cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_BADALG);
                        cmp_pkimessage_free(cmp);
                        return ret;
                    }
                }
            }

        } else { /* MSG_SIG_ALG  */
            if ((ret = mbedtls_oid_get_sig_alg(&prot_alg_buf, &cmp->sig_md,
                                               &cmp->sig_pk)) != 0) {
                CMPERRS("Signature based protection algorithm could not be parsed!");
                cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_BADALG);
                cmp_pkimessage_free(cmp);
                return -1;
            }
        }
    }

    /* senderKID       [2] KeyIdentifier           OPTIONAL */
    if (!PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC |  2)) {
        /* TODO: check here */
        p = p + len;
    }

    /* recipKID        [3] KeyIdentifier           OPTIONAL */
    if (!PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC |  3)) {
        /* TODO: check here */
        p = p + len;
    }

    /* transactionID   [4] OCTET STRING            OPTIONAL  */
    /*   -- identifies the transaction; i.e., this will be the same in
     *   -- corresponding request, response, certConf, and PKIConf
     *   -- messages
     */
    if (!PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC |  4)) {

        if ((ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
            cmp_pkimessage_free(cmp);
            return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;
        }

        /* check for length */
        if (ctx->transactionID_len != len) {
            cmp_pkimessage_free(cmp);
            cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_BADMESSAGECHECK);
            CMPERRS("TransactionID not matching!");
            return -1;
        }

        if (memcmp(ctx->transactionID, p, len) != 0) {
            cmp_pkimessage_free(cmp);
            cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_BADMESSAGECHECK);
            CMPERRS("TransactionID not matching!");
            return -1;
        }
        CMPDBGS("TransactionID match!");

        p = p + len;
    }

    /* senderNonce     [5] OCTET STRING            OPTIONAL */
    if (!PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC | 5)) {

        if ((ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
            cmp_pkimessage_free(cmp);
            return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;
        }

        if (ctx->recipNonce) {
            mbedtls_free(ctx->recipNonce);
            ctx->recipNonce = NULL;
            ctx->recipNonce_len = 0;
        }

        if (setStr(&(ctx->recipNonce), p, len) != 0) {
            CMPERRS("Failed to store recipNonce in context!");
            cmp_pkimessage_free(cmp);
            return -1;
        }
        ctx->recipNonce_len = len;

        p = p + len;
    }

    /* recipNonce      [6] OCTET STRING            OPTIONAL */
    if (!PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC | 6)) {

        if ((ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
            cmp_pkimessage_free(cmp);
            return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;
        }


        /* check for length */
        if (ctx->senderNonce_len != len) {
            cmp_pkimessage_free(cmp);
            CMPERRS("TransactionID not matching!");
            return -1;
        }

        if (memcmp(ctx->senderNonce, p, len) != 0) {
            cmp_pkimessage_free(cmp);
            cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_BADRECIPIENTNONCE);
            CMPERRS("recipNonce does not match sent senderNonce!");
            return -1;
        }
        CMPDBGS("recipNonce matches sent senderNonce!");
        p = p + len;
    }

    /* freeText        [7] PKIFreeText             OPTIONAL */
    if (!PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC | 7)) {
        /* TODO: add if needed; ignore for now */
        p = p + len;
    }

    /* generalInfo     [8] SEQUENCE SIZE (1..MAX) OF        OPTIONAL  */
    if (!PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC | 8)) {

        mbedtls_asn1_sequence *general_info_seq = (mbedtls_asn1_sequence *) mbedtls_calloc(1,
                                                                                           sizeof(
                                                                                               mbedtls_asn1_sequence));

        /* SEQUENCE */
        ret = mbedtls_asn1_get_sequence_of(&p, p+len, general_info_seq,
                                           MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret != 0) {
            cmp_pkimessage_free(cmp);
            return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;
        }

        /*
           InfoTypeAndValue ::= SEQUENCE {
             infoType    INFO-TYPE-AND-VALUE.
                             &id({SupportedInfoSet}),
             infoValue   INFO-TYPE-AND-VALUE.
                             &Type({SupportedInfoSet}{@infoType}) }
         */
        mbedtls_asn1_buf *cur = NULL;
        cur = &(general_info_seq->buf);
        while (cur != NULL && cmp->implicit_conf_granted == 0) {

            ret = mbedtls_asn1_get_tag(&(cur->p), p + len, &(cur->len), MBEDTLS_ASN1_OID);
            if (ret != 0) {
                cmp_pkimessage_free(cmp);
                return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;

            }

            /* look for implicitConfim */
            if (memcmp(cur->p, IMPLICITCONFIRM_OID, cur->len) == 0) {
                CMPDBGS("implicitConfirm was granted");
                cmp->implicit_conf_granted = 1;
            }

            /* TODO: parse additional fields */

            cur = &(general_info_seq->next->buf);
        }
        cmp_asn1_sequence_free(general_info_seq);

    }

    return 0;
}

/*
 * Parse PKIFreeText in DER Format
 */
static int cmp_pkibody_PKIFreeText_parse_der(unsigned char **p, unsigned char *end,
                                             mbedtls_asn1_sequence **outSeq)
{
    int ret;
    *outSeq = (mbedtls_asn1_sequence *) mbedtls_calloc(1,
                                                       sizeof(mbedtls_asn1_sequence));
    if ((ret = mbedtls_asn1_get_sequence_of(p, end,
                                            *outSeq, MBEDTLS_ASN1_UTF8_STRING))) {
        MBEDTLS_ERR(ret);
        return CMPCL_ERR_ASN1_PARSING;

    }
    return 0;
}

/*
 * Parse CMP PKIStatusInfo in DER format
 */
static int cmp_pkibody_PKIStatusInfo_parse_der(cmp_PKIStatusInfo *sinfo,
                                               unsigned char *p, unsigned char *end)
{
    int ret;
    size_t len;

    /*
       PKIStatusInfo ::= SEQUENCE {
         status        PKIStatus,
         statusString  PKIFreeText     OPTIONAL,
         failInfo      PKIFailureInfo  OPTIONAL
       }
     */

    /*
         status        PKIStatus,

       PKIStatus ::= INTEGER {
         accepted                (0),
         -- you got exactly what you asked for
         grantedWithMods        (1),
         -- you got something like what you asked for; the
         -- requester is responsible for ascertaining the differences
         rejection              (2),
         -- you don't get it, more information elsewhere in the message
         waiting                (3),
         -- the request body part has not yet been processed; expect to
         -- hear more later (note: proper handling of this status
         -- response MAY use the polling req/rep PKIMessages specified
         -- in Section 5.3.22; alternatively, polling in the underlying
         -- transport layer MAY have some utility in this regard)
         revocationWarning      (4),
         -- this message contains a warning that a revocation is
         -- imminent
         revocationNotification (5),
         -- notification that a revocation has occurred
         keyUpdateWarning       (6)
         -- update already done for the oldCertId specified in
         -- CertReqMsg
       }
     */

    if ((ret = mbedtls_asn1_get_int(&p, end, &sinfo->PKIStatus)) != 0) {
        MBEDTLS_ERR(ret);
        return CMPCL_ERR_ASN1_PARSING;
    }
    /* not accepted ?
       int ok = sinfo->PKIStatus == CMP_PKISTATUS_ACCEPTED;
       if(ok) {
        CMPDBGV( "Response with PKIStatus: CMP_PKISTATUS_ACCEPTED");
       } else {
        CMPERRV( "Response with PKIStatus: %d", sinfo->PKIStatus );
       }*/
    if (p == end) {
        return 0;
    }

    /*
         statusString  PKIFreeText     OPTIONAL,
            PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
     */
    unsigned char *tmpp = p;
    if ((ret = mbedtls_asn1_get_tag(&tmpp, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) == 0) {
        len += tmpp-p;
        CMPERRV("Response StatusString(s): ");
        if ((ret = cmp_pkibody_PKIFreeText_parse_der(&p, p+len, &sinfo->statusString)) != 0) {
            return ret;
        }
    }

    if (p == end) {
        return 0;
    }

    /*
         failInfo      PKIFailureInfo  OPTIONAL
         PKIFailureInfo ::= BIT STRING
     */
    if ((ret = mbedtls_asn1_get_bitstring(&p, end, &sinfo->PKIFailureInfo)) == 0) {
        len = sinfo->PKIFailureInfo.len;
        unsigned char *errMsg = errMsg = sinfo->statusString->buf.p;
        CMPERRV("PKIFailureInfo %#1x %#1x %#1x %#1x: %.*s",
                len > 0 ? (unsigned char) sinfo->PKIFailureInfo.p[0] : 0,
                len > 1 ? (unsigned char) sinfo->PKIFailureInfo.p[1] : 0,
                len > 2 ? (unsigned char) sinfo->PKIFailureInfo.p[2] : 0,
                len > 3 ? (unsigned char) sinfo->PKIFailureInfo.p[3] : 0,
                (int) sinfo->statusString->buf.len, errMsg);
        if (len > 4) {
            CMPWARNS("PKIFailureInfo field has more than four bytes!");
        }
    } else {
        MBEDTLS_ERR(ret);
        return CMPCL_ERR_ASN1_PARSING;
    }

    if (p != end) {
        MBEDTLS_ERR(MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        return CMPCL_ERR_ASN1_PARSING;
    }
    return 0;
}

/*
 * Parse CMP CertifiedKeyPair in DER format
 */
static int cmp_pkibody_CertifiedKeyPair_parse_der(
    cmp_CertifiedKeyPair *ckp,
    unsigned char *p, unsigned char *end)
{
    int ret;
    size_t len;

    /*
       CertifiedKeyPair ::= SEQUENCE {
         certOrEncCert       CertOrEncCert,
         privateKey      [0] EncryptedValue      OPTIONAL,
         -- see [CRMF] for comment on encoding
         publicationInfo [1] PKIPublicationInfo  OPTIONAL
       }
     */
    /*
       CertOrEncCert ::= CHOICE {
         certificate     [0] CMPCertificate,
         encryptedCert   [1] EncryptedValue
       }
     */

    int certChoice = *p ^ MBEDTLS_ASN1_CONTEXT_SPECIFIC ^ MBEDTLS_ASN1_CONSTRUCTED;

    if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC | certChoice)) {
        return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;
    }

    switch (certChoice) {
        case 0:
            ckp->cert_d.p = p;
            ckp->cert = mbedtls_calloc(1, sizeof(struct mbedtls_x509_crt));
            if ((ret = mbedtls_x509_crt_parse_der(ckp->cert, p, len))) {
                return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;
            }
            g_rc_len_cert = len;
            p += len;
            /*
                 certificate     [0] CMPCertificate,
             */
            break;
        default:
            CMPERRV("Error, unsupported CertOrEncCert choice %d\n", certChoice);
            ret = CMPCL_ERR_CERT_OR_ENCCERT;
            break;
    }

    if (p != end) {
        return MBEDTLS_ERR_X509_INVALID_FORMAT +
               MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }
    return 0;
}


/*
 * Parse CMP CertResponse in DER format
 */
static int cmp_pkibody_certrep_parse_der(cmp_CertResponse *response,
                                         unsigned char *p, unsigned char *end)
{
    int ret;
    size_t len;

    /*
       CertResponse ::= SEQUENCE {
         certReqId           INTEGER,
         status              PKIStatusInfo,
         certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
         rspInfo             OCTET STRING        OPTIONAL
         -- analogous to the id-regInfo-utf8Pairs string defined
         -- for regInfo in CertReqMsg [CRMF]
       }
     */
    /*
       CertResponse ::= SEQUENCE {
     */
    if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_SEQUENCE)) {
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    /*
         certReqId           INTEGER,
     */
    if ((ret = mbedtls_asn1_get_int(&p, end, &response->certReqId)) != 0) {
        return MBEDTLS_ERR_X509_INVALID_VERSION + ret;

    }
    /*
       status              PKIStatusInfo,
     */

    /*
       PKIStatusInfo ::= SEQUENCE
     */
    if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_SEQUENCE)) {
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    if ((ret = cmp_pkibody_PKIStatusInfo_parse_der(&response->status, p, p+len)) != 0) {
        return MBEDTLS_ERR_X509_INVALID_VERSION + ret;
    }
    p += len;

    /* optional elements? */
    if (p == end) {
        return 0;
    }
    /*
       certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
     */
    if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_SEQUENCE)) {
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    response->certifiedKeyPair = mbedtls_calloc(1, sizeof(struct cmp_CertifiedKeyPair));
    if ((ret = cmp_pkibody_CertifiedKeyPair_parse_der(response->certifiedKeyPair, p, p+len)) != 0) {
        return MBEDTLS_ERR_X509_INVALID_VERSION + ret;
    }
    p += len;

    if (p != end) {
        return MBEDTLS_ERR_X509_INVALID_FORMAT +
               MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }
    return 0;
}

/*
 * Parse CMP CertRepMessage in DER format
 */
static int cmp_pkibody_crepmsg_parse_der(cmp_CertRepMessage *crep,
                                         unsigned char *p, unsigned char *end)
{
    int ret;
    size_t len;

    /*
       CertRepMessage ::= SEQUENCE {
         caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                          OPTIONAL,
         response         SEQUENCE OF CertResponse
       }
     */

    /*
     *     caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                          OPTIONAL,
     */
    if (!PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1)) {
        if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_SEQUENCE)) {
            return MBEDTLS_ERR_X509_INVALID_FORMAT;
        }
        /* caPubs seen = len */
        g_rc_len_caPubs = len;
        p += len;
    }

    /*      response         SEQUENCE OF CertResponse */
    if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_SEQUENCE)) {
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    crep->response = mbedtls_calloc(1, sizeof(struct cmp_CertResponse));
    if ((ret = cmp_pkibody_certrep_parse_der(crep->response, p, p+len)) != 0) {
        CMPERRS("Parsing of cerRep body failed!");
        return CMPCL_ERR_CERTREP_B_PARSING;
    }
    p += len;


    if (p != end) {
        return MBEDTLS_ERR_X509_INVALID_FORMAT +
               MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }
    return 0;
}

/*
 * Parse CMP Error Message Content in DER format
 */
static int cmp_pkibody_errmsgcnt_parse_der(cmp_ErrorMsgContent *emc,
                                           unsigned char *p, unsigned char *end)
{
    int ret;
    size_t len;

    /*
       ErrorMsgContent ::= SEQUENCE {
       pKIStatusInfo          PKIStatusInfo,
       errorCode              INTEGER           OPTIONAL,
       -- implementation-specific error codes
       errorDetails           PKIFreeText       OPTIONAL
       -- implementation-specific error details
       }
     */
    /*
       PKIStatusInfo ::= SEQUENCE
     */
    if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_SEQUENCE)) {
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }
    if ((ret = cmp_pkibody_PKIStatusInfo_parse_der(&emc->pKIStatusInfo, p, p+len))) {
        return ret;

    }
    p += len;
    if (p == end) {
        return 0;
    }

    /*errorCode              INTEGER           OPTIONAL,*/
    unsigned char *tmpp = p;

    if ((ret = mbedtls_asn1_get_tag(&tmpp, end, &len, MBEDTLS_ASN1_INTEGER)) == 0) {
        if ((ret = mbedtls_asn1_get_int(&p, end, &emc->errorCode)) != 0) {
            MBEDTLS_ERR(ret);
            return CMPCL_ERR_ASN1_PARSING;
        }
        CMPERRV("Response with Error Code: %d", emc->errorCode);
        if (p == end) {
            return 0;
        }
    }

    /*
            errorDetails           PKIFreeText       OPTIONAL
               PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
     */
    tmpp = p;
    if ((ret = mbedtls_asn1_get_tag(&tmpp, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) == 0) {
        len += tmpp-p;
        CMPERRV("Response Error Detail(s): ");
        if ((ret = cmp_pkibody_PKIFreeText_parse_der(&p, p+len, &emc->errorDetails)) != 0) {
            return ret;
        }
    }

    if (p != end) {
        MBEDTLS_ERR(MBEDTLS_ERR_X509_INVALID_FORMAT +
                    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        return CMPCL_ERR_ASN1_PARSING;
    }

    return 0;
}

/*
 * Parse and check CMP PKIMessage in DER format
 */
int cmp_pkimessage_parse_check_der(cmp_ctx *ctx, int expected_type, cmp_pkimessage *cmp,
                                   unsigned char *buf, size_t buflen)
{
    int ret;
    size_t len;
    unsigned char *p, *end;


    /* needed to print sizes of chosen parts of the message
     * initialize to zero for each new PKIMessage
     */
    g_rc_len_extraCerts = 0;
    g_rc_n_extraCerts = 0;
    g_rc_len_caPubs = 0;
    g_rc_len_cert = 0;

    /*
     * Check for valid input
     */
    if (cmp == NULL || buf == NULL || buflen == 0) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    p = buf;
    end = p + buflen;

    /*
     * consume the raw DER data
     */
    cmp->raw.p = buf;
    cmp->raw.len = buflen;

    /*
     * PKIMessage ::= SEQUENCE {
     *    header           PKIHeader,
     *    body             PKIBody,
     *    protection   [0] PKIProtection OPTIONAL,
     *    extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
     *                     OPTIONAL
     * }
     */
    if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_SEQUENCE)) {
        cmp_pkimessage_free(cmp);
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    if (len != (size_t) (end - p)) {
        cmp_pkimessage_free(cmp);
        return MBEDTLS_ERR_X509_INVALID_FORMAT +
               MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

    /*
     * PKIHeader ::= SEQUENCE {
     */
    cmp->header.p = p;

    if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_SEQUENCE)) {
        cmp_pkimessage_free(cmp);
        return MBEDTLS_ERR_X509_INVALID_FORMAT + ret;
    }

    if ((ret = cmp_header_parse_check_der(ctx, cmp, p, p+len)) != 0) {
        return ret;
    }

    cmp->header.len = p + len - cmp->header.p;
    p += len;

    /*
     * PKIBody ::= CHOICE {       -- message-specific body elements
     */
    cmp->body.p = p;

    int bodytype = *p ^ MBEDTLS_ASN1_CONTEXT_SPECIFIC ^ MBEDTLS_ASN1_CONSTRUCTED;

    if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC | bodytype)) {
        ret += MBEDTLS_ERR_X509_INVALID_FORMAT;
        goto err;
    }

    if (bodytype != MBEDTLS_CMP_PKIBODY_ERROR && bodytype != expected_type) {
        CMPERRV("Wrong response type %d", bodytype);
        ret = CMPCL_ERR_WRONG_RESP_TYPE;
        goto err;
    }

    switch (bodytype) {
        case MBEDTLS_CMP_PKIBODY_IP:
        case MBEDTLS_CMP_PKIBODY_CP:
        case MBEDTLS_CMP_PKIBODY_KUP:
            /* Within the bodytype, there's always an extra TL block */
            if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_SEQUENCE)) {
                return MBEDTLS_ERR_X509_INVALID_FORMAT;
            }
            if ((cmp->crep = mbedtls_calloc(1, sizeof(struct cmp_CertRepMessage))) == NULL) {
                CMPERRS("Out of memory!");
                ret = CMPCL_ERR_MEMORY_ALLOCATION;
                goto err;
            }
            ;
            ret = cmp_pkibody_crepmsg_parse_der(cmp->crep, p, p+len);
            break;
        case MBEDTLS_CMP_PKIBODY_ERROR:
            if (PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_SEQUENCE)) {
                return MBEDTLS_ERR_X509_INVALID_FORMAT;
            }
            cmp->error = mbedtls_calloc(1, sizeof(cmp_ErrorMsgContent));
            if ((ret = cmp_pkibody_errmsgcnt_parse_der(cmp->error, p, p+len)) != 0) {
                CMPERRS("PKIBody error message parse failed!");
                goto err;
            }
            ret = -1;
            break;
        case MBEDTLS_CMP_PKIBODY_PKICONF:
            CMPDBGS("PKIConf message received!");
            break;
        default:
            CMPERRV("Unsupported body type %d", bodytype);
            ret = CMPCL_ERR_UNSUPPORTED_BODYTYPE;
            break;
    }

err:
    if (ret != 0) {
        cmp_pkimessage_free(cmp);
        return ret;
    }

    cmp->body.len = p + len - cmp->body.p;
    p += len;

    /*
     *    protection   [0] PKIProtection OPTIONAL,
     */

    if (!PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0)) {
        cmp->protection = mbedtls_calloc(1, sizeof(mbedtls_asn1_bitstring));
        if ((ret = mbedtls_asn1_get_bitstring(&p, p + len, cmp->protection)) != 0) {
            CMPERRS("Failed to retrieve protection bitstring!");
            cmp_pkimessage_free(cmp);
            return MBEDTLS_ERR_X509_INVALID_FORMAT;
        }
    } else {
        CMPDBGS("WARNING: Received PKIMessage not protected!");
    }

    /*
     *    extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
     *                     OPTIONAL
     */
    if (!PARSE_ASN1_CONSTRUCTED_TAG(MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1)) {
        cmp->extraCerts.p = p;
        cmp->extraCerts.len = len;


        if ((ret = cmp_extra_certs_parse_check(ctx, cmp)) != 0) {
            cmp_pkimessage_free(cmp);
            return MBEDTLS_ERR_X509_INVALID_FORMAT;
        }
        p += cmp->extraCerts.len;
    }


    if (p != end) {
        CMPERRV("Unexpected end of response; length difference = " SIZEFMT, p - end);
        cmp_pkimessage_free(cmp);
        return MBEDTLS_ERR_X509_INVALID_FORMAT +
               MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

    /*  verify received certificate */

    /* 1. check CMP protection */
    if (cmp->protection == NULL || cmp_prot_check(ctx, cmp) != 0) {

        CMPDBGV("Response protection %s",
                cmp->protection == NULL ? "not present!" :  "could not be verified!");

        if (ctx->unprotected_errors == 0 ||
            (bodytype != MBEDTLS_CMP_PKIBODY_PKICONF &&
             cmp->crep->response->status.PKIStatus == 0)) {
            cmp_pkimessage_free(cmp);
            cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_NOTAUTHORIZED);
            return -1;
        }
    }


    /*
     * 2. check validity of signer cert (chain)
     */
    if (cmp->protection != NULL && cmp->pbmp == NULL) {  /* only if signature-based protection */


        if (ctx->prot_trust_anchor == NULL) {
            CMPERRS("No protection trust anchor provided. Cannot validate protection chain!");
            cmp_pkimessage_free(cmp);
            return -1;
        }

        if ((ret = cmp_x509_crt_verify(ctx->extraCerts,  //mbedtls_x509_crt *crt,
                                       ctx->prot_trust_anchor, //mbedtls_x509_crt *trust_ca,
                                       ctx->prot_crls, //mbedtls_x509_crl *ca_crl,
                                       &cmp->sender //mbedtls_x509_name *exp_name
                                       )) != 0) {
            cmp_ctx_set_failinfo(ctx, CMP_PKIFAILINFO_NOTAUTHORIZED);

            cmp_pkimessage_free(cmp);
            return ret;
        }
    }

    /*
       CMPINFOV("received PKIMessage header length: %d", cmp->header.len);
       if ( g_rc_len_cert > 0 )
        CMPINFOV("received certificate length: %d", g_rc_len_cert);
       if ( g_rc_len_caPubs > 0 )
        CMPINFOV("received caPubs length: %d", g_rc_len_caPubs);
       if (cmp->protection != NULL && cmp->pbmp != NULL)
        CMPINFOV("PBM-based protection");
       else if (cmp->protection != NULL && cmp->pbmp == NULL)
        CMPINFOV("signature-based protection");
       else
        CMPINFOV("no protection");
       CMPINFOV("received PKIMessage protection length: %d", protection_len);
       CMPINFOV("received %d extraCerts with total length: %d", g_rc_n_extraCerts, g_rc_len_extraCerts);
       CMPINFOV("response PKIMessage overhead (excl. certs): %d", buflen - g_rc_len_cert - g_rc_len_caPubs - g_rc_len_extraCerts);
       CMPINFOV("response PKIMessage total length: %d", buflen);
     */
    return 0;
}

void cmp_CertifiedKeyPair_free(cmp_CertifiedKeyPair *certifiedKeyPair)
{
    if (certifiedKeyPair == NULL) {
        return;
    }
    if (certifiedKeyPair->cert) {
        mbedtls_x509_crt_free(certifiedKeyPair->cert);
        mbedtls_free(certifiedKeyPair->cert);
    }
    mbedtls_platform_zeroize(certifiedKeyPair, sizeof(cmp_CertifiedKeyPair));
}

void cmp_PKIStatusInfo_free(cmp_PKIStatusInfo *sinfo)
{
    if (sinfo == NULL) {
        return;
    }
    cmp_asn1_sequence_free(sinfo->statusString);
    cmp_asn1_bitstring_free(&sinfo->PKIFailureInfo);
    mbedtls_platform_zeroize(sinfo, sizeof(cmp_PKIStatusInfo));
}

void cmp_CertResponse_free(cmp_CertResponse *response)
{
    if (response == NULL) {
        return;
    }
    cmp_PKIStatusInfo_free(&response->status);
    if (response->certifiedKeyPair) {
        cmp_CertifiedKeyPair_free(response->certifiedKeyPair);
        mbedtls_free(response->certifiedKeyPair);
    }
    mbedtls_platform_zeroize(response, sizeof(cmp_CertResponse));
}


void cmp_CertRepMessage_free(cmp_CertRepMessage *crep)
{
    if (crep == NULL) {
        return;
    }
    if (crep->response) {
        cmp_CertResponse_free(crep->response);
        mbedtls_free(crep->response);
    }
    mbedtls_platform_zeroize(crep, sizeof(cmp_CertRepMessage));
}


void cmp_ErrorMsgContent_free(cmp_ErrorMsgContent *cerr)
{
    if (cerr == NULL) {
        return;
    }
    cmp_PKIStatusInfo_free(&cerr->pKIStatusInfo);
    cmp_asn1_sequence_free(cerr->errorDetails);
    mbedtls_platform_zeroize(cerr, sizeof(cmp_ErrorMsgContent));
}


/*
 * Initialize a CMP PKIMessage
 */
void cmp_pkimessage_init(cmp_pkimessage *msg)
{
    memset(msg, 0, sizeof(cmp_pkimessage));
}

/*
 * Unallocate all CMP data
 */
void cmp_pkimessage_free(cmp_pkimessage *msg)
{
    mbedtls_x509_name *name_cur = NULL;
    mbedtls_x509_name *name_prv = NULL;

    if (msg == NULL) {
        return;
    }
    if (msg->crep) {
        cmp_CertRepMessage_free(msg->crep);
        mbedtls_free(msg->crep);
        msg->crep = NULL;
    }
    if (msg->error) {
        cmp_ErrorMsgContent_free(msg->error);
        mbedtls_free(msg->error);
        msg->error = NULL;
    }
    name_cur = msg->sender.next;
    while (name_cur != NULL) {
        name_prv = name_cur;
        name_cur = name_cur->next;
        mbedtls_platform_zeroize(name_prv, sizeof(mbedtls_x509_name));
        mbedtls_free(name_prv);
    }

    name_cur = msg->recipient.next;
    while (name_cur != NULL) {
        name_prv = name_cur;
        name_cur = name_cur->next;
        mbedtls_platform_zeroize(name_prv, sizeof(mbedtls_x509_name));
        mbedtls_free(name_prv);
    }
    if (msg->pbmp) {
        cmp_PBMParameter_free(msg->pbmp);
        mbedtls_free(msg->pbmp);
    }
    if (msg->protection) {
        mbedtls_platform_zeroize(msg->protection, sizeof(mbedtls_asn1_bitstring));
        mbedtls_free(msg->protection);
    }

    mbedtls_platform_zeroize(msg->raw.p, msg->raw.len);

    mbedtls_platform_zeroize(msg, sizeof(cmp_pkimessage));
}

/* #endif */ /* MBEDTLS_CMP_PARSE_C */
