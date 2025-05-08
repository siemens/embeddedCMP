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

/* **************************************************************** */
/* HELPERS */
/* **************************************************************** */

void cmp_asn1_sequence_free(mbedtls_asn1_sequence *asn1_sequence)
{

    mbedtls_asn1_sequence *seq_cur, *seq_prv;

    seq_cur = asn1_sequence;
    while (seq_cur != NULL) {
        seq_prv = seq_cur;
        seq_cur = seq_cur->next;
        mbedtls_platform_zeroize(seq_prv, sizeof(mbedtls_x509_sequence));
        mbedtls_free(seq_prv);
    }
}

void cmp_asn1_bitstring_free(mbedtls_asn1_bitstring *asn1_bitstring)
{

    mbedtls_platform_zeroize(asn1_bitstring, sizeof(asn1_bitstring));
}

char *strdup(const char *src)
{
    char *result = NULL;
    int rc = setStr((unsigned char **) &result, (unsigned char *) src, strlen(src) + 1);
    return rc == 0 ? (char *) result : NULL;
}

char *strndup(const char *s, size_t n)
{
    char *result = NULL;
    int rc = setStr((unsigned char **) &result, (unsigned char *) s, n + 1);
    if (rc == 0) {
        result[n] = '\0';
        return result;
    } else {
        return NULL;
    }
}

int setStr(unsigned char **dst, const unsigned char *src, const size_t len)
{
    if (!src) {
        return 0;
    }
    if (*dst) {
        mbedtls_free(*dst);
    }
    if ((*dst = (unsigned char *) mbedtls_calloc(1, len)) == NULL) {
        CMPERRS("Error allocating space\n");
        return CMPCL_ERR_MEMORY_ALLOCATION;
    }
    memcpy(*dst, src, len);
    return 0;
}

#ifdef DEVELOPMENT
int write_to_file(char *output_file, const unsigned char *data, size_t len)
{
    FILE *f;

    if ((f = fopen(output_file, "wb")) == NULL) {
        CMPDBGV("fopen failed for %s", output_file);
        return CMPCL_ERR_FILE_OPEN;
    }

    if (fwrite(data, 1, len, f) != len) {
        CMPDBGV("fwrite failed for %s", output_file);
        fclose(f);
        return CMPCL_ERR_FILE_WRITE;
    }

    CMPDBGV("Binary data written to %s", output_file);

    fclose(f);
    return len;
}
#endif


/*
 * extracts CN from mbedtls_x509_name and stores it in a string
 * free memory from caller!
 */
char *cmp_x509_cn_gets(mbedtls_x509_name *dn)
{

    const mbedtls_x509_name *cn_start;
    char *result = NULL;

    cn_start = mbedtls_asn1_find_named_data(dn, MBEDTLS_OID_AT_CN, sizeof(MBEDTLS_OID_AT_CN) - 1);

    if (cn_start == NULL) {
        CMPDBGS("Failed to find CN in given DN");
        return NULL;
    }

    result = strndup((char *) cn_start->val.p, cn_start->val.len);

    return result;
}

/*
 * Custom wrapper for mbedtls_x509_crt_verify_with_profile()
 *
 * Verify the certificate validity, with built-in custom profile
 *
 * This function:
 *  - checks the requested CN (if any)
 *  - checks the type and size of the EE cert's key,
 *    as that isn't done as part of chain building/verification currently
 *  - builds and verifies the chain
 */
int cmp_x509_crt_verify(mbedtls_x509_crt *crt,
                        mbedtls_x509_crt *trust_ca,
                        mbedtls_x509_crl *ca_crl,
                        mbedtls_x509_name *exp_name)
{

    int ret;
    unsigned int failure_bits = 0;
    char *expected_cn = NULL;

    if (trust_ca == NULL) {
        CMPDBGS("Empty trusted certs chain. Abort verification.");
        return CMPCL_ERR_EMPTY_TRUST_CA;
    }

    if (exp_name != NULL) {

        expected_cn = cmp_x509_cn_gets(exp_name);

        if (expected_cn == NULL) {      /*CN extraction failed */
            CMPERRS("Failed to extract CN name");
            ret = CMPCL_ERR_EXTRACT_CN;
            goto err;
        }
    }

    /* for compatibility with insta CA enable SHA1*/
    mbedtls_x509_crt_profile ver_prof = mbedtls_x509_crt_profile_default;
    ver_prof.allowed_mds |= MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1);


    ret = mbedtls_x509_crt_verify_with_profile(crt, /* treat ret appropriately in caller */
                                               trust_ca, ca_crl, &ver_prof,
                                               expected_cn,
                                               &failure_bits,
                                               NULL,
                                               NULL);
/*
    if( ret == 0) {
        CMPDBGV("%s chain verified successfully", description);
    } else {
        CMPERRV("%s chain validation FAILED!", description);
        CMPERRV("mbedtls_x509_crt_verify() returned: 0x%04x", -ret);
        CMPERRV("verification failure bits: 0x%04x", failure_bits);
    }
 */

err:
    mbedtls_free(expected_cn);
    return ret;
}




/* **************************************************************** */
int cmp_ctx_set_rndm_str(unsigned char **str,
                         size_t *str_len,
                         mbedtls_ctr_drbg_context *ctr_drbg,
                         size_t len)
{
    int ret;

    if (*str) {
        mbedtls_free(*str);
    }
    *str = (unsigned char *) mbedtls_calloc(1, len);
    if (*str == NULL) {
        CMPERRS("Error allocating memory!");
        return -1;
    }
    *str_len = len;
    if ((ret = mbedtls_ctr_drbg_random(ctr_drbg, *str, len)) != 0) {
        CMPERRV("Error generating random string: %d\n", ret);
        ;
    }
    return ret;
}

/* **************************************************************** */
/* PBM */
/* **************************************************************** */

int cmp_PBMParameter_init(cmp_PBMParameter *pbmp,
                          mbedtls_ctr_drbg_context *ctr_drbg,
                          size_t salt_len,
                          mbedtls_md_type_t owf,
                          int iterationCount,
                          mbedtls_md_type_t mac)
{
    memset(pbmp, 0, sizeof(cmp_PBMParameter));

    if (cmp_ctx_set_rndm_str(&pbmp->salt,
                             &pbmp->salt_len,
                             ctr_drbg,
                             salt_len) != 0) {
        CMPERRS("Error setting PBM parameters!");
        return -1;
    }

    pbmp->owf = owf;
    pbmp->iterationCount = iterationCount;
    pbmp->mac = mac;

    return 0;
}

void cmp_PBMParameter_free(cmp_PBMParameter *pbmp)
{
    if (pbmp->salt) {
        mbedtls_free(pbmp->salt);
    }
}

int cmp_PBM_new(const cmp_PBMParameter *pbmp,
                const unsigned char *secret, size_t secret_len,
                const unsigned char *msg, size_t msg_len,
                unsigned char *mac, size_t *mac_len)
{
    unsigned char *basekey;
    unsigned int bk_len;
    int iter;
    int ret = -1;
    mbedtls_md_context_t md_ctx;
    const mbedtls_md_info_t *md_info;

    mbedtls_md_init(&md_ctx);

    basekey = (unsigned char *) mbedtls_calloc(1, MBEDTLS_MD_MAX_SIZE);

    if (!basekey) {
        CMPERRS("Error allocating memory!");
        goto err;
    }
    if (!mac) {
        goto err;
    }
    if (!pbmp) {
        goto err;
    }
    if (!msg) {
        goto err;
    }
    if (!secret) {
        goto err;
    }

    /*
     * owf identifies the hash algorithm and associated parameters used to
     * compute the key used in the MAC process.  All implementations MUST
     * support SHA-1.
     */

    if (!(md_info = mbedtls_md_info_from_type(pbmp->owf))) {
        goto err;
    }

    bk_len = mbedtls_md_get_size(md_info);

    ret = mbedtls_md_setup(&md_ctx, md_info, 0);
    if (ret != 0) {
        goto err;
    }

    ret = mbedtls_md_starts(&md_ctx);
    if (ret != 0) {
        goto err;
    }

    ret = mbedtls_md_update(&md_ctx, secret, secret_len);
    if (ret != 0) {
        goto err;
    }

    ret = mbedtls_md_update(&md_ctx, pbmp->salt, pbmp->salt_len);
    if (ret != 0) {
        goto err;
    }

    ret = mbedtls_md_finish(&md_ctx, basekey);
    if (ret != 0) {
        goto err;
    }

    iter = pbmp->iterationCount-1; /* first iteration already done above */
    while (iter-- > 0) {
        /* maybe this could be done with mbedtls_md - but *input=*ouput... */
        ret = mbedtls_md_starts(&md_ctx);
        if (ret != 0) {
            goto err;
        }
        ret = mbedtls_md_update(&md_ctx, basekey, bk_len);
        if (ret != 0) {
            goto err;
        }
        ret = mbedtls_md_finish(&md_ctx, basekey);
        if (ret != 0) {
            goto err;
        }
    }
    mbedtls_md_free(&md_ctx);

    /*
     * mac identifies the algorithm and associated parameters of the MAC
     * function to be used.  All implementations MUST support HMAC-SHA1
     * [HMAC].      All implementations SHOULD support DES-MAC and Triple-
     * DES-MAC [PKCS11].
     */
    mbedtls_md_init(&md_ctx);

    if (!(md_info = mbedtls_md_info_from_type(pbmp->mac))) {
        goto err;
    }

    *mac_len = mbedtls_md_get_size(md_info);

    ret = mbedtls_md_setup(&md_ctx, md_info, 1);
    if (ret != 0) {
        goto err;
    }

    ret = mbedtls_md_hmac_starts(&md_ctx, basekey, bk_len);
    if (ret != 0) {
        goto err;
    }

    ret = mbedtls_md_hmac_update(&md_ctx, msg, msg_len);
    if (ret != 0) {
        goto err;
    }

    ret = mbedtls_md_hmac_finish(&md_ctx, mac);
    if (ret != 0) {
        goto err;
    }

    /* cleanup */
err:
    mbedtls_md_free(&md_ctx);
    mbedtls_free(basekey);
    return ret;
}
