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

// #define NO_CMP /* just for CMP code size differential measurement */

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include "cmpclient.h"
#include "coap_helper.h"
#include "cmp_main.h"


/*******************************************************************************
 * Variables
 ******************************************************************************/

extern mbedtls_ctr_drbg_context ctr_drbg;
extern unsigned int __end_of_heap;

/* ************************************************************************** */

static int gen_ec_key(mbedtls_pk_context *key) {
	int ret;
	const mbedtls_ecp_curve_info *curve_info;

	if ((ret = mbedtls_pk_setup(key,
			mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0) {
		CMPERRV("Key setup failed, mbedtls_pk_setup returned 0x%04x", -ret);
		return (ret);
	}

	curve_info = mbedtls_ecp_curve_info_from_name( NEW_KEY_ECCURVE);
	if (!curve_info) {
		CMPERRS("Failed to extract ecp curve from given parameter 'NEW_KEY_ECCURVE'");
		return -1;
	}
	ret = mbedtls_ecp_gen_key(curve_info->grp_id, mbedtls_pk_ec(*key),
			&mbedtls_ctr_drbg_random, &ctr_drbg);

	if (ret == 0) {
		CMPDBGS("Generated Key");
	} else {
		CMPERRV("Key gen failed, mbedtls_ec_gen_key returned 0x%04x", ret);
	}
	return (ret);
}

/* ************************************************************************** */
static int print_certinfo(mbedtls_x509_crt *crt, const char* prefix) {
	int ret = -1;
	char certbuf[1024];
	ret = mbedtls_x509_crt_info(certbuf, 1024, prefix, crt);
	if (ret < 0) {
		CMPERRV("Failed to print cert info 0x%04x", -ret);
		return -1;
	}
	/* workaround for dangling spaces produced by mbedtls_x509_crt_info(): */
	char *p = certbuf+strlen(certbuf);
	while(p != certbuf && p[-1] == ' ')
		p--;
	while (p != certbuf && (p[-1] == '\r' || p[-1] == '\n'))
		p--;
	*p = '\0';
	CMPINFOV("%s", certbuf);
	return 0;
}

/* ************************************************************************** */
static
int invoke_cert_request(const int body_type, const char *subject_name,
		const char *sender_name, const char *recipient_name,
		const char *reference, const char *pbm_secret, const char *server_path,
		const char *server_host, int server_port,
		cmp_send_receive_cb send_receive_func,
		mbedtls_ctr_drbg_context *ctr_drbg,
		const char *path_to_existing_cert, const char *path_to_existing_chain,
		const char *path_to_protection_trust_anchor, const char *path_to_protection_crls,
		const char *path_to_enrollment_trust_anchor, const char *path_to_enrollment_crls,
		const char *path_to_existing_key,
		const char *path_to_new_cert, const char *path_to_new_chain,
		const char *path_to_new_key) {

    mbedtls_x509_crt existing_cert;
    mbedtls_x509_crt_init(&existing_cert);
    mbedtls_x509_crt existing_chain;
    mbedtls_x509_crt_init(&existing_chain);
    mbedtls_x509_crt prot_trust_anchor;
    mbedtls_x509_crt_init(&prot_trust_anchor);
    mbedtls_x509_crl prot_crls;
    mbedtls_x509_crl_init(&prot_crls);
    mbedtls_x509_crt enrol_trust_anchor;
    mbedtls_x509_crt_init(&enrol_trust_anchor);
    mbedtls_x509_crl enrol_crls;
    mbedtls_x509_crl_init(&enrol_crls);
    mbedtls_pk_context existing_key;
    mbedtls_pk_init(&existing_key);
    mbedtls_pk_context new_key;
    mbedtls_pk_init(&new_key);

	int ret = -1;
	if (send_receive_func == coap_send_receive)
		server_port = COAP_PORT;

	/* create new context */
	cmp_ctx ctx;
#ifndef NO_CMP

	ret = cmp_ctx_init(&ctx, ctr_drbg,
            POPO_METHOD, SIG_PROT_MD_ALG,
            POPO_MD_ALG, server_host, server_path, server_port, send_receive_func);
	if (ret != 0) {
		CMPERRS("Error initializing context");
		goto err;
		/* need to call cmp_ctx_free() since cmp_ctx_init() does not clean up on error */
	}

	/* Existing Cert */
	if (path_to_existing_cert != NULL) {
		if ( ( ret = append_certs_from_pem(&existing_cert, path_to_existing_cert) == 0) ) {
			CMPDBGS("Parsed existing Cert");
		} else {
			CMPERRS("Parsing Existing failed");
			goto err;
		}
	} else {
		CMPDBGS("No existing cert provided");
	}

	/* Vendor Device Chain */
	if (path_to_existing_chain != NULL) {
		if ( ( ret = append_certs_from_pem(&existing_chain, path_to_existing_chain)
				== 0) ) {
			CMPDBGS("Parsed existing Chain");
		} else {
			CMPERRS("Parsing existing Chain failed");
			goto err;
		}
	} else {
		CMPDBGS("No existing cert chain provided");
	}

	if (path_to_existing_key != NULL) {
		if( ( ret = parse_key_from_pem(&existing_key, path_to_existing_key) == 0 ) ) {
			CMPDBGS("Parsed existing Key");
		} else {
			CMPERRS("Parsing existing Key failed");
			goto err;
		}
	} else {
		CMPDBGS("No existing key provided");
	}

	/* protection trust anchor */
    if (path_to_protection_trust_anchor != NULL) {
        if( (ret = append_certs_from_pem(&prot_trust_anchor, path_to_protection_trust_anchor)
                == 0) ) {
            CMPDBGS("Parsed trusted certs");
        } else {
            CMPERRS("Parsing trusted certs failed");
            goto err;
        }
        cmp_ctx_set_prot_trust_anchor(&ctx, &prot_trust_anchor);
    } else {
        CMPDBGS("No trusted certs provided");
    }

    /* protection trust anchor CRLs*/
    if (path_to_protection_crls != NULL) {
        if( (ret = append_crls_from_pem(&prot_crls, path_to_protection_crls)
                == 0) ) {
            CMPDBGS("Parsed protection CRL");
            cmp_ctx_set_prot_crls(&ctx, &prot_crls);
        } else {
            CMPERRS("Parsing protection CRL failed");
            goto err;
        }
    } else {
        CMPDBGS("No protection CRL provided");
    }

    /* enrollment trust anchor */
    if (path_to_enrollment_trust_anchor != NULL) {
        if ((ret = append_certs_from_pem(&enrol_trust_anchor,
                path_to_enrollment_trust_anchor) == 0)) {
            CMPDBGS("Parsed enrollment trust anchor");
        } else {
            CMPERRS("Parsing enrollment trust anchor failed!");
            goto err;
        }
        cmp_ctx_set_enrol_trust_anchor(&ctx, &enrol_trust_anchor);
    } else {
        CMPDBGS("No enrollment trust anchor provided");
    }

    /* enrollment trust anchor CRLs*/
    if (path_to_enrollment_crls != NULL) {
        if ((ret = append_crls_from_pem(&enrol_crls, path_to_enrollment_crls)
                == 0)) {
            CMPDBGS("Parsed enrollment CRL");
            cmp_ctx_set_enrol_crls(&ctx, &enrol_crls);
        } else {
            CMPERRS("Parsing enrollment CRL failed");
            goto err;
        }
    } else {
        CMPDBGS("No enrollment CRL provided");
    }


    /* set proxy settings */
    if ( PROXY_NAME != NULL) {
        if (cmp_ctx_set_proxy(&ctx, PROXY_NAME, PROXY_PORT) != 0) {
            CMPERRS("Error setting proxy");
            goto err;
        }
    }

	/* set basic header info in ctx */
	if (sender_name == NULL && path_to_existing_cert != NULL) {
		char sender_name_aux[MAX_NAME_LENGTH];
		ret = mbedtls_x509_dn_gets(sender_name_aux, MAX_NAME_LENGTH,
				&existing_cert.subject);
		if (ret < 0) {
			CMPERRV(
					"Error reading subject name from existing cert. Code: 0x%04x",
					-ret);
			goto err;
		}
		sender_name = sender_name_aux;
	}
	ret = cmp_ctx_set_sender_name(&ctx, sender_name);
	if (ret != 0) {
		CMPERRS("Error setting sender name");
		goto err;
	}

	if (recipient_name == NULL && path_to_existing_cert != NULL) {
		char recipient_name_aux[MAX_NAME_LENGTH];
		ret = mbedtls_x509_dn_gets(recipient_name_aux, MAX_NAME_LENGTH,
				&existing_cert.issuer);
		if (ret < 0) {
			CMPERRV(
					"Error reading subject name from existing cert. Code: 0x%04x",
					-ret);
			goto err;
		}
		recipient_name = recipient_name_aux;
	}
	ret = cmp_ctx_set_recipient_name(&ctx, recipient_name);
	if (ret != 0)
		goto err;

    if (reference != NULL) {
        ret = cmp_ctx_set_reference(&ctx, (const unsigned char *) reference,
                strlen((const char *) reference));
        if (ret != 0)
            goto err;
    }

	/* set request specific fields */
	if ((ret = gen_ec_key(&new_key)) < 0) {
		goto err;
	}
	cmp_ctx_set_new_key(&ctx, &new_key);

	/* take given subject name or read from existing cert */
	if (subject_name == NULL && path_to_existing_cert != NULL) {
		char subject_name_aux[MAX_NAME_LENGTH];
		if (mbedtls_x509_dn_gets(subject_name_aux, MAX_NAME_LENGTH,
				&existing_cert.subject) < 0) {
			CMPERRS("Error reading subject name from existing cert");
			goto err;
		}
		subject_name = subject_name_aux;
	}

	if ((ret = cmp_ctx_set_subject_name(&ctx, subject_name)) != 0) {
		CMPERRS("Error setting subject name");
		goto err;
	}

	if (body_type != MBEDTLS_CMP_PKIBODY_IR) { /* cert-based protection */
	        if (path_to_existing_cert == NULL) {
	            CMPERRS("No certificate for CR or KUR!");
	            goto err;
	        }
	        cmp_ctx_set_cl_crt(&ctx, &existing_cert);
	        if (body_type == MBEDTLS_CMP_PKIBODY_CR) {
	            cmp_ctx_set_cl_crt_chain(&ctx, &existing_chain);
	        }
	        cmp_ctx_set_prot_key(&ctx, &existing_key);
	} else if (pbm_secret != NULL && body_type != MBEDTLS_CMP_PKIBODY_KUR) { /* this enables use of PBM */
        ret = cmp_ctx_set_pbm_secret(&ctx, ctr_drbg,
                (const unsigned char *) pbm_secret,
                strlen((const char*) pbm_secret));
        if (ret != 0) {
            CMPERRS("Error initializing PBM");
            goto err;
        }
	}

#ifdef UNPROTECTED_ERRORS
	cmp_ctx_set_unprotected_errors(&ctx, 1);
#endif

#ifdef IMPLICIT_CONFIRM
	cmp_ctx_set_implicit_confirm(&ctx, 1);
#endif

#ifdef CACHE_EXTRACERTS
    cmp_ctx_set_cache_extracerts(&ctx, 1);
#endif

#ifdef UNPROTECTED_IR
    cmp_ctx_set_unprotected_ir(&ctx, 1);
#endif

	/* execute CMP operation */
	if ((ret = cmpcl_do_transaction(&ctx, body_type)) != 0) {
		CMPERRS("Certificate enrollment failed :-/");
	} else {
		print_certinfo(ctx.new_cert, "\rrecvd: "); /* TODO: find more elegant way to deal with Eclipse terminal */

		if (write_private_key_pem(&new_key, path_to_new_key) != 0) {
			CMPERRV("Failed to write new key to file %s", new_key);
			ret = -1;
		}
		if (write_cert_pem(ctx.new_cert, path_to_new_cert) != 0) {
			CMPERRV("Failed to write new cert to file %s", path_to_new_cert);
			ret = -1;
		}
		if (write_cert_pem(ctx.extraCerts, path_to_new_chain) != 0) {
			CMPERRV("Failed to write new chain to file %s", path_to_new_chain);
			ret = -1;
		}
	}

#else
        CMPWARNS("This build does not include CMP.");
        return -1;
#endif /* NO_CMP */

	err:
	/* cleanup */
	cmp_ctx_free(&ctx);
	// CMPDBGV("Free address 0x%x", &new_key);
	mbedtls_pk_free(&new_key);
	// CMPDBGV("Free address 0x%x", &existing_key)
	mbedtls_pk_free(&existing_key);
	// CMPDBGV("Free address 0x%x", &existing_chain);
	mbedtls_x509_crt_free(&existing_chain);
	// CMPDBGV("Free address 0x%x", &existing_cert);
	mbedtls_x509_crt_free(&existing_cert);
	mbedtls_x509_crt_free(&prot_trust_anchor);
	mbedtls_x509_crl_free(&prot_crls);
    mbedtls_x509_crt_free(&enrol_trust_anchor);
    mbedtls_x509_crl_free(&enrol_crls);

	PRINTF("\r\n=============END OF HEAP: %x==============\r\n", __end_of_heap);

	return ret;

}

//====================================================================================================
int invoke_kur_transaction(cmp_send_receive_cb send_receive_func) {

	int ret = -1;

	CMPINFOV("### Starting KUR transaction ###");
	ret = invoke_cert_request(MBEDTLS_CMP_PKIBODY_KUR,
			NULL,
			NULL,
			NULL,				// recipient_name
#ifdef REFERENCE
			REFERENCE
#else
			NULL
#endif
			,
			NULL
			,
			UPDATING_SERVER_PATH,
			UPDATING_SERVER_HOST,
			UPDATING_SERVER_PORT, send_receive_func, &ctr_drbg,
			PATH_TO_OPERATIONAL_CERT_PEM,
			PATH_TO_OPERATIONAL_CHAIN_PEM,
			PATH_TO_PROTECTION_TRUST_ANCHOR_PEM,
			PATH_TO_PROTECTION_CRLS,
			PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM,
			PATH_TO_ENROLLMENT_CRLS,
			PATH_TO_OPERATIONAL_KEY_PEM,
			PATH_TO_OPERATIONAL_CERT_PEM,
			PATH_TO_OPERATIONAL_CHAIN_PEM,
			PATH_TO_OPERATIONAL_KEY_PEM);

        if (ret != 0) {
            CMPERRV("### KUR transaction returned code %d ###\r\n", ret);
        }

	return ret;
}



//====================================================================================================
int invoke_cr_transaction(cmp_send_receive_cb send_receive_func) {

	int ret = -1;

	CMPINFOV("### Starting CR transaction ###");
	ret = invoke_cert_request(MBEDTLS_CMP_PKIBODY_CR,
			BOOTSTRAPPING_SUBJECT_NAME,
			NULL,
			RECIPIENT_NAME,				// recipient_name
#ifdef REFERENCE
			REFERENCE
#else
			NULL
#endif
			,
#ifdef		PBM_SECRET
			PBM_SECRET
#else
			NULL
#endif
			,
			BOOTSTRAPPING_SERVER_PATH,
			BOOTSTRAPPING_SERVER_HOST,
			BOOTSTRAPPING_SERVER_PORT,
			send_receive_func,
			&ctr_drbg,
			PATH_TO_VENDOR_CERT_PEM,
			PATH_TO_VENDOR_CHAIN_PEM,
			PATH_TO_PROTECTION_TRUST_ANCHOR_PEM,
			PATH_TO_PROTECTION_CRLS,
            PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM,
            PATH_TO_ENROLLMENT_CRLS,
            PATH_TO_VENDOR_KEY_PEM,
			PATH_TO_OPERATIONAL_CERT_PEM,
			PATH_TO_OPERATIONAL_CHAIN_PEM,
			PATH_TO_OPERATIONAL_KEY_PEM);

	CMPDBGV("### CR transaction returned code %d ###\r\n", ret);

	return ret;
}

//====================================================================================================
int invoke_ir_transaction(cmp_send_receive_cb send_receive_func) {

	int ret = -1;

	CMPINFOV("### Starting IR transaction ###");

	ret = invoke_cert_request(
			MBEDTLS_CMP_PKIBODY_IR,		// body_type,
			IMPRINTING_SUBJECT_NAME, 	// subject_name,
			IMPRINTING_SUBJECT_NAME, 	// sender_name,
			RECIPIENT_NAME,				// recipient_name
#ifdef REFERENCE						// reference
			REFERENCE
#else
			NULL
#endif
			,
#ifdef		PBM_SECRET
			PBM_SECRET
#else
			NULL
#endif
			,							// pbm_secret
			IMPRINTING_SERVER_PATH,		// server_path
			IMPRINTING_SERVER_HOST, 	// server_host
			IMPRINTING_SERVER_PORT,		// server_port,
			send_receive_func,
			&ctr_drbg,
			NULL,						// path_to_existing_cert
			NULL,						// path_to_existing_chain
			PATH_TO_PROTECTION_TRUST_ANCHOR_PEM,     // path_to_trusted_ca_certs
			PATH_TO_PROTECTION_CRLS,     // path_to_trusted_ca_crl
            PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM,
            PATH_TO_ENROLLMENT_CRLS,
			NULL,						// path_to_existing_key
			PATH_TO_VENDOR_CERT_PEM,	// path_to_new_cert,
			PATH_TO_VENDOR_CHAIN_PEM,	// path_to_new_chain
			PATH_TO_VENDOR_KEY_PEM);	// path_to_new_key

	CMPDBGV("### IR transaction returned code %d ###\r\n", ret);

	return ret;
}

