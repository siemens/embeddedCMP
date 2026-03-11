/*
 *  Copyright (c) 2025 Siemens AG
 * *
 *  Licensed under the Apache License, Version 2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 * cmpclient_config.h
 */

#ifndef CMPCLIENT_CONFIG_H_
#define CMPCLIENT_CONFIG_H_

/* define hash and signature algorithm for signature protection and proof-of-possession */
#define SIG_PROT_MD_ALG MBEDTLS_MD_SHA256
#define POPO_MD_ALG MBEDTLS_MD_SHA256

/* define method to for proof of possession */
#define POPO_METHOD CMP_CTX_POPO_SIGNATURE

/* authentication method: if PBM_SECRET is set and not KUR, then PBM, else signature unless IR and UNPROTECTED_IR is defined  */

/* EC curve to be used for key generation */
#define NEW_KEY_ECCURVE "secp256r1"

/* select one CA to be used */
// #define PLAYGROUND
#define MOCK_CA
// #define LOCAL_RA_CA
// #define INSTA
// #define DOCKER_EJBCA
// XXXX NETGUARD was not tested yet
// #define NETGUARD

/* define details of selected CA and associated certs/keys */

#ifdef LOCAL_RA_CA

// local LigthweightCmpRaComponent

/* CMP server */

#define USE_PLAIN_HTTP 0

# define SERVER_HOST   "localhost"
# define SERVER_PORT   6000
# define SERVER_PATH_IR   "onlinelra"
# define SERVER_PATH_CR   "onlinelra"
# define SERVER_PATH_KUR   "onlinelra"

# define CERTS_ROOT_PATH "./resources/certs/local_ra_lra/"

// vendor credentials
#define PATH_TO_VENDOR_CERT_PEM         CERTS_ROOT_PATH  "vendor/VD_CERT.PEM"
#define PATH_TO_VENDOR_KEY_PEM          CERTS_ROOT_PATH  "vendor/VD_PRIV.PEM"
#define PATH_TO_VENDOR_CHAIN_PEM        CERTS_ROOT_PATH  "vendor/VD_CHAIN.PEM"

// operational credentials
#define PATH_TO_OPERATIONAL_CERT_PEM    CERTS_ROOT_PATH  "operat/OP_CERT.PEM"
#define PATH_TO_OPERATIONAL_KEY_PEM     CERTS_ROOT_PATH  "operat/OP_PRIV.PEM"
#define PATH_TO_OPERATIONAL_CHAIN_PEM   CERTS_ROOT_PATH  "operat/OP_CHAIN.PEM"

// protection credentials
#define PATH_TO_PROTECTION_CERT CERTS_ROOT_PATH "protection/CMP_EE_Cert.pem"
#define PATH_TO_PROTECTION_KEY CERTS_ROOT_PATH "protection/CMP_EE_Key.pem"
#define PATH_TO_PROTECTION_CHAIN CERTS_ROOT_PATH "protection/CMP_EE_Chain.pem"

// trusted protection CA certificates /CRLs
#define PATH_TO_PROTECTION_TRUST_ANCHOR_PEM    CERTS_ROOT_PATH  "trusted/prot_ca.crt"
# define PATH_TO_PROTECTION_CRLS NULL

// trusted enrollment CA certificates /CRLs
#define PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM    "trusted/root_cert.pem"
# define PATH_TO_ENROLLMENT_CRLS NULL

# define RECIPIENT_NAME "CN=recip"
/* if set, use given subject name, else use name from file PATH_TO_VENDOR_CERT_PEM */
# define IMPRINTING_SUBJECT_NAME "CN=subject"
# define BOOTSTRAPPING_SUBJECT_NAME "CN=subject"

# define PBM_SECRET "myPresharedSecret"
# define PBM_KID "keyIdentification"
#define PBM_OWF MBEDTLS_MD_SHA256
#define PBM_MAC MBEDTLS_MD_SHA1

#endif

#ifdef MOCK_CA

/* CMP test-suite Mock CA */
#define USE_PLAIN_HTTP 1
# define SERVER_HOST   "127.0.0.1"
# define SERVER_PORT   5000
# define SERVER_PATH_IR   "issuing"
# define SERVER_PATH_CR   "issuing"
# define SERVER_PATH_KUR   "issuing"

# define CERTS_ROOT_PATH "./resources/certs/local_ra_lra/"

/* enrollment output paths */
#define PATH_TO_VENDOR_CERT_PEM         CERTS_ROOT_PATH  "vendor/VD_CERT.PEM"
#define PATH_TO_VENDOR_KEY_PEM          CERTS_ROOT_PATH  "vendor/VD_PRIV.PEM"
#define PATH_TO_VENDOR_CHAIN_PEM        CERTS_ROOT_PATH  "vendor/VD_CHAIN.PEM"

/* operational credentials (unused for -i, kept for completeness) */
#define PATH_TO_OPERATIONAL_CERT_PEM    CERTS_ROOT_PATH  "operat/OP_CERT.PEM"
#define PATH_TO_OPERATIONAL_KEY_PEM     CERTS_ROOT_PATH  "operat/OP_PRIV.PEM"
#define PATH_TO_OPERATIONAL_CHAIN_PEM   CERTS_ROOT_PATH  "operat/OP_CHAIN.PEM"

/* protection credentials (unused for PBM-protected IR) */
#define PATH_TO_PROTECTION_CERT CERTS_ROOT_PATH "protection/CMP_EE_Cert.pem"
#define PATH_TO_PROTECTION_KEY CERTS_ROOT_PATH "protection/CMP_EE_Key.pem"
#define PATH_TO_PROTECTION_CHAIN CERTS_ROOT_PATH "protection/CMP_EE_Chain.pem"

/* enable enrollment chain validation for local mock server */
#define PATH_TO_PROTECTION_TRUST_ANCHOR_PEM    NULL
# define PATH_TO_PROTECTION_CRLS NULL
#define PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM    "trusted/root_cert.pem"
# define PATH_TO_ENROLLMENT_CRLS NULL

# define RECIPIENT_NAME "CN=recip"
# define IMPRINTING_SUBJECT_NAME "CN=embeddedcmp-ir"
# define BOOTSTRAPPING_SUBJECT_NAME "CN=embeddedcmp-cr"

# define PBM_SECRET "SiemensIT"
# define PBM_KID "embeddedcmp-ir"
#define PBM_OWF MBEDTLS_MD_SHA256
#define PBM_MAC MBEDTLS_MD_SHA256

#endif


#ifdef PLAYGROUND

// PPKI Certificate Management Playground

/* CMP server */

#define USE_PLAIN_HTTP 0

//# define SERVER_HOST   "signservice-playground.ct.siemens.com"
# define SERVER_HOST   "ppki-playground.ct.siemens.com"
# define SERVER_PORT   443

# define SERVER_PATH_IR   "/ejbca/publicweb/cmp/PlaygroundECC_PBE"
# define SERVER_PATH_CR   "/ejbca/publicweb/cmp/PlaygroundECC"
# define SERVER_PATH_KUR   "/ejbca/publicweb/cmp/PlaygroundCMPSigning"

# define CERTS_ROOT_PATH "./resources/certs/playground/"
// vendor credentials
#define PATH_TO_VENDOR_CERT_PEM         CERTS_ROOT_PATH  "vendor/VD_CERT.PEM"
#define PATH_TO_VENDOR_KEY_PEM          CERTS_ROOT_PATH  "vendor/VD_PRIV.PEM"
#define PATH_TO_VENDOR_CHAIN_PEM        CERTS_ROOT_PATH  "vendor/VD_CHAIN.PEM"

// operational credentials
#define PATH_TO_OPERATIONAL_CERT_PEM    CERTS_ROOT_PATH  "operat/OP_CERT.PEM"
#define PATH_TO_OPERATIONAL_KEY_PEM     CERTS_ROOT_PATH  "operat/OP_PRIV.PEM"
#define PATH_TO_OPERATIONAL_CHAIN_PEM   CERTS_ROOT_PATH  "operat/OP_CHAIN.PEM"


// protection credentials
#define PATH_TO_PROTECTION_CERT CERTS_ROOT_PATH "protection/CMP_EE_Cert.pem"
#define PATH_TO_PROTECTION_KEY CERTS_ROOT_PATH "protection/CMP_EE_Key.pem"
#define PATH_TO_PROTECTION_CHAIN CERTS_ROOT_PATH "protection/CMP_EE_Chain.pem"

// trusted protection CA certificates /CRLs
#define PATH_TO_PROTECTION_TRUST_ANCHOR_PEM    CERTS_ROOT_PATH  "trusted/prot_ca.crt"
# define PATH_TO_PROTECTION_CRLS NULL

// trusted enrollment CA certificates /CRLs
#define PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM    CERTS_ROOT_PATH  "trusted/enr_ca.crt"
# define PATH_TO_ENROLLMENT_CRLS NULL

# define RECIPIENT_NAME "CN=recip"
/* if set, use given subject name, else use name from file PATH_TO_VENDOR_CERT_PEM */
# define IMPRINTING_SUBJECT_NAME \
    "CN=subject,OU=PPKI Playground,OU=Corporate Technology,OU=For internal test purposes only,O=Siemens,C=DE"
# define BOOTSTRAPPING_SUBJECT_NAME \
    "CN=my_ECC,OU=PPKI Playground,OU=Corporate Technology,OU=For internal test purposes only,O=Siemens,C=DE"

# define PBM_SECRET "SecretCmp"
# define PBM_KID "keyIdentification"

#define PBM_OWF MBEDTLS_MD_SHA256
#define PBM_MAC MBEDTLS_MD_SHA256

#define UNPROTECTED_ERRORS 1

#endif


#ifdef INSTA

/* CMP server */
#define USE_PLAIN_HTTP 1
# define SERVER_HOST   "91.213.161.196" // IP address must be used if no proxy is used, corresponds to "pki.certificate.fi"
# define SERVER_PORT   8700
# define SERVER_PATH_IR   "pkix/" // Insta CA requires that SERVER_PATH has trailing '/'
# define SERVER_PATH_CR   "pkix/"
# define SERVER_PATH_KUR   "pkix/"

# define CERTS_ROOT_PATH "./resources/certs/insta/"
// vendor credentials
#define PATH_TO_VENDOR_CERT_PEM         CERTS_ROOT_PATH  "vendor/VD_CERT.PEM"
#define PATH_TO_VENDOR_KEY_PEM          CERTS_ROOT_PATH  "vendor/VD_PRIV.PEM"
#define PATH_TO_VENDOR_CHAIN_PEM        CERTS_ROOT_PATH  "vendor/VD_CHAIN.PEM"

// operational credentials
#define PATH_TO_OPERATIONAL_CERT_PEM    CERTS_ROOT_PATH  "operat/OP_CERT.PEM"
#define PATH_TO_OPERATIONAL_KEY_PEM     CERTS_ROOT_PATH  "operat/OP_PRIV.PEM"
#define PATH_TO_OPERATIONAL_CHAIN_PEM   CERTS_ROOT_PATH  "operat/OP_CHAIN.PEM"

// protection credentials
#define PATH_TO_PROTECTION_CERT PATH_TO_VENDOR_CERT_PEM
#define PATH_TO_PROTECTION_KEY PATH_TO_VENDOR_KEY_PEM
#define PATH_TO_PROTECTION_CHAIN PATH_TO_VENDOR_CHAIN_PEM

// trusted protection CA certificates /CRLs
#define PATH_TO_PROTECTION_TRUST_ANCHOR_PEM    CERTS_ROOT_PATH  "trusted/prot_ca.crt"
# define PATH_TO_PROTECTION_CRLS NULL

// trusted enrollment CA certificates /CRLs
#define PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM    CERTS_ROOT_PATH  "trusted/enr_ca.crt"
# define PATH_TO_ENROLLMENT_CRLS NULL

# define RECIPIENT_NAME "C=FI,O=Insta Demo,CN=Insta Demo CA" /* only needed for PBM */
/* if set, use given subject name, else use name from file PATH_TO_VENDOR_CERT_PEM */
# define IMPRINTING_SUBJECT_NAME "CN=Device,serialNumber=0000000001,O=Nokia,OU=Test"
# define BOOTSTRAPPING_SUBJECT_NAME "CN=Operation,O=Nokia,OU=Test"

# define PBM_SECRET "insta"
# define PBM_KID "3078"
#define PBM_OWF MBEDTLS_MD_SHA256
#define PBM_MAC MBEDTLS_MD_SHA1

#endif

#ifdef DOCKER_EJBCA

/* CMP server */
#define USE_PLAIN_HTTP 1
# define SERVER_HOST   "127.0.0.1"
# define SERVER_PORT   6080
# define SERVER_PATH_IR   "ejbca/publicweb/cmp/cmp_imprint_RA"
# define SERVER_PATH_CR   "ejbca/publicweb/cmp/cmp_bootstrap_RA"
# define SERVER_PATH_KUR   "ejbca/publicweb/cmp/cmp_client"

# define CERTS_ROOT_PATH "./resources/certs/docker_ejbca/"
// vendor credentials
#define PATH_TO_VENDOR_CERT_PEM         CERTS_ROOT_PATH  "vendor/VD_CERT.PEM"
#define PATH_TO_VENDOR_KEY_PEM          CERTS_ROOT_PATH  "vendor/VD_PRIV.PEM"
#define PATH_TO_VENDOR_CHAIN_PEM        CERTS_ROOT_PATH  "vendor/VD_CHAIN.PEM"

// operational credentials
#define PATH_TO_OPERATIONAL_CERT_PEM    CERTS_ROOT_PATH  "operat/OP_CERT.PEM"
#define PATH_TO_OPERATIONAL_KEY_PEM     CERTS_ROOT_PATH  "operat/OP_PRIV.PEM"
#define PATH_TO_OPERATIONAL_CHAIN_PEM   CERTS_ROOT_PATH  "operat/OP_CHAIN.PEM"

// protection credentials
#define PATH_TO_PROTECTION_CERT PATH_TO_VENDOR_CERT_PEM
#define PATH_TO_PROTECTION_KEY PATH_TO_VENDOR_KEY_PEM
#define PATH_TO_PROTECTION_CHAIN NULL

// trusted protection CA certificates /CRLs
#define PATH_TO_PROTECTION_TRUST_ANCHOR_PEM    CERTS_ROOT_PATH  "trusted/trusted.crt"
# define PATH_TO_PROTECTION_CRLS NULL

// trusted enrollment CA certificates /CRLs
#define PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM    CERTS_ROOT_PATH  "trusted/trusted.crt"
# define PATH_TO_ENROLLMENT_CRLS NULL

# define RECIPIENT_NAME "CN=CUSTOMER_ISSUING_CA" /* only needed for PBM */
/* if set, use given subject name, else use name from file PATH_TO_VENDOR_CERT_PEM */
# define IMPRINTING_SUBJECT_NAME \
    "CN=test-genCMPClientDemo,OU=For testing purposes only,O=Siemens,C=DE,OU=IDevID"
# define BOOTSTRAPPING_SUBJECT_NAME \
    "CN=test-genCMPClientDemo,OU=For testing purposes only,O=Siemens,C=DE"

# define PBM_SECRET "SecretCmp"
# define PBM_KID ""
#define PBM_OWF MBEDTLS_MD_SHA256
#define PBM_MAC MBEDTLS_MD_SHA256

#endif


#ifdef NETGUARD
// XXXX not tested!

# define CERTS_ROOT_PATH    PATH_FS   "certs/netguard/"
# define RECIPIENT_NAME    "C=FI,ST=Uusimaa,L=Espoo,O=Nokia,OU=Security,CN=NetGuard Test CA" /* only needed for PBM */
/* if set, use given subject name, else use name from file PATH_TO_VENDOR_CERT_PEM */

/* CMP server */
# define SERVER_HOST   "certifier.mynetwork"
# define SERVER_PORT   8080
# define SERVER_PATH_IR   "pkix/"
/* Proxy */
# define PROXY_NAME    "194.145.60.1"
# define PROXY_PORT    9400

# define PBM_SECRET "9pp8-b35i-Xd3Q-udNR"
# define PBM_KID "4787"

#endif

#ifndef USE_PLAIN_HTTP
# define USE_PLAIN_HTTP 0
#endif

#ifndef SNI_HOSTNAME
# define SNI_HOSTNAME SERVER_HOST
#endif

/* MBED TLS server configuration */
#define TLS_CREDENTIAL_ROOT CERTS_ROOT_PATH "tlssrv/"
#define TLS_SERVER_ROOT TLS_CREDENTIAL_ROOT "srvcrt.crt"
#define TLS_CLIENT_KEY TLS_CREDENTIAL_ROOT "clientkey.key"
#define TLS_CLIENT_CERT TLS_CREDENTIAL_ROOT "clientcert.crt"

#ifndef IMPRINTING_SERVER_HOST
# define IMPRINTING_SERVER_HOST SERVER_HOST
#endif
#ifndef BOOTSTRAPPING_SERVER_HOST
# define BOOTSTRAPPING_SERVER_HOST SERVER_HOST
#endif
#ifndef UPDATING_SERVER_HOST
# define UPDATING_SERVER_HOST SERVER_HOST
#endif

#ifndef IMPRINTING_SERVER_PORT
# define IMPRINTING_SERVER_PORT SERVER_PORT
#endif
#ifndef BOOTSTRAPPING_SERVER_PORT
# define BOOTSTRAPPING_SERVER_PORT SERVER_PORT
#endif
#ifndef UPDATING_SERVER_PORT
# define UPDATING_SERVER_PORT SERVER_PORT
#endif

#ifndef COAP_PORT
# define COAP_PORT 5683
#endif

#ifndef IMPRINTING_SERVER_PATH
# define IMPRINTING_SERVER_PATH SERVER_PATH_IR
#endif
#ifndef BOOTSTRAPPING_SERVER_PATH
# define BOOTSTRAPPING_SERVER_PATH SERVER_PATH_IR
#endif
#ifndef UPDATING_SERVER_PATH
# define UPDATING_SERVER_PATH SERVER_PATH_IR
#endif

#ifndef IMPRINTING_SUBJECT_NAME
# define IMPRINTING_SUBJECT_NAME SUBJECT_NAME
#endif
#ifndef BOOTSTRAPPING_SUBJECT_NAME
# define BOOTSTRAPPING_SUBJECT_NAME SUBJECT_NAME
#endif



#endif /* CMPCLIENT_CONFIG_H_ */
