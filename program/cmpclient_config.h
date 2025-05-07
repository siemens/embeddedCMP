/*
 *  Copyright (c) 2019 Siemens AG
 * *
 *  Licensed under the Apache License, Version 2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 * cmpclient_config.h
 */

#ifndef CMPCLIENT_CONFIG_H_
#define CMPCLIENT_CONFIG_H_

/* by default, read private key from file, else generate new key */
//#define CMPCL_EE_GEN_KEY

/* define hash and signature algorithm for signature protection and proof-of-possession */
#define SIG_PROT_MD_ALG MBEDTLS_MD_SHA256
#define POPO_MD_ALG MBEDTLS_MD_SHA256

/* define method to for proof of possession */
#define POPO_METHOD CMP_CTX_POPO_SIGNATURE

/* authentication method: if PBM_SECRET is set and not KUR, then PBM, else signature unless IR and UNPROTECTED_IR is defined  */

/* EC curve to be used for key generation */
#define NEW_KEY_ECCURVE "secp256r1"

/* general prefix for file system paths */
#define PATH_FS ""

/* select CA to be used */
#define PLAYGROUND
// #define LOCAL_RA_CA
// #define INSTA
//#define NETGUARD

/* define details of selected CA and associated certs/keys */

#ifdef LOCAL_RA_CA
// local LigthweightCmpRaComponent

#define USE_PLAIN_HTTP 0

# define CERTS_ROOT_PATH "./resources/sdcard_root/SDHC/certs/local_ra_lra/"

# define RECIPIENT_NAME "CN=recip"
/* if set, use given subject name, else use name from file PATH_TO_VENDOR_CERT_PEM */
# define IMPRINTING_SUBJECT_NAME "CN=subject"
# define BOOTSTRAPPING_SUBJECT_NAME "CN=subject"

/* CMP server */
# define SERVER_HOST   "localhost" // IP address must be used if no proxy is used, corresponds to "pki.certificate.fi"
# define SERVER_PORT   6000
# define SERVER_PATH_IR   "onlinelra"
# define SERVER_PATH_CR   "onlinelra"
# define SERVER_PATH_KUR   "onlinelra"

//# define UNPROTECTED_IR   /* IR may be unprotected if authenticated by LRA */
# define PBM_SECRET "myPresharedSecret"
# define PBM_KID "keyIdentification"
#define PBM_OWF MBEDTLS_MD_SHA256
#define PBM_MAC MBEDTLS_MD_SHA1

#endif


#ifdef PLAYGROUND
// PPKI Certificate Management Playground

#define USE_PLAIN_HTTP 0

# define CERTS_ROOT_PATH "./resources/sdcard_root/SDHC/certs/playground/"

# define RECIPIENT_NAME "CN=recip"
/* if set, use given subject name, else use name from file PATH_TO_VENDOR_CERT_PEM */
# define IMPRINTING_SUBJECT_NAME \
    "CN=subject,OU=PPKI Playground,OU=Corporate Technology,OU=For internal test purposes only,O=Siemens,C=DE"
# define BOOTSTRAPPING_SUBJECT_NAME \
    "CN=my_ECC,OU=PPKI Playground,OU=Corporate Technology,OU=For internal test purposes only,O=Siemens,C=DE"

/* CMP server */
# define SERVER_HOST   "signservice-playground.ct.siemens.com"
# define SERVER_PORT   443

# define SERVER_PATH_IR   "/ejbca/publicweb/cmp/PlaygroundECC_PBE"

# define PBM_SECRET "SecretCmp"
# define PBM_KID "keyIdentification"

#define PBM_OWF MBEDTLS_MD_SHA256
#define PBM_MAC MBEDTLS_MD_SHA256


# define SERVER_PATH_CR   "/ejbca/publicweb/cmp/PlaygroundECC"

# define SERVER_PATH_KUR   "/ejbca/publicweb/cmp/PlaygroundCMPSigning"


#define UNPROTECTED_ERRORS 1

#endif


#ifdef INSTA

# define CERTS_ROOT_PATH "./resources/sdcard_root/SDHC/certs/insta/"

# define RECIPIENT_NAME "C=FI,O=Insta Demo,CN=Insta Demo CA" /* only needed for PBM */
/* if set, use given subject name, else use name from file PATH_TO_VENDOR_CERT_PEM */
# define IMPRINTING_SUBJECT_NAME "CN=Device,serialNumber=0000000001,O=Nokia,OU=Test"
# define BOOTSTRAPPING_SUBJECT_NAME "CN=Operation,O=Nokia,OU=Test"

/* CMP server */
#define USE_PLAIN_HTTP 1
# define SERVER_HOST   "91.213.161.196" // IP address must be used if no proxy is used, corresponds to "pki.certificate.fi"
# define SERVER_PORT   8700
# define SERVER_PATH_IR   "pkix/" // Insta CA requires that SERVER_PATH has trailing '/'
# define SERVER_PATH_CR   "pkix/"
# define SERVER_PATH_KUR   "pkix/"

/* HTTP Proxy example, if needed */
# define PROXY_NAME    "192.168.0.100"
# define PROXY_PORT    9400

//# define UNPROTECTED_IR   /* IR may be unprotected if authenticated by LRA */
# define PBM_SECRET "insta"
# define PBM_KID "3078"
#define PBM_OWF MBEDTLS_MD_SHA256
#define PBM_MAC MBEDTLS_MD_SHA1

#endif

#ifdef NETGUARD
# define CERTS_ROOT_PATH    PATH_FS   "certs/netguard/"
# define RECIPIENT_NAME    "C=FI,ST=Uusimaa,L=Espoo,O=Nokia,OU=Security,CN=NetGuard Test CA" /* only needed for PBM */
/* if set, use given subject name, else use name from file PATH_TO_VENDOR_CERT_PEM */
//#define SUBJECT_NAME "CN=Device,serialNumber=0000000001,O=Nokia,OU=Test"
/* CMP server */
# define SERVER_HOST   "certifier.mynetwork"
# define SERVER_PORT   8080
# define SERVER_PATH_IR   "pkix/"
/* Proxy */
# define PROXY_NAME    "194.145.60.1"
# define PROXY_PORT    9400

//# define UNPROTECTED_IR   /* IR may be unprotected if authenticated by LRA */
# define PBM_SECRET "9pp8-b35i-Xd3Q-udNR"
# define PBM_KID "4787"

#endif

/* paths to PEM files that hold required certificates/keys */

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
#define PATH_TO_PROTECTION_TRUST_ANCHOR_PEM    CERTS_ROOT_PATH  "trusted/prot_ca.crt" /* fatfs supports out-of-the-box only 8.3 names! */
#ifndef PATH_TO_PROTECTION_CRLS
// # define PATH_TO_PROTECTION_CRLS                CERTS_ROOT_PATH  "trusted/prot_crl.crl"
# define PATH_TO_PROTECTION_CRLS NULL
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

// trusted enrollment CA certificates /CRLs
#define PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM    CERTS_ROOT_PATH  "trusted/enr_ca.crt" /* fatfs supports out-of-the-box only 8.3 names! */
#ifndef PATH_TO_ENROLLMENT_CRLS
// # define PATH_TO_ENROLLMENT_CRLS                CERTS_ROOT_PATH  "trusted/enr_crl.crl"
# define PATH_TO_ENROLLMENT_CRLS NULL
#endif

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
