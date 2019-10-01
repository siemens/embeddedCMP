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

#define CMP_CLIENT_HTTPD 0 /* define to 1 to enable demo http server, else 0 */

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
#define INSTA
//#define NETGUARD

#if !defined INSTA && !defined NETGUARD
# include "cmpclient_config-ext.h"
#endif

/* define details of selected CA and associated certs/keys */

#ifdef INSTA

# define CERTS_ROOT_PATH    PATH_FS    "certs/insta/"

# define RECIPIENT_NAME "C=FI,O=Insta Demo,CN=Insta Demo CA" /* only needed for PBM */
/* if set, use given subject name, else use name from file PATH_TO_VENDOR_CERT_PEM */
# define IMPRINTING_SUBJECT_NAME "CN=Device,serialNumber=0000000001,O=Nokia,OU=Test"
# define BOOTSTRAPPING_SUBJECT_NAME "CN=Operation,O=Nokia,OU=Test"

/* CMP server */
# define SERVER_HOST   "91.213.161.196" // IP address must be used if no proxy is used, corresponds to "pki.certificate.fi"
# define SERVER_PORT   8700
# define SERVER_PATH   "pkix/" // Insta CA requires that SERVER_PATH has trailing '/'

/* HTTP Proxy example, if needed */
# define PROXY_NAME    "192.168.0.100"
# define PROXY_PORT    9400

//# define UNPROTECTED_IR   /* IR may be unprotected if authenticated by LRA */
# define PBM_SECRET "insta"
# define REFERENCE "3078"

#endif

#ifdef NETGUARD
# define CERTS_ROOT_PATH    PATH_FS   "certs/netguard/"
# define RECIPIENT_NAME    "C=FI,ST=Uusimaa,L=Espoo,O=Nokia,OU=Security,CN=NetGuard Test CA" /* only needed for PBM */
/* if set, use given subject name, else use name from file PATH_TO_VENDOR_CERT_PEM */
//#define SUBJECT_NAME "CN=Device,serialNumber=0000000001,O=Nokia,OU=Test"
/* CMP server */
# define SERVER_HOST   "certifier.mynetwork"
# define SERVER_PORT   8080
# define SERVER_PATH   "pkix/"
/* Proxy */
# define PROXY_NAME    "194.145.60.1"
# define PROXY_PORT    9400

//# define UNPROTECTED_IR   /* IR may be unprotected if authenticated by LRA */
# define PBM_SECRET "9pp8-b35i-Xd3Q-udNR"
# define REFERENCE "4787"

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

// trusted protection CA certificates /CRLs
#define PATH_TO_PROTECTION_TRUST_ANCHOR_PEM    CERTS_ROOT_PATH  "trusted/prot_ca.crt" /* fatfs supports out-of-the-box only 8.3 names! */
#ifndef PATH_TO_PROTECTION_CRLS
# define PATH_TO_PROTECTION_CRLS                CERTS_ROOT_PATH  "trusted/prot_crl.crl"
#endif

// trusted enrollment CA certificates /CRLs
#define PATH_TO_ENROLLMENT_TRUST_ANCHOR_PEM    CERTS_ROOT_PATH  "trusted/enr_ca.crt" /* fatfs supports out-of-the-box only 8.3 names! */
#ifndef PATH_TO_ENROLLMENT_CRLS
# define PATH_TO_ENROLLMENT_CRLS                CERTS_ROOT_PATH  "trusted/enr_crl.crl"
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
# define IMPRINTING_SERVER_PATH SERVER_PATH
#endif
#ifndef BOOTSTRAPPING_SERVER_PATH
# define BOOTSTRAPPING_SERVER_PATH SERVER_PATH
#endif
#ifndef UPDATING_SERVER_PATH
# define UPDATING_SERVER_PATH SERVER_PATH
#endif

#ifndef IMPRINTING_SUBJECT_NAME
# define IMPRINTING_SUBJECT_NAME SUBJECT_NAME
#endif
#ifndef BOOTSTRAPPING_SUBJECT_NAME
# define BOOTSTRAPPING_SUBJECT_NAME SUBJECT_NAME
#endif



#endif /* CMPCLIENT_CONFIG_H_ */
