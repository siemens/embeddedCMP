/*
 *  Copyright (c) 2019 Siemens AG
 * *
 *  Licensed under the Apache License, Version 2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  cmpcl_error.h
 *
 *  Created on: 19.08.2022
 */

#ifndef CMPCL_ERROR_H_
#define CMPCL_ERROR_H_

#ifdef __cplusplus
extern "C" {
#endif


#define CMPCL_ERR_MEMORY_ALLOCATION             -0x0004     /** Error in memory allocation  */
#define CMPCL_ERR_PBM_PARM                      -0x0005     /** Error in setting PBM Parameter */
#define CMPCL_ERR_MSGTIME_LEN                   -0x0006     /** Invalid length of UTC_TIME, must be equal to 14(MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1) */
#define CMPCL_ERR_PROXY_IP                      -0x0007     /** Error in setting proxy IP  */
#define CMPCL_ERR_EMPTY_TRUST_CA                -0x0008     /** Trusted CA structure is empty */
#define CMPCL_ERR_EXTRACT_CN                    -0x0009     /** Error in extracting CN from provided DN */
#define CMPCL_ERR_ASN1_PARSING                  -0x000A     /** Error in parsing ASN1  */
#define CMPCL_ERR_CERT_OR_ENCCERT               -0x0010     /** Invalid CertOrEncCert choice */
#define CMPCL_ERR_POPO_METHOD                   -0x0011     /** Invalid/Unsupported POPO Method */
#define CMPCL_ERR_KUR_OLDCERT                   -0x0012     /** Existing certificate missing for KUR  */
#define CMPCL_ERR_CERTREP_B_PARSING             -0x0013     /** Error in parsing certrep body */
#define CMPCL_ERR_WRONG_RESP_TYPE               -0x0014     /** Wrong response type received  */
#define CMPCL_ERR_UNSUPPORTED_BODYTYPE          -0x0015     /** Received body type not supported  */
#define CMPCL_ERR_CERT_NOT_RECEIVED             -0x0016     /** No certificate received in certrep message */
#define CMPCL_ERR_FILE_OPEN                     -0x0017     /** Error in file opening */
#define CMPCL_ERR_FILE_WRITE                    -0x0018     /** Error in file writing */


#define CMPCL_ER_BUF_LEN                        100

#ifdef __cplusplus
}
#endif

#endif /* CMPCL_ERROR_H_ */
