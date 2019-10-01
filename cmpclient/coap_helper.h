/*
 *  Copyright (c) 2019 Siemens AG
 * *
 *  Licensed under the Apache License, Version 2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 * coap_helpers.h
 *
 *  Created on: 22.01.2019
 *      Author: kretscha
 */

#ifndef COAP_HELPER_H_
#define COAP_HELPER_H_

//#include <stdlib.h>

#include "cmpcl.h"

#ifdef  __MCUXPRESSO
#define exit(val) return(-1) /* TODO: improve handling of fatal errors */
#endif /* __KSDK__ */


extern int coap_send_receive(const char *shost, const int sport, const char *spath,
		const char *phost, const int pport,
		const unsigned char *outbuf, const size_t outlen, unsigned char **inbuf,
		size_t *inlen);


#endif /* COAP_HELPER_H_ */
