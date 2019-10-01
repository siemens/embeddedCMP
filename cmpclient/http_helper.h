/*
 * http_helper.h
 *
 *  Created on: 09.01.2019
 *      Author: kretscha
 */

#ifndef HTTP_HELPER_H_
#define HTTP_HELPER_H_

#include <stdio.h>

int http_send_receive(const char *shost, const int sport, const char *spath,
        const char *phost, const int pport,
        const unsigned char *outbuf, const size_t outlen, unsigned char **inbuf,
        size_t *inlen);

#endif /* HTTP_HELPER_H_ */
