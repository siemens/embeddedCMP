/*
 * lwip_helper.h
 *
 *  Created on: 09.01.2019
 *      Author: kretscha
 */

#ifndef LWIP_HELPER_H_
#define LWIP_HELPER_H_

#include <stdio.h>

void setup_lwip();

/* Poll the driver, get any outstanding frames */
void poll_lwip_driver();

#endif /* LWIP_HELPER_H_ */
