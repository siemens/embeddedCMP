/*
 *  Copyright (c) 2019 Siemens AG
 * *
 *  Licensed under the Apache License, Version 2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  cmpclient.h
 *
 *  Created on: 05.03.2019
 *      Author: Christian Epple
 */

#ifndef CMPCLIENT_H_
#define CMPCLIENT_H_

/* **************************************************************** */
/* Define */
/* **************************************************************** */
#define MAX_NAME_LENGTH 300 /* arbitrarily chosen; TODO: replace */

/* **************************************************************** */
/* Include */
/* **************************************************************** */
#include "cmpcl.h"
#include "cmpclient_config.h"
#include "file_helpers.h"
#include "ctr_drbg.h"

int invoke_ir_transaction(cmp_send_receive_cb send_receive_func);
int invoke_cr_transaction(cmp_send_receive_cb send_receive_func);
int invoke_kur_transaction(cmp_send_receive_cb send_receive_func);

#endif
