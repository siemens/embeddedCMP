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

/* **************************************************************** */
/* cmpcl_log.c                                                   */
/* Implementation of the configurable CMP logging interface.        */
/* **************************************************************** */

#include "cmpcl_log.h"
#include <stdio.h>      /* printf  */

/* ---------------------------------------------------------------- */
/* Global log function — defaults to printf                         */
/* ---------------------------------------------------------------- */
static cmp_log_func_t g_cmp_log_func = printf;

/* ---------------------------------------------------------------- */
/* Null sink — silently discards all output                         */
/* ---------------------------------------------------------------- */
static int cmp_log_null_sink(const char *format, ...)
{
    (void)format; /* Prevent unused parameter warning */
    return 0;
}

/* ---------------------------------------------------------------- */
/* cmp_set_log_function()                                           */
/* ---------------------------------------------------------------- */
void cmp_set_log_function(cmp_log_func_t func)
{
    g_cmp_log_func = func != NULL ? func : printf;
}

/* ---------------------------------------------------------------- */
/* cmp_get_log_function()                                           */
/* ---------------------------------------------------------------- */
cmp_log_func_t cmp_get_log_function(void)
{
    return g_cmp_log_func;
}

/* ---------------------------------------------------------------- */
/* cmp_silence_log()                                                */
/* ---------------------------------------------------------------- */
void cmp_silence_log(void)
{
    cmp_set_log_function(cmp_log_null_sink);
}
