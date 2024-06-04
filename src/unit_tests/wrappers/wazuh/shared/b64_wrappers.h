/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef B64_WRAPPERS_H
#define B64_WRAPPERS_H

#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef WIN32
#include <stdint.h>
#include <winsock2.h>
#include <windows.h>
#endif

char *__wrap_encode_base64(int size, const char *src);
void expect_encode_base64(int size, const char *src, char * ret);

char *__wrap_decode_base64(const char *src);
void expect_decode_base64(const char *src, char * ret);

#endif
