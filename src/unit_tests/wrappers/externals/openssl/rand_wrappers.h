/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef RAND_WRAPPERS_H
#define RAND_WRAPPERS_H

#include <openssl/rand.h>

/* First mock() value: non-zero -> pass through to the real RAND_bytes; zero -> return the next
 * mock_type(int) as RAND_bytes' result (1 = success, 0 = failure) without touching `buf`. */
int __wrap_RAND_bytes(unsigned char *buf, int num);
extern int __real_RAND_bytes(unsigned char *buf, int num);

#endif
