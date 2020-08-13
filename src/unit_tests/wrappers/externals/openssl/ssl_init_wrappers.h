/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SSL_INIT_WRAPPERS_H
#define SSL_INIT_WRAPPERS_H

#include <stdint.h>
#include <openssl/crypto.h>

int __wrap_OPENSSL_init_ssl(uint64_t opts,
                            const OPENSSL_INIT_SETTINGS * settings);

#endif
