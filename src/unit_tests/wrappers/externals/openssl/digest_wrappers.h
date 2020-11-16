/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef DIGEST_WRAPPERS_H
#define DIGEST_WRAPPERS_H

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif
#include <stddef.h>
#include <openssl/evp.h>

int __wrap_EVP_DigestUpdate(EVP_MD_CTX *ctx,
                            const void *data,
                            size_t count);

#endif
