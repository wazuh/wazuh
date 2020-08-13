/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "digest_wrappers.h"
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>


int __wrap_EVP_DigestUpdate(__attribute__((unused)) EVP_MD_CTX *ctx,
                            const void *data,
                            size_t count) {
   check_expected(data);
   check_expected(count);
   return mock();
}
