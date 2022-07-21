/* Copyright (C) 2015, Wazuh Inc.
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
#include "../../common.h"
#include <openssl/evp.h>

extern int __real_EVP_DigestUpdate(EVP_MD_CTX *ctx,const void *data, size_t count);
int __wrap_EVP_DigestUpdate(EVP_MD_CTX *ctx,
                            const void *data,
                            size_t count) {
   if (test_mode) {
      check_expected(data);
      check_expected(count);
      return mock();
   }
   else {
     return __real_EVP_DigestUpdate(ctx, data, count);
   }
}
