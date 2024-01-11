/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "evp_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>


EVP_PKEY *__wrap_EVP_PKEY_new(void) {
    if (mock()) {
        return __real_EVP_PKEY_new();
    }

    return mock_type(EVP_PKEY *);
}
