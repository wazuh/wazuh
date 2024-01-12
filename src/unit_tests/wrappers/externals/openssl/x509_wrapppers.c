/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "x509_wrapppers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md) {
    return mock_type(int);
}

X509 *__wrap_X509_new(void) {
    if (mock()) {
        return __real_X509_new();
    }
    return mock_type(X509 *);
}
