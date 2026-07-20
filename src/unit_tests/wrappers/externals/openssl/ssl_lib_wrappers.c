/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "ssl_lib_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

int __wrap_SSL_read(SSL *ssl, void *buf, int num) {
    check_expected(ssl);
    check_expected_ptr(buf);
    check_expected(num);

    snprintf(buf, num, "%s",mock_ptr_type(char*));

    return mock_type(int);
}

int __wrap_SSL_connect(__attribute__((unused)) SSL *s) {
    return mock_type(int);
}

int __wrap_SSL_get_error(__attribute__((unused)) const SSL *s, int i) {
    check_expected(i);
    return mock_type(int);
}

int __wrap_SSL_write(SSL *ssl, const void *buf, __attribute__((unused)) int num) {
    check_expected(ssl);
    check_expected(buf);
    return mock_type(int);
}

SSL *__wrap_SSL_new(SSL_CTX *ctx) {
    check_expected(ctx);
    return mock_ptr_type(SSL *);
}

void __wrap_SSL_set_bio(__attribute__((unused)) SSL *s,
                        __attribute__((unused)) BIO *rbio,
                        __attribute__((unused)) BIO *wbio) {
    return;
}
