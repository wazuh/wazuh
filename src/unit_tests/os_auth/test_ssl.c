/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "shared.h"
#include "os_auth/auth.h"

#include "../wrappers/externals/openssl/ssl_lib_wrappers.h"

/*************************/
/* setup/teardown        */

void test_wrap_SSL_read_error_code(void **state) {
    char buffer[OS_SIZE_4096];

    expect_any(__wrap_SSL_read, ssl);
    expect_value(__wrap_SSL_read, buf, buffer);
    expect_value(__wrap_SSL_read, num, OS_SIZE_4096);
    will_return(__wrap_SSL_read, "");
    will_return(__wrap_SSL_read, -1);

    int ret =wrap_SSL_read(NULL, buffer, OS_SIZE_4096);
    assert_int_equal(ret, -1);
}

void test_wrap_SSL_read_success(void **state) {
    char buffer[OS_SIZE_4096];

    expect_any(__wrap_SSL_read, ssl);
    expect_value(__wrap_SSL_read, buf, buffer);
    expect_value(__wrap_SSL_read, num, OS_SIZE_4096);
    will_return(__wrap_SSL_read, "");
    will_return(__wrap_SSL_read, 256);

    int ret =wrap_SSL_read(NULL, buffer, OS_SIZE_4096);
    assert_int_equal(ret, 256);
}

void test_wrap_SSL_read_full_single_record(void **state) {
    char buffer[OS_SIZE_65536 + OS_SIZE_4096];

    expect_any(__wrap_SSL_read, ssl);
    expect_value(__wrap_SSL_read, buf, buffer);
    expect_value(__wrap_SSL_read, num, OS_SIZE_65536 + OS_SIZE_4096);
    will_return(__wrap_SSL_read, "");
    will_return(__wrap_SSL_read, MAX_SSL_PACKET_SIZE); // One record

    expect_any(__wrap_SSL_read, ssl);
    expect_value(__wrap_SSL_read, buf, buffer + MAX_SSL_PACKET_SIZE);
    expect_value(__wrap_SSL_read, num, OS_SIZE_65536 + OS_SIZE_4096 - MAX_SSL_PACKET_SIZE);
    will_return(__wrap_SSL_read, "");
    will_return(__wrap_SSL_read, -1); // One record

    int ret  =wrap_SSL_read(NULL, buffer, OS_SIZE_65536 + OS_SIZE_4096);
    assert_int_equal(ret, MAX_SSL_PACKET_SIZE);
}

void test_wrap_SSL_read_multi_record(void **state) {
    char buffer[OS_SIZE_65536 + OS_SIZE_4096];

    expect_any(__wrap_SSL_read, ssl);
    expect_value(__wrap_SSL_read, buf, buffer);
    expect_value(__wrap_SSL_read, num, OS_SIZE_65536 + OS_SIZE_4096);
    will_return(__wrap_SSL_read, "");
    will_return(__wrap_SSL_read, MAX_SSL_PACKET_SIZE); // One record

    expect_any(__wrap_SSL_read, ssl);
    expect_value(__wrap_SSL_read, buf, buffer + MAX_SSL_PACKET_SIZE);
    expect_value(__wrap_SSL_read, num, OS_SIZE_65536 + OS_SIZE_4096 - MAX_SSL_PACKET_SIZE);
    will_return(__wrap_SSL_read, "");
    will_return(__wrap_SSL_read, MAX_SSL_PACKET_SIZE); // Second record

    expect_any(__wrap_SSL_read, ssl);
    expect_value(__wrap_SSL_read, buf, buffer + (2* MAX_SSL_PACKET_SIZE));
    expect_value(__wrap_SSL_read, num, OS_SIZE_65536 + OS_SIZE_4096 - (2* MAX_SSL_PACKET_SIZE) );
    will_return(__wrap_SSL_read, "");
    will_return(__wrap_SSL_read, MAX_SSL_PACKET_SIZE); // Third record

    expect_any(__wrap_SSL_read, ssl);
    expect_value(__wrap_SSL_read, buf, buffer + (3* MAX_SSL_PACKET_SIZE));
    expect_value(__wrap_SSL_read, num, OS_SIZE_65536 + OS_SIZE_4096 - (3* MAX_SSL_PACKET_SIZE) );
    will_return(__wrap_SSL_read, "");
    will_return(__wrap_SSL_read, 1024); // Part of fourth record

    int ret = wrap_SSL_read(NULL, buffer, OS_SIZE_65536 + OS_SIZE_4096);
    assert_int_equal(ret, (3* MAX_SSL_PACKET_SIZE) + 1024);
}

/*************************/
int main(void) {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_wrap_SSL_read_error_code),
        cmocka_unit_test(test_wrap_SSL_read_success),
        cmocka_unit_test(test_wrap_SSL_read_full_single_record),
        cmocka_unit_test(test_wrap_SSL_read_multi_record),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
