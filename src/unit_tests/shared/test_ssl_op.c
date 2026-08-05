/*
 * Copyright (C) 2015, Wazuh Inc.
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
#include "ssl_op.h"

#include "../wrappers/externals/openssl/ssl_lib_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

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

void test_get_ssl_context_default_min_version_is_tls13(void **state) {
    SSL_CTX *ctx = get_ssl_context(DEFAULT_CIPHERS);

    assert_non_null(ctx);
    assert_int_equal(SSL_CTX_get_min_proto_version(ctx), TLS1_3_VERSION);

    SSL_CTX_free(ctx);
}

void test_get_ssl_context_accepts_tls13_ciphersuites(void **state) {
    SSL_CTX *ctx = get_ssl_context("TLS_AES_128_GCM_SHA256");

    assert_non_null(ctx);

    SSL_CTX_free(ctx);
}

void test_get_ssl_context_rejects_legacy_cipher_list(void **state) {
    expect_string(__wrap__merror, formatted_msg,
                  "Invalid TLS 1.3 cipher suite list: 'HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH'");

    SSL_CTX *ctx = get_ssl_context("HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH");

    assert_null(ctx);
}

/*************************/
int main(void) {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_wrap_SSL_read_error_code),
        cmocka_unit_test(test_wrap_SSL_read_success),
        cmocka_unit_test(test_wrap_SSL_read_full_single_record),
        cmocka_unit_test(test_wrap_SSL_read_multi_record),
        cmocka_unit_test(test_get_ssl_context_default_min_version_is_tls13),
        cmocka_unit_test(test_get_ssl_context_accepts_tls13_ciphersuites),
        cmocka_unit_test(test_get_ssl_context_rejects_legacy_cipher_list),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
