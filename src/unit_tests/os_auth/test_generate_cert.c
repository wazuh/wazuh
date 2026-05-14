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

#include "generate_cert.h"

static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}


static void test_generate_cert_success(void **state) {
    FILE key_file = {0};
    FILE cert_file = {0};

    will_return(__wrap_EVP_PKEY_new, 1);

    will_return(__wrap_X509_new, 1);
    will_return(__wrap_X509_sign, 1);

    expect_string(__wrap_wfopen, path, "key_path");
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, &key_file);

    will_return(__wrap_PEM_write_PrivateKey, 1);

    expect_value(__wrap_fclose, _File, &key_file);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_wfopen, path, "cert_path");
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, &cert_file);

    will_return(__wrap_PEM_write_X509, 1);
    expect_value(__wrap_fclose, _File, &cert_file);

    will_return(__wrap_fclose, 0);

    int ret_value = generate_cert(1024, 2048, "key_path", "cert_path", "/C=US/ST=California/CN=Wazuh/");
    assert_int_equal(ret_value, 0);
}

static void test_generate_cert_success_typo(void **state) {
    FILE key_file = {0};
    FILE cert_file = {0};

    will_return(__wrap_EVP_PKEY_new, 1);

    will_return(__wrap_X509_new, 1);
    will_return(__wrap_X509_sign, 1);

    expect_string(__wrap_wfopen, mode, "wb");
    expect_string(__wrap_wfopen, path, "key_path");
    will_return(__wrap_wfopen, &key_file);

    will_return(__wrap_PEM_write_PrivateKey, 1);

    expect_value(__wrap_fclose, _File, &key_file);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_wfopen, path, "cert_path");
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, &cert_file);

    will_return(__wrap_PEM_write_X509, 1);
    expect_value(__wrap_fclose, _File, &cert_file);

    will_return(__wrap_fclose, 0);

    int ret_value = generate_cert(1024, 2048, "key_path", "cert_path", "/C=US/ST=California/CN=Wazuh/asdfg/");
    assert_int_equal(ret_value, 0);
}

static void test_save_key_fail(void **state) {
    FILE key_file = {0};
    FILE cert_file = {0};

    will_return(__wrap_EVP_PKEY_new, 1);

    will_return(__wrap_X509_new, 1);
    will_return(__wrap_X509_sign, 1);

    expect_string(__wrap_wfopen, path, "key_path");
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, &key_file);

    will_return(__wrap_PEM_write_PrivateKey, 0);
    expect_string(__wrap__merror, formatted_msg, "Cannot dump private key.");

    expect_value(__wrap_fclose, _File, &key_file);
    will_return(__wrap_fclose, 0);

    int ret_value = generate_cert(1024, 2048, "key_path", "cert_path", "/C=US/ST=California/CN=Wazuh/");

    assert_int_equal(ret_value, 1);
}

static void test_save_key_fail_fopen(void **state) {
    FILE key_file = {0};

    will_return(__wrap_EVP_PKEY_new, 1);

    will_return(__wrap_X509_new, 1);
    will_return(__wrap_X509_sign, 1);

    expect_string(__wrap_wfopen, path, "key_path");
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, NULL);

    expect_string(__wrap__merror, formatted_msg, "Cannot open key_path.");

    int ret_value = generate_cert(1024, 2048, "key_path", "cert_path", "/C=US/ST=California/CN=Wazuh/");

    assert_int_equal(ret_value, 1);
}

static void test_save_cert_fail(void **state) {
    FILE key_file = {0};
    FILE cert_file = {0};

    will_return(__wrap_EVP_PKEY_new, 1);

    will_return(__wrap_X509_new, 1);
    will_return(__wrap_X509_sign, 1);

    expect_string(__wrap_wfopen, path, "key_path");
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, &key_file);

    will_return(__wrap_PEM_write_PrivateKey, 1);

    expect_value(__wrap_fclose, _File, &key_file);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_wfopen, path, "cert_path");
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, &cert_file);

    will_return(__wrap_PEM_write_X509, 0);
    expect_string(__wrap__merror, formatted_msg, "Cannot dump certificate.");
    expect_value(__wrap_fclose, _File, &cert_file);
    will_return(__wrap_fclose, 0);

    int ret_value = generate_cert(1024, 2048, "key_path", "cert_path", "/C=US/ST=California/CN=Wazuh/");
    assert_int_equal(ret_value, 1);
}

static void test_save_cert_fail_fopen(void **state) {
    FILE key_file = {0};
    FILE cert_file = {0};

    will_return(__wrap_EVP_PKEY_new, 1);

    will_return(__wrap_X509_new, 1);
    will_return(__wrap_X509_sign, 1);

    expect_string(__wrap_wfopen, path, "key_path");
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, &key_file);

    will_return(__wrap_PEM_write_PrivateKey, 1);

    expect_value(__wrap_fclose, _File, &key_file);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_wfopen, path, "cert_path");
    expect_string(__wrap_wfopen, mode, "wb");
    will_return(__wrap_wfopen, NULL);
    expect_string(__wrap__merror, formatted_msg, "Cannot open cert_path.");

    int ret_value = generate_cert(1024, 2048, "key_path", "cert_path", "/C=US/ST=California/CN=Wazuh/");
    assert_int_equal(ret_value, 1);
}

static void test_generate_cert_key_null(void **state) {
    will_return(__wrap_EVP_PKEY_new, 0);
    will_return(__wrap_EVP_PKEY_new, NULL);

    will_return(__wrap_X509_new, 1);

    expect_string(__wrap__merror, formatted_msg, "Cannot create EVP_PKEY or EVP_PKEY_CTX structure.");
    expect_string(__wrap__merror, formatted_msg, "Cannot generate key to sign the certificate.");

    int ret_value = generate_cert(1024, 2048, "key_path", "cert_path", "/C=US/ST=California/CN=Wazuh/");
    assert_int_equal(ret_value, 1);
}

static void test_generate_cert_pkey_null(void **state) {
    will_return(__wrap_EVP_PKEY_new, 0);
    will_return(__wrap_EVP_PKEY_new, NULL);

    will_return(__wrap_X509_new, 1);

    expect_string(__wrap__merror, formatted_msg, "Cannot create EVP_PKEY or EVP_PKEY_CTX structure.");
    expect_string(__wrap__merror, formatted_msg, "Cannot generate key to sign the certificate.");

    int ret_value = generate_cert(1024, 2048, "key_path", "cert_path", "/C=US/ST=California/CN=Wazuh/");
    assert_int_equal(ret_value, 1);
}

static void test_generate_cert_x509_null(void **state) {
    will_return(__wrap_EVP_PKEY_new, 1);

    will_return(__wrap_X509_new, 0);
    will_return(__wrap_X509_new, NULL);

    expect_string(__wrap__merror, formatted_msg, "Cannot generate certificate.");

    int ret_value = generate_cert(1024, 2048, "key_path", "cert_path", "/C=US/ST=California/CN=Wazuh/");
    assert_int_equal(ret_value, 1);
}

static void test_generate_cert_sign_fail(void **state) {
    FILE key_file = {0};
    FILE cert_file = {0};

    will_return(__wrap_EVP_PKEY_new, 1);

    will_return(__wrap_X509_new, 1);
    will_return(__wrap_X509_sign, 0);

    expect_string(__wrap__merror, formatted_msg, "Error signing certificate.");

    int ret_value = generate_cert(1024, 2048, "key_path", "cert_path", "/C=US/ST=California/CN=Wazuh/");
    assert_int_equal(ret_value, 1);
}
int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_generate_cert_success),
        cmocka_unit_test(test_generate_cert_success_typo),
        cmocka_unit_test(test_save_key_fail),
        cmocka_unit_test(test_save_key_fail_fopen),
        cmocka_unit_test(test_save_cert_fail),
        cmocka_unit_test(test_save_cert_fail_fopen),
        cmocka_unit_test(test_generate_cert_key_null),
        cmocka_unit_test(test_generate_cert_pkey_null),
        cmocka_unit_test(test_generate_cert_sign_fail),
        cmocka_unit_test(test_generate_cert_x509_null),


    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
