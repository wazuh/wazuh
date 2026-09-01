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
#include "../wrappers/posix/unistd_wrappers.h"

// STATIC in generate_cert.c, exposed under WAZUH_UNIT_TESTING.
void build_subject_alt_name(const char *common_name, char *san, size_t san_len);

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
    // build_subject_alt_name() reads the hostname to put it in the certificate's SAN.
    will_return(__wrap_gethostname, "test-host");
    will_return(__wrap_gethostname, 0);
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
    // build_subject_alt_name() reads the hostname to put it in the certificate's SAN.
    will_return(__wrap_gethostname, "test-host");
    will_return(__wrap_gethostname, 0);
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
    // build_subject_alt_name() reads the hostname to put it in the certificate's SAN.
    will_return(__wrap_gethostname, "test-host");
    will_return(__wrap_gethostname, 0);
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
    // build_subject_alt_name() reads the hostname to put it in the certificate's SAN.
    will_return(__wrap_gethostname, "test-host");
    will_return(__wrap_gethostname, 0);
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
    // build_subject_alt_name() reads the hostname to put it in the certificate's SAN.
    will_return(__wrap_gethostname, "test-host");
    will_return(__wrap_gethostname, 0);
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
    // build_subject_alt_name() reads the hostname to put it in the certificate's SAN.
    will_return(__wrap_gethostname, "test-host");
    will_return(__wrap_gethostname, 0);
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
    // build_subject_alt_name() reads the hostname to put it in the certificate's SAN.
    will_return(__wrap_gethostname, "test-host");
    will_return(__wrap_gethostname, 0);
    will_return(__wrap_X509_sign, 0);

    expect_string(__wrap__merror, formatted_msg, "Error signing certificate.");

    int ret_value = generate_cert(1024, 2048, "key_path", "cert_path", "/C=US/ST=California/CN=Wazuh/");
    assert_int_equal(ret_value, 1);
}
/* subjectAltName construction.
 *
 * The certificate used to name its host only in the CN, which no current TLS client looks at
 * (RFC 6125: when a SAN is present the CN is ignored, and clients that find no SAN have
 * nothing to match), so nothing could verify the manager -- including a reverse proxy acting
 * as a TLS client towards it. These cover the value handed to the extension. */

#define SAN_FIXED_ENTRIES "DNS:localhost,IP:127.0.0.1,IP:::1"

static void test_build_san_includes_loopback_hostname_and_cn(void **state) {
    char san[512] = {0};

    will_return(__wrap_gethostname, "manager-01");
    will_return(__wrap_gethostname, 0);

    build_subject_alt_name("wazuh", san, sizeof(san));

    assert_string_equal(san, SAN_FIXED_ENTRIES ",DNS:manager-01,DNS:wazuh");
}

static void test_build_san_without_cn(void **state) {
    char san[512] = {0};

    will_return(__wrap_gethostname, "manager-01");
    will_return(__wrap_gethostname, 0);

    build_subject_alt_name(NULL, san, sizeof(san));

    assert_string_equal(san, SAN_FIXED_ENTRIES ",DNS:manager-01");
}

// A CN carrying a comma would otherwise close the entry and smuggle in an extra SAN name.
static void test_build_san_rejects_cn_with_separator(void **state) {
    char san[512] = {0};

    will_return(__wrap_gethostname, "manager-01");
    will_return(__wrap_gethostname, 0);

    build_subject_alt_name("wazuh,DNS:attacker.example", san, sizeof(san));

    assert_string_equal(san, SAN_FIXED_ENTRIES ",DNS:manager-01");
    assert_null(strstr(san, "attacker.example"));
}

static void test_build_san_does_not_repeat_the_hostname(void **state) {
    char san[512] = {0};

    will_return(__wrap_gethostname, "manager-01");
    will_return(__wrap_gethostname, 0);

    build_subject_alt_name("manager-01", san, sizeof(san));

    assert_string_equal(san, SAN_FIXED_ENTRIES ",DNS:manager-01");
}

// An unreadable hostname must still leave a usable certificate, not an empty extension.
static void test_build_san_survives_gethostname_failure(void **state) {
    char san[512] = {0};

    will_return(__wrap_gethostname, "");
    will_return(__wrap_gethostname, -1);

    build_subject_alt_name("wazuh", san, sizeof(san));

    assert_string_equal(san, SAN_FIXED_ENTRIES ",DNS:wazuh");
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
        cmocka_unit_test(test_build_san_includes_loopback_hostname_and_cn),
        cmocka_unit_test(test_build_san_without_cn),
        cmocka_unit_test(test_build_san_rejects_cn_with_separator),
        cmocka_unit_test(test_build_san_does_not_repeat_the_hostname),
        cmocka_unit_test(test_build_san_survives_gethostname_failure),


    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
