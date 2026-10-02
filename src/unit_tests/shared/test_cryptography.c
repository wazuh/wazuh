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
#include <stdbool.h>
#include <cmocka.h>

#include "shared.h"
#include "cryptography.h"
#include "../wrappers/windows/wincrypt_wrappers.h"

// Same default as src/Makefile, which libwazuh.a is built with.
#ifndef CA_NAME
#define CA_NAME "Microsoft Identity Verification Root Certificate Authority 2020"
#endif

#define SELF_PATH L"C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe"
#define OTHER_ROOT "Another Root CA"

static HCERTSTORE fake_store = (HCERTSTORE)0x1;
static PCCERT_CONTEXT fake_cert = (PCCERT_CONTEXT)0x2;

static void expect_root_store_lookup(const char *cert_name, bool matches) {
    expect_string(wrap_CertOpenSystemStore, szSubsystemProtocol, "ROOT");
    will_return(wrap_CertOpenSystemStore, fake_store);
    will_return(wrap_CertEnumCertificatesInStore, fake_cert);
    expect_CertGetNameString_call(cert_name);
    if (matches) {
        expect_value(wrap_CertFreeCertificateContext, pCertContext, fake_cert);
    } else {
        will_return(wrap_CertEnumCertificatesInStore, NULL);
    }
    will_return(wrap_CertCloseStore, TRUE);
}

static void expect_self_path(DWORD length) {
    will_return(wrap_GetModuleFileNameW, SELF_PATH);
    will_return(wrap_GetModuleFileNameW, length);
}

static void test_check_ca_available_found(void **state) {
    expect_root_store_lookup(CA_NAME, true);

    assert_int_equal(check_ca_available(), ERROR_SUCCESS);
}

static void test_check_ca_available_installed_on_demand(void **state) {
    expect_root_store_lookup(OTHER_ROOT, false);
    expect_self_path(wcslen(SELF_PATH));
    expect_WinVerifyTrust_call(SELF_PATH, ERROR_SUCCESS);
    expect_root_store_lookup(CA_NAME, true);

    assert_int_equal(check_ca_available(), ERROR_SUCCESS);
}

static void test_check_ca_available_installed_despite_failed_verification(void **state) {
    expect_root_store_lookup(OTHER_ROOT, false);
    expect_self_path(wcslen(SELF_PATH));
    expect_WinVerifyTrust_call(SELF_PATH, CERT_E_EXPIRED);
    expect_root_store_lookup(CA_NAME, true);

    assert_int_equal(check_ca_available(), ERROR_SUCCESS);
}

static void test_check_ca_available_untrusted_signature(void **state) {
    expect_root_store_lookup(OTHER_ROOT, false);
    expect_self_path(wcslen(SELF_PATH));
    expect_WinVerifyTrust_call(SELF_PATH, CERT_E_UNTRUSTEDROOT);
    expect_root_store_lookup(OTHER_ROOT, false);

    assert_int_not_equal(check_ca_available(), ERROR_SUCCESS);
}

static void test_check_ca_available_signed_by_other_root(void **state) {
    expect_root_store_lookup(OTHER_ROOT, false);
    expect_self_path(wcslen(SELF_PATH));
    expect_WinVerifyTrust_call(SELF_PATH, ERROR_SUCCESS);
    expect_root_store_lookup(OTHER_ROOT, false);

    assert_int_not_equal(check_ca_available(), ERROR_SUCCESS);
}

static void test_check_ca_available_no_module_path(void **state) {
    expect_root_store_lookup(OTHER_ROOT, false);
    expect_self_path(0);

    assert_int_not_equal(check_ca_available(), ERROR_SUCCESS);
}

static void test_check_ca_available_truncated_module_path(void **state) {
    expect_root_store_lookup(OTHER_ROOT, false);
    expect_self_path(MAX_PATH);

    assert_int_not_equal(check_ca_available(), ERROR_SUCCESS);
}

static void test_check_ca_available_store_open_error(void **state) {
    expect_string(wrap_CertOpenSystemStore, szSubsystemProtocol, "ROOT");
    will_return(wrap_CertOpenSystemStore, NULL);

    SetLastError(ERROR_ACCESS_DENIED);
    assert_int_equal(check_ca_available(), ERROR_ACCESS_DENIED);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_check_ca_available_found),
        cmocka_unit_test(test_check_ca_available_installed_on_demand),
        cmocka_unit_test(test_check_ca_available_installed_despite_failed_verification),
        cmocka_unit_test(test_check_ca_available_untrusted_signature),
        cmocka_unit_test(test_check_ca_available_signed_by_other_root),
        cmocka_unit_test(test_check_ca_available_no_module_path),
        cmocka_unit_test(test_check_ca_available_truncated_module_path),
        cmocka_unit_test(test_check_ca_available_store_open_error),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
