/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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


#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"

/* redefinitons/wrapping */

int __wrap_OS_ConnectUnixDomain() {
    return mock();
}

int __wrap_IsDir(const char * file) {
    check_expected(file);
    return mock();
}

int __wrap_IsLink(const char * file) {
    check_expected(file);
    return mock();
}

int __wrap_IsFile(const char * file) {
    check_expected(file);
    return mock();
}

int __wrap_IsSocket(const char * sock) {
    check_expected(sock);
    return mock();
}

int __wrap_audit_restart() {
    return mock();
}

int __wrap__minfo() {
    return 0;
}

int __wrap__merror() {
    return 0;
}

int __wrap_fopen(const char *filename, const char *mode) {
    check_expected(filename);
    return mock();
}

int __wrap_fwrite() {
    return 1;
}

int __wrap_fprintf() {
    return 1;
}

int __wrap_fclose() {
    return 0;
}

int __wrap_unlink() {
    return 1;
}

int __wrap_symlink(const char *path1, const char *path2) {
    check_expected(path1);
    check_expected(path2);
    return mock();
}

/* tests */


void test_check_auditd_enabled(void **state)
{
    (void) state;
    int ret;

    ret = check_auditd_enabled();
    assert_int_equal(-1, ret);
}


void test_init_auditd_socket_success(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_OS_ConnectUnixDomain, 124);
    ret = init_auditd_socket();
    assert_int_equal(124, ret);
}


void test_init_auditd_socket_failure(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_OS_ConnectUnixDomain, -5);
    ret = init_auditd_socket();
    assert_int_equal(-1, ret);
}


void test_set_auditd_config_audit3_plugin_created(void **state)
{
    (void) state;

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin already created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 0);

    expect_string(__wrap_IsFile, file, audit3_socket);
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap_IsSocket, sock, "/var/ossec/queue/ossec/audit");
    will_return(__wrap_IsSocket, 0);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 0);
}


void test_set_auditd_config_audit2_plugin_created(void **state)
{
    (void) state;

    // Not Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 1);
    // Audit 2
    expect_string(__wrap_IsDir, file, "/etc/audisp/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin already created
    const char *audit2_socket = "/etc/audisp/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit2_socket);
    will_return(__wrap_IsLink, 0);

    expect_string(__wrap_IsFile, file, audit2_socket);
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap_IsSocket, sock, "/var/ossec/queue/ossec/audit");
    will_return(__wrap_IsSocket, 0);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 0);
}


void test_set_auditd_config_audit_socket_not_created(void **state)
{
    (void) state;

    syscheck.restart_audit = 1;

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin already created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 0);

    expect_string(__wrap_IsFile, file, audit3_socket);
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap_IsSocket, sock, "/var/ossec/queue/ossec/audit");
    will_return(__wrap_IsSocket, 1);

    will_return(__wrap_audit_restart, 99);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 99);
}


void test_set_auditd_config_audit_plugin_not_created(void **state)
{
    (void) state;

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin not created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 1);

    expect_string(__wrap_fopen, filename, "/var/ossec/etc/af_wazuh.conf");
    will_return(__wrap_fopen, 1);

    // Create plugin
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, 1);

    // Restart
    syscheck.restart_audit = 1;
    will_return(__wrap_audit_restart, 99);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 99);
}


void test_set_auditd_config_audit_plugin_not_created_recreate_symlink(void **state)
{
    (void) state;

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin not created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 1);

    expect_string(__wrap_fopen, filename, "/var/ossec/etc/af_wazuh.conf");
    will_return(__wrap_fopen, 1);

    // Create plugin
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, -1);
    errno = EEXIST;
    // Delete and create
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, 0);

    // Restart
    syscheck.restart_audit = 1;
    will_return(__wrap_audit_restart, 99);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 99);
}


void test_set_auditd_config_audit_plugin_not_created_recreate_symlink_error(void **state)
{
    (void) state;

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin not created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 1);

    expect_string(__wrap_fopen, filename, "/var/ossec/etc/af_wazuh.conf");
    will_return(__wrap_fopen, 1);

    // Create plugin
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, -1);
    errno = EEXIST;
    // Delete and create
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, -1);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, -1);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_check_auditd_enabled),
        cmocka_unit_test(test_init_auditd_socket_success),
        cmocka_unit_test(test_init_auditd_socket_failure),
        cmocka_unit_test(test_set_auditd_config_audit2_plugin_created),
        cmocka_unit_test(test_set_auditd_config_audit3_plugin_created),
        cmocka_unit_test(test_set_auditd_config_audit_socket_not_created),
        cmocka_unit_test(test_set_auditd_config_audit_plugin_not_created),
        cmocka_unit_test(test_set_auditd_config_audit_plugin_not_created_recreate_symlink),
        cmocka_unit_test(test_set_auditd_config_audit_plugin_not_created_recreate_symlink_error),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
