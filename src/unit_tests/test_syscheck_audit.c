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

/* redefinitons/wrapping */

int __wrap_OS_ConnectUnixDomain()
{
    return mock();
}

int __wrap_IsDir(const char * file)
{
    check_expected(file);
    return mock();
}

int __wrap_IsLink(const char * file)
{
    check_expected(file);
    return mock();
}

int __wrap_IsFile(const char * file)
{
    check_expected(file);
    return mock();
}

int __wrap_IsSocket(const char * sock)
{
    check_expected(sock);
    return mock();
}

int __wrap_audit_restart()
{
    return mock();
}

int __wrap__minfo()
{
    return 0;
}

int __wrap__merror()
{
    return 0;
}

int __wrap__mdebug1()
{
    return 0;
}

int __wrap_fopen(const char *filename, const char *mode)
{
    check_expected(filename);
    return mock();
}

int __wrap_fwrite()
{
    return 1;
}

int __wrap_fprintf()
{
    return 1;
}

int __wrap_fclose()
{
    return 0;
}

int __wrap_unlink()
{
    return 1;
}

int __wrap_symlink(const char *path1, const char *path2)
{
    check_expected(path1);
    check_expected(path2);
    return mock();
}

int __wrap_audit_open()
{
    return 1;
}

int __wrap_audit_close()
{
    return 1;
}

int __wrap_audit_get_rule_list()
{
    return mock();
}

int __wrap_W_Vector_length()
{
    return mock();
}

int __wrap_search_audit_rule()
{
    return mock();
}

int __wrap_audit_add_rule()
{
    return mock();
}

int __wrap_W_Vector_insert_unique()
{
    return mock();
}

static int free_string(void **state)
{
    char * string = *state;
    free(string);
    return 0;
}

/* tests */


void test_check_auditd_enabled(void **state)
{
    (void) state;
    int ret;

    ret = check_auditd_enabled();
    assert_return_code(ret, 0);
}


void test_init_auditd_socket_success(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_OS_ConnectUnixDomain, 124);
    ret = init_auditd_socket();
    assert_int_equal(ret, 124);
}


void test_init_auditd_socket_failure(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_OS_ConnectUnixDomain, -5);
    ret = init_auditd_socket();
    assert_int_equal(ret, -1);
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


void test_audit_get_id(void **state)
{
    (void) state;

    const char* event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 res=1";

    char *ret;
    ret = audit_get_id(event);
    *state = ret;

    assert_string_equal(ret, "1571145421.379:659");
}


void test_init_regex(void **state)
{
    (void) state;
    int ret;

    ret = init_regex();

    assert_int_equal(ret, 0);
}


void test_add_audit_rules_syscheck_not_added(void **state)
{
    (void) state;

    char *entry = "/var/test";
    os_calloc(2, sizeof(char *), syscheck.dir);
    os_calloc(strlen(entry) + 2, sizeof(char), syscheck.dir[0]);
    snprintf(syscheck.dir[0], strlen(entry) + 1, "%s", entry);
    os_calloc(2, sizeof(int *), syscheck.opts);
    syscheck.opts[0] |= WHODATA_ACTIVE;
    syscheck.max_audit_entries = 100;

    // Read loaded rules in Audit
    will_return(__wrap_audit_get_rule_list, 5);

    // Audit added rules
    will_return(__wrap_W_Vector_length, 3);

    // Rule already not added
    will_return(__wrap_search_audit_rule, 0);

    // Add rule
    will_return(__wrap_audit_add_rule, 1);
    will_return(__wrap_W_Vector_insert_unique, 1);

    int ret;
    ret = add_audit_rules_syscheck();

    assert_int_equal(ret, 1);
}


void test_add_audit_rules_syscheck_added(void **state)
{
    (void) state;

    char *entry = "/var/test";
    os_calloc(2, sizeof(char *), syscheck.dir);
    os_calloc(strlen(entry) + 2, sizeof(char), syscheck.dir[0]);
    snprintf(syscheck.dir[0], strlen(entry) + 1, "%s", entry);
    os_calloc(2, sizeof(int *), syscheck.opts);
    syscheck.opts[0] |= WHODATA_ACTIVE;
    syscheck.max_audit_entries = 100;

    // Read loaded rules in Audit
    will_return(__wrap_audit_get_rule_list, 5);

    // Audit added rules
    will_return(__wrap_W_Vector_length, 3);

    // Rule already added
    will_return(__wrap_search_audit_rule, 1);

    // Add rule
    will_return(__wrap_W_Vector_insert_unique, 1);

    int ret;
    ret = add_audit_rules_syscheck();

    free(syscheck.dir[0]);
    free(syscheck.dir);
    free(syscheck.opts);

    assert_int_equal(ret, 1);
}


void test_filterkey_audit_events_custom(void **state)
{
    (void) state;

    char *key = "test_key";
    os_calloc(2, sizeof(char *), syscheck.audit_key);
    os_calloc(strlen(key) + 2, sizeof(char), syscheck.audit_key[0]);
    snprintf(syscheck.audit_key[0], strlen(key) + 1, "%s", key);

    int ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=test_key";
    ret = filterkey_audit_events(event);

    free(syscheck.audit_key[0]);
    free(syscheck.audit_key);

    assert_int_equal(ret, 2);
}


void test_filterkey_audit_events_discard(void **state)
{
    (void) state;

    char *key = "test_key";
    os_calloc(2, sizeof(char *), syscheck.audit_key);
    os_calloc(strlen(key) + 2, sizeof(char), syscheck.audit_key[0]);
    snprintf(syscheck.audit_key[0], strlen(key) + 1, "%s", key);

    int ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=\"test_invalid_key\"";
    ret = filterkey_audit_events(event);

    free(syscheck.audit_key[0]);
    free(syscheck.audit_key);

    assert_int_equal(ret, 0);
}


void test_filterkey_audit_events_hc(void **state)
{
    (void) state;

    int ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=\"wazuh_hc\"";
    ret = filterkey_audit_events(event);

    assert_int_equal(ret, 3);
}


void test_filterkey_audit_events_fim(void **state)
{
    (void) state;

    int ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=\"wazuh_fim\"";
    ret = filterkey_audit_events(event);

    assert_int_equal(ret, 1);
}


void test_gen_audit_path(void **state)
{
    (void) state;

    char * cwd = "/root";
    char * path0 = "/root/test/";
    char * path1 = "/root/test/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/root/test/file");
}


void test_gen_audit_path2(void **state)
{
    (void) state;

    char * cwd = "/root/test";
    char * path0 = "/root/test/";
    char * path1 = "/root/test/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/root/test/file");
}


void test_gen_audit_path3(void **state)
{
    (void) state;

    char * cwd = "/";
    char * path0 = "/root/test/";
    char * path1 = "/root/test/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/root/test/file");
}


void test_gen_audit_path4(void **state)
{
    (void) state;

    char * cwd = "/";
    char * path0 = "/";
    char * path1 = "/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/file");
}


void test_gen_audit_path5(void **state)
{
    (void) state;

    char * cwd = "/root";
    char * path0 = "/";
    char * path1 = "/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/file");
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
        cmocka_unit_test_teardown(test_audit_get_id, free_string),
        cmocka_unit_test(test_init_regex),
        cmocka_unit_test(test_add_audit_rules_syscheck_added),
        cmocka_unit_test(test_add_audit_rules_syscheck_not_added),
        cmocka_unit_test(test_filterkey_audit_events_custom),
        cmocka_unit_test(test_filterkey_audit_events_discard),
        cmocka_unit_test(test_filterkey_audit_events_fim),
        cmocka_unit_test(test_filterkey_audit_events_hc),
        cmocka_unit_test_teardown(test_gen_audit_path, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path2, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path3, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path4, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path5, free_string),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
