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

#include "../wrappers/common.h"
#include "syscheckd/syscheck.h"

#include "../wrappers/externals/audit/libaudit_wrappers.h"
#include "../wrappers/externals/procpc/readproc_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/libc/stdlib_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/shared/audit_op_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/fs_op_wrappers.h"
#include "../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../wrappers/wazuh/shared/syscheck_op_wrappers.h"
#include "../wrappers/wazuh/shared/vector_op_wrappers.h"
#include "../wrappers/wazuh/syscheckd/create_db_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"

#include "external/procps/readproc.h"

extern volatile int audit_health_check_creation;
extern volatile int hc_thread_active;
int hc_success = 0;


int __wrap_audit_delete_rule(const char *path, const char *key) {
    check_expected(path);
    check_expected(key);

    return mock();
}

int __wrap_recv(int __fd, void *__buf, size_t __n, int __flags) {
    int ret;
    int n;
    check_expected(__fd);
    n = mock();
    if(n < __n)
        ret = n;
    else
        ret = __n;
    if(ret > 0)
        memcpy(__buf, mock_type(void*), ret);

    return ret;
}

int __wrap_pthread_cond_init(pthread_cond_t *__cond, const pthread_condattr_t *__cond_attr) {
    function_called();
    return 0;
}

int __wrap_pthread_cond_wait (pthread_cond_t *__cond, pthread_mutex_t *__mutex) {
    function_called();

    hc_thread_active = 1;

    return 0;
}

int __wrap_pthread_mutex_lock (pthread_mutex_t *__mutex) {
    function_called();
    return 0;
}

int __wrap_pthread_mutex_unlock (pthread_mutex_t *__mutex) {
    function_called();
    return 0;
}

int __wrap_CreateThread(void * (*function_pointer)(void *), void *data) {
    if(hc_success) {
        audit_health_check_creation = 1;
    }
    return 1;
}

/* setup/teardown */
static int setup_group(void **state) {
    (void) state;
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    (void) state;
    memset(&syscheck, 0, sizeof(syscheck_config));
    Free_Syscheck(&syscheck);
    test_mode = 0;
    return 0;
}

static int free_string(void **state) {
    char * string = *state;
    free(string);
    return 0;
}

static int test_audit_read_events_setup(void **state) {
    int *audit_sock;
    audit_sock = calloc(1, sizeof(int));
    *state = audit_sock;
    return 0;
}

static int test_audit_read_events_teardown(void **state) {
    int *audit_sock = *state;
    free(audit_sock);
    return 0;
}

static int setup_hc_success(void **state) {
    hc_success = 1;
    return 0;
}

static int teardown_hc_success(void **state) {
    hc_success = 0;
    return 0;
}

static int setup_add_audit_rules(void **state) {
    syscheck.symbolic_links = calloc(2, sizeof(char *));

    if (syscheck.symbolic_links == NULL) {
        return -1;
    }

    syscheck.symbolic_links[0] = NULL;

    return 0;
}

static int teardown_add_audit_rules(void **state) {
    if (syscheck.symbolic_links[0] != NULL) {
        free(syscheck.symbolic_links[0]);
        syscheck.symbolic_links[0] = NULL;
    }

    if (syscheck.symbolic_links != NULL) {
        free(syscheck.symbolic_links);
        syscheck.symbolic_links = NULL;
    }

    return 0;
}

/* tests */


void test_check_auditd_enabled_success(void **state) {
    (void) state;
    int ret;

    proc_t *mock_proc;

    mock_proc = calloc(3, sizeof(proc_t));

    snprintf(mock_proc[0].cmd, 16, "not-auditd");
    mock_proc[0].tid = 20;

    snprintf(mock_proc[1].cmd, 16, "something");
    mock_proc[1].tid = 25;

    snprintf(mock_proc[2].cmd, 16, "auditd");
    mock_proc[2].tid = 15;

    expect_value(__wrap_openproc, flags, PROC_FILLSTAT | PROC_FILLSTATUS | PROC_FILLCOM);
    will_return(__wrap_openproc, 1234);

    expect_value_count(__wrap_readproc, PT, 1234, 3);
    expect_value_count(__wrap_readproc, p, NULL, 3);
    will_return(__wrap_readproc, &mock_proc[0]);
    will_return(__wrap_readproc, &mock_proc[1]);
    will_return(__wrap_readproc, &mock_proc[2]);

    expect_value(__wrap_freeproc, p, &mock_proc[0]);
    expect_value(__wrap_freeproc, p, &mock_proc[1]);
    expect_value(__wrap_freeproc, p, &mock_proc[2]);

    expect_value(__wrap_closeproc, PT, 1234);

    ret = check_auditd_enabled();
    assert_return_code(ret, 0);
    free(mock_proc);
}

void test_check_auditd_enabled_openproc_error(void **state) {
    (void) state;
    int ret;

    expect_value(__wrap_openproc, flags, PROC_FILLSTAT | PROC_FILLSTATUS | PROC_FILLCOM);
    will_return(__wrap_openproc, NULL);

    ret = check_auditd_enabled();
    assert_int_equal(ret, -1);
}

void test_check_auditd_enabled_readproc_error(void **state) {
    (void) state;
    int ret;

    expect_value(__wrap_openproc, flags, PROC_FILLSTAT | PROC_FILLSTATUS | PROC_FILLCOM);
    will_return(__wrap_openproc, 1234);

    expect_value(__wrap_readproc, PT, 1234);
    expect_value(__wrap_readproc, p, NULL);
    will_return(__wrap_readproc, NULL);

    expect_value(__wrap_closeproc, PT, 1234);

    ret = check_auditd_enabled();
    assert_int_equal(ret, -1);
}


void test_init_auditd_socket_success(void **state) {
    (void) state;
    int ret;

    expect_any(__wrap_OS_ConnectUnixDomain, path);
    expect_any(__wrap_OS_ConnectUnixDomain, type);
    expect_any(__wrap_OS_ConnectUnixDomain, max_msg_size);
    will_return(__wrap_OS_ConnectUnixDomain, 124);

    ret = init_auditd_socket();
    assert_int_equal(ret, 124);
}


void test_init_auditd_socket_failure(void **state) {
    (void) state;
    int ret;

    expect_any(__wrap_OS_ConnectUnixDomain, path);
    expect_any(__wrap_OS_ConnectUnixDomain, type);
    expect_any(__wrap_OS_ConnectUnixDomain, max_msg_size);
    will_return(__wrap_OS_ConnectUnixDomain, -5);

    expect_string(__wrap__merror, formatted_msg, "(6636): Cannot connect to socket '/var/ossec/queue/ossec/audit'.");

    ret = init_auditd_socket();
    assert_int_equal(ret, -1);
}


void test_set_auditd_config_audit3_plugin_created(void **state) {
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


void test_set_auditd_config_wrong_audit_version(void **state) {
    (void) state;

    // Not Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 1);
    // Not Audit 2
    expect_string(__wrap_IsDir, file, "/etc/audisp/plugins.d");
    will_return(__wrap_IsDir, 1);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 0);
}


void test_set_auditd_config_audit2_plugin_created(void **state) {
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


void test_set_auditd_config_audit_socket_not_created(void **state) {
    (void) state;

    syscheck.restart_audit = 0;

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

    expect_string(__wrap__mwarn, formatted_msg, "(6909): Audit socket (/var/ossec/queue/ossec/audit) does not exist. You need to restart Auditd. Who-data will be disabled.");

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 1);
}


void test_set_auditd_config_audit_socket_not_created_restart(void **state) {
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

    expect_string(__wrap__minfo, formatted_msg, "(6023): No socket found at '/var/ossec/queue/ossec/audit'. Restarting Auditd service.");

    expect_string(__wrap_IsSocket, sock, "/var/ossec/queue/ossec/audit");
    will_return(__wrap_IsSocket, 1);

    will_return(__wrap_audit_restart, 99);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 99);
}


void test_set_auditd_config_audit_plugin_not_created(void **state) {
    (void) state;

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin not created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap__minfo, formatted_msg, "(6024): Generating Auditd socket configuration file: '/var/ossec/etc/af_wazuh.conf'");

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 1);

    expect_string(__wrap_fopen, path, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);

    expect_any_always(__wrap_fprintf, __stream);
    expect_any_always(__wrap_fprintf, formatted_msg);
    will_return_always(__wrap_fprintf, 1);
    will_return_always(__wrap_fwrite, 1);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    // Create plugin
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, 1);

    expect_string(__wrap__minfo, formatted_msg, "(6025): Audit plugin configuration (/var/ossec/etc/af_wazuh.conf) was modified. Restarting Auditd service.");

    // Restart
    syscheck.restart_audit = 1;
    will_return(__wrap_audit_restart, 99);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 99);
}


void test_set_auditd_config_audit_plugin_not_created_fopen_error(void **state) {
    (void) state;

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap__minfo, formatted_msg, "(6024): Generating Auditd socket configuration file: '/var/ossec/etc/af_wazuh.conf'");

    // Plugin not created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 1);

    expect_string(__wrap_fopen, path, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 0);

    expect_string(__wrap__merror, formatted_msg, "(1103): Could not open file '/var/ossec/etc/af_wazuh.conf' due to [(0)-(Success)].");

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, -1);
}


void test_set_auditd_config_audit_plugin_not_created_fclose_error(void **state) {
    (void) state;

    expect_string(__wrap__minfo, formatted_msg, "(6024): Generating Auditd socket configuration file: '/var/ossec/etc/af_wazuh.conf'");

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin not created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 1);

    expect_string(__wrap_fopen, path, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);

    expect_any_always(__wrap_fprintf, __stream);
    expect_any_always(__wrap_fprintf, formatted_msg);
    will_return_always(__wrap_fprintf, 1);
    will_return_always(__wrap_fwrite, 1);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, -1);

    expect_string(__wrap__merror, formatted_msg, "(1140): Could not close file '/var/ossec/etc/af_wazuh.conf' due to [(0)-(Success)].");

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, -1);
}


void test_set_auditd_config_audit_plugin_not_created_recreate_symlink(void **state) {
    (void) state;

    expect_string(__wrap__minfo, formatted_msg, "(6024): Generating Auditd socket configuration file: '/var/ossec/etc/af_wazuh.conf'");

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin not created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 1);

    expect_string(__wrap_fopen, path, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);

    expect_any_always(__wrap_fprintf, __stream);
    expect_any_always(__wrap_fprintf, formatted_msg);
    will_return_always(__wrap_fprintf, 1);
    will_return_always(__wrap_fwrite, 1);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    // Create plugin
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, -1);
    errno = EEXIST;

    expect_string(__wrap_unlink, file, "/etc/audit/plugins.d/af_wazuh.conf");
    will_return(__wrap_unlink, 0);

    // Delete and create
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, 0);

    // Do not restart
    syscheck.restart_audit = 0;

    expect_string(__wrap__mwarn, formatted_msg, "(6910): Audit plugin configuration was modified. You need to restart Auditd. Who-data will be disabled.");

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 1);
}


void test_set_auditd_config_audit_plugin_not_created_recreate_symlink_restart(void **state) {
    (void) state;

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    // Plugin not created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap__minfo, formatted_msg, "(6024): Generating Auditd socket configuration file: '/var/ossec/etc/af_wazuh.conf'");

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 1);

    expect_string(__wrap_fopen, path, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);

    expect_any_always(__wrap_fprintf, __stream);
    expect_any_always(__wrap_fprintf, formatted_msg);
    will_return_always(__wrap_fprintf, 1);
    will_return_always(__wrap_fwrite, 1);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    // Create plugin
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, -1);
    errno = EEXIST;

    expect_string(__wrap_unlink, file, "/etc/audit/plugins.d/af_wazuh.conf");
    will_return(__wrap_unlink, 0);

    // Delete and create
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, 0);

    expect_string(__wrap__minfo, formatted_msg, "(6025): Audit plugin configuration (/var/ossec/etc/af_wazuh.conf) was modified. Restarting Auditd service.");

    // Restart
    syscheck.restart_audit = 1;
    will_return(__wrap_audit_restart, 99);

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, 99);
}


void test_set_auditd_config_audit_plugin_not_created_recreate_symlink_error(void **state) {
    (void) state;

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap__minfo, formatted_msg, "(6024): Generating Auditd socket configuration file: '/var/ossec/etc/af_wazuh.conf'");

    // Plugin not created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 1);

    expect_string(__wrap_fopen, path, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);

    expect_any_always(__wrap_fprintf, __stream);
    expect_any_always(__wrap_fprintf, formatted_msg);
    will_return_always(__wrap_fprintf, 1);
    will_return_always(__wrap_fwrite, 1);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    // Create plugin
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, -1);
    errno = EEXIST;

    expect_string(__wrap_unlink, file, "/etc/audit/plugins.d/af_wazuh.conf");
    will_return(__wrap_unlink, 0);

    // Delete and create
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, -1);

    expect_string(__wrap__merror, formatted_msg, "(1134): Unable to link from '/etc/audit/plugins.d/af_wazuh.conf' to '/var/ossec/etc/af_wazuh.conf' due to [(17)-(File exists)].");

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, -1);
}


void test_set_auditd_config_audit_plugin_not_created_recreate_symlink_unlink_error(void **state) {
    (void) state;

    // Audit 3
    expect_string(__wrap_IsDir, file, "/etc/audit/plugins.d");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap__minfo, formatted_msg, "(6024): Generating Auditd socket configuration file: '/var/ossec/etc/af_wazuh.conf'");

    // Plugin not created
    const char *audit3_socket = "/etc/audit/plugins.d/af_wazuh.conf";

    expect_string(__wrap_IsLink, file, audit3_socket);
    will_return(__wrap_IsLink, 1);

    expect_string(__wrap_fopen, path, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);

    expect_any_always(__wrap_fprintf, __stream);
    expect_any_always(__wrap_fprintf, formatted_msg);
    will_return_always(__wrap_fprintf, 1);
    will_return_always(__wrap_fwrite, 1);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    // Create plugin
    expect_string(__wrap_symlink, path1, "/var/ossec/etc/af_wazuh.conf");
    expect_string(__wrap_symlink, path2, audit3_socket);
    will_return(__wrap_symlink, -1);
    errno = EEXIST;

    expect_string(__wrap_unlink, file, "/etc/audit/plugins.d/af_wazuh.conf");
    will_return(__wrap_unlink, -1);

    expect_string(__wrap__merror, formatted_msg, "(1123): Unable to delete file: '/etc/audit/plugins.d/af_wazuh.conf' due to [(17)-(File exists)].");

    int ret;
    ret = set_auditd_config();

    assert_int_equal(ret, -1);
}


void test_audit_get_id(void **state) {
    (void) state;

    const char* event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 res=1";

    char *ret;
    ret = audit_get_id(event);
    *state = ret;

    assert_string_equal(ret, "1571145421.379:659");
}


void test_audit_get_id_begin_error(void **state) {
    (void) state;

    const char* event = "audit1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 res=1";

    char *ret;
    ret = audit_get_id(event);

    assert_null(ret);
}


void test_audit_get_id_end_error(void **state) {
    (void) state;

    const char* event = "type=LOGIN msg=audit(1571145421.379:659";

    char *ret;
    ret = audit_get_id(event);

    assert_null(ret);

}


void test_init_regex(void **state) {
    (void) state;
    int ret;

    ret = init_regex();

    assert_int_equal(ret, 0);
}


void test_add_audit_rules_syscheck_not_added(void **state) {
    (void) state;

    char *entry = "/var/test";
    syscheck.dir = calloc (2, sizeof(char *));
    syscheck.dir[0] = calloc(strlen(entry) + 2, sizeof(char));
    snprintf(syscheck.dir[0], strlen(entry) + 1, "%s", entry);
    syscheck.opts = calloc (2, sizeof(int *));
    syscheck.opts[0] |= WHODATA_ACTIVE;
    syscheck.max_audit_entries = 100;

    // Audit open
    will_return(__wrap_audit_open, 1);

    // Read loaded rules in Audit
    will_return(__wrap_audit_get_rule_list, 0);

    // Audit close
    will_return(__wrap_audit_close, 1);

    expect_string(__wrap__merror, formatted_msg, "(6637): Could not read audit loaded rules.");

    // Audit added rules
    will_return(__wrap_W_Vector_length, 3);

    // Rule already not added
    will_return(__wrap_search_audit_rule, 0);

    // Add rule
    will_return(__wrap_audit_add_rule, 1);
    expect_value(__wrap_W_Vector_insert_unique, v, audit_added_dirs);
    expect_string(__wrap_W_Vector_insert_unique, element, "/var/test");
    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_W_Vector_insert_unique, 1);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string(__wrap__mdebug1, formatted_msg, "(6322): Reloaded audit rule for monitoring directory: '/var/test'");

    int ret;
    ret = add_audit_rules_syscheck(0);

    free(syscheck.opts);
    free(syscheck.dir[0]);
    free(syscheck.dir);

    assert_int_equal(ret, 1);
}


void test_add_audit_rules_syscheck_not_added_new(void **state) {
    (void) state;

    char *entry = "/var/test";
    syscheck.dir = calloc (2, sizeof(char *));
    syscheck.dir[0] = calloc(strlen(entry) + 2, sizeof(char));
    snprintf(syscheck.dir[0], strlen(entry) + 1, "%s", entry);
    syscheck.opts = calloc (2, sizeof(int *));
    syscheck.opts[0] |= WHODATA_ACTIVE;
    syscheck.max_audit_entries = 100;

    // Audit open
    will_return(__wrap_audit_open, 1);

    // Read loaded rules in Audit
    will_return(__wrap_audit_get_rule_list, 0);

    // Audit close
    will_return(__wrap_audit_close, 1);

    expect_string(__wrap__merror, formatted_msg, "(6637): Could not read audit loaded rules.");

    // Audit added rules
    will_return(__wrap_W_Vector_length, 3);

    // Rule already not added
    will_return(__wrap_search_audit_rule, 0);

    // Add rule
    will_return(__wrap_audit_add_rule, 1);
    expect_value(__wrap_W_Vector_insert_unique, v, audit_added_dirs);
    expect_string(__wrap_W_Vector_insert_unique, element, "/var/test");
    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_W_Vector_insert_unique, 0);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string(__wrap__mdebug1, formatted_msg, "(6270): Added audit rule for monitoring directory: '/var/test'");

    int ret;
    ret = add_audit_rules_syscheck(0);

    free(syscheck.opts);
    free(syscheck.dir[0]);
    free(syscheck.dir);

    assert_int_equal(ret, 1);
}


void test_add_audit_rules_syscheck_not_added_error(void **state) {
    (void) state;

    char *entry = "/var/test";
    syscheck.dir = calloc (2, sizeof(char *));
    syscheck.dir[0] = calloc(strlen(entry) + 2, sizeof(char));
    snprintf(syscheck.dir[0], strlen(entry) + 1, "%s", entry);
    syscheck.opts = calloc (2, sizeof(int *));
    syscheck.opts[0] |= WHODATA_ACTIVE;
    syscheck.max_audit_entries = 100;

    // Audit open
    will_return(__wrap_audit_open, 1);

    // Read loaded rules in Audit
    will_return(__wrap_audit_get_rule_list, 0);

    // Audit close
    will_return(__wrap_audit_close, 1);

    expect_string(__wrap__merror, formatted_msg, "(6637): Could not read audit loaded rules.");

    // Audit added rules
    will_return(__wrap_W_Vector_length, 3);

    // Rule already not added
    will_return(__wrap_search_audit_rule, 0);

    // Add rule
    will_return(__wrap_audit_add_rule, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "(6926): Unable to add audit rule for '/var/test'");

    int ret;
    ret = add_audit_rules_syscheck(0);

    free(syscheck.opts);
    free(syscheck.dir[0]);
    free(syscheck.dir);

    assert_int_equal(ret, 0);
}


void test_add_audit_rules_syscheck_not_added_first_error(void **state) {
    (void) state;

    char *entry = "/var/test";
    syscheck.dir = calloc (2, sizeof(char *));
    syscheck.dir[0] = calloc(strlen(entry) + 2, sizeof(char));
    snprintf(syscheck.dir[0], strlen(entry) + 1, "%s", entry);
    syscheck.opts = calloc (2, sizeof(int *));
    syscheck.opts[0] |= WHODATA_ACTIVE;
    syscheck.max_audit_entries = 100;

    // Audit open
    will_return(__wrap_audit_open, 1);

    // Read loaded rules in Audit
    will_return(__wrap_audit_get_rule_list, 0);

    // Audit close
    will_return(__wrap_audit_close, 1);

    expect_string(__wrap__merror, formatted_msg, "(6637): Could not read audit loaded rules.");

    // Audit added rules
    will_return(__wrap_W_Vector_length, 3);

    // Rule already not added
    will_return(__wrap_search_audit_rule, 0);

    // Add rule
    will_return(__wrap_audit_add_rule, -1);

    expect_string(__wrap__mwarn, formatted_msg, "(6926): Unable to add audit rule for '/var/test'");

    int ret;
    ret = add_audit_rules_syscheck(1);

    free(syscheck.opts);
    free(syscheck.dir[0]);
    free(syscheck.dir);

    assert_int_equal(ret, 0);
}


void test_add_audit_rules_syscheck_added(void **state) {
    (void) state;

    char *entry = "/var/test";
    syscheck.dir = calloc(2, sizeof(char *));
    syscheck.dir[0] = calloc(strlen(entry) + 2, sizeof(char));
    snprintf(syscheck.dir[0], strlen(entry) + 1, "%s", entry);
    syscheck.opts = calloc(2, sizeof(int *));
    syscheck.opts[0] |= WHODATA_ACTIVE;
    syscheck.max_audit_entries = 100;

    // Audit open
    will_return(__wrap_audit_open, 1);

    // Read loaded rules in Audit
    will_return(__wrap_audit_get_rule_list, 5);

    // Audit close
    will_return(__wrap_audit_close, 1);

    // Audit added rules
    will_return(__wrap_W_Vector_length, 3);

    // Rule already added
    will_return(__wrap_search_audit_rule, 1);

    // Add rule
    expect_value(__wrap_W_Vector_insert_unique, v, audit_added_dirs);
    expect_string(__wrap_W_Vector_insert_unique, element, "/var/test");
    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_W_Vector_insert_unique, 0);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string(__wrap__mdebug1, formatted_msg, "(6271): Audit rule for monitoring directory '/var/test' already added.");

    int ret;
    ret = add_audit_rules_syscheck(0);

    free(syscheck.dir[0]);
    free(syscheck.dir);
    free(syscheck.opts);

    assert_int_equal(ret, 1);
}


void test_add_audit_rules_syscheck_max(void **state) {
    (void) state;

    char *entry = "/var/test";
    char *entry2 = "/var/test2";
    syscheck.dir = calloc(3, sizeof(char *));
    syscheck.dir[0] = calloc(strlen(entry) + 2, sizeof(char));
    syscheck.dir[1] = calloc(strlen(entry2) + 2, sizeof(char));
    snprintf(syscheck.dir[0], strlen(entry) + 1, "%s", entry);
    snprintf(syscheck.dir[1], strlen(entry2) + 1, "%s", entry2);
    syscheck.opts = calloc(3, sizeof(int *));
    syscheck.opts[0] |= WHODATA_ACTIVE;
    syscheck.opts[1] |= WHODATA_ACTIVE;
    syscheck.max_audit_entries = 3;

    // Audit open
    will_return(__wrap_audit_open, 1);

    // Read loaded rules in Audit
    will_return(__wrap_audit_get_rule_list, 5);

    // Audit close
    will_return(__wrap_audit_close, 1);

    // Audit added rules
    will_return(__wrap_W_Vector_length, 3);

    expect_string(__wrap__merror, formatted_msg, "(6640): Unable to monitor who-data for directory: '/var/test' - Maximum size permitted (3).");

    // Audit added rules
    will_return(__wrap_W_Vector_length, 3);

    expect_string(__wrap__mdebug1, formatted_msg, "(6640): Unable to monitor who-data for directory: '/var/test2' - Maximum size permitted (3).");

    int ret;
    ret = add_audit_rules_syscheck(0);

    free(syscheck.dir[0]);
    free(syscheck.dir[1]);
    free(syscheck.dir);
    free(syscheck.opts);

    assert_int_equal(ret, 0);
}


void test_filterkey_audit_events_custom(void **state) {
    (void) state;
    int ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=test_key";
    char *key = "test_key";

    syscheck.audit_key = calloc(2, sizeof(char *));
    syscheck.audit_key[0] = calloc(strlen(key) + 2, sizeof(char));
    snprintf(syscheck.audit_key[0], strlen(key) + 1, "%s", key);

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"test_key\"'");

    ret = filterkey_audit_events(event);

    free(syscheck.audit_key[0]);
    free(syscheck.audit_key);

    assert_int_equal(ret, 2);
}


void test_filterkey_audit_events_discard(void **state) {
    (void) state;

    char *key = "test_key";
    syscheck.audit_key = calloc(2, sizeof(char *));
    syscheck.audit_key[0] = calloc(strlen(key) + 2, sizeof(char));
    snprintf(syscheck.audit_key[0], strlen(key) + 1, "%s", key);

    int ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=\"test_invalid_key\"";
    ret = filterkey_audit_events(event);

    free(syscheck.audit_key[0]);
    free(syscheck.audit_key);

    assert_int_equal(ret, 0);
}


void test_filterkey_audit_events_hc(void **state) {
    (void) state;

    int ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=\"wazuh_hc\"";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_hc\"'");

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, 3);
}


void test_filterkey_audit_events_fim(void **state) {
    (void) state;

    int ret;
    char * event = "type=LOGIN msg=audit(1571145421.379:659): pid=16455 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=57 key=\"wazuh_fim\"";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

    ret = filterkey_audit_events(event);

    assert_int_equal(ret, 1);
}


void test_gen_audit_path(void **state) {
    (void) state;

    char * cwd = "/root";
    char * path0 = "/root/test/";
    char * path1 = "/root/test/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/root/test/file");
}


void test_gen_audit_path2(void **state) {
    (void) state;

    char * cwd = "/root";
    char * path0 = "./test/";
    char * path1 = "./test/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/root/test/file");
}


void test_gen_audit_path3(void **state) {
    (void) state;

    char * cwd = "/";
    char * path0 = "root/test/";
    char * path1 = "root/test/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/root/test/file");
}


void test_gen_audit_path4(void **state) {
    (void) state;

    char * cwd = "/";
    char * path0 = "/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, NULL);
    *state = ret;

    assert_string_equal(ret, "/file");
}


void test_gen_audit_path5(void **state) {
    (void) state;

    char * cwd = "/root/test";
    char * path0 = "../test/";
    char * path1 = "../test/file";

    char * ret;
    ret = gen_audit_path(cwd, path0, path1);
    *state = ret;

    assert_string_equal(ret, "/root/test/file");
}


void test_gen_audit_path6(void **state) {
    (void) state;

    char * cwd = "/root";
    char * path0 = "./file";

    char * ret;
    ret = gen_audit_path(cwd, path0, NULL);
    *state = ret;

    assert_string_equal(ret, "/root/file");
}


void test_gen_audit_path7(void **state) {
    (void) state;

    char * cwd = "/root";
    char * path0 = "../file";

    char * ret;
    ret = gen_audit_path(cwd, path0, NULL);
    *state = ret;

    assert_string_equal(ret, "/file");
}


void test_gen_audit_path8(void **state) {
    (void) state;

    char * cwd = "/root";
    char * path0 = "file";

    char * ret;
    ret = gen_audit_path(cwd, path0, NULL);
    *state = ret;

    assert_string_equal(ret, "/root/file");
}

void test_get_process_parent_info_failed(void **state) {
    (void) state;

    char *parent_name;
    char *parent_cwd;

    parent_name = malloc(10);
    parent_cwd = malloc(10);

    will_return(__wrap_readlink, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Failure to obtain the name of the process: '1515'. Error: File exists");

    will_return(__wrap_readlink, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Failure to obtain the cwd of the process: '1515'. Error: File exists");

    get_parent_process_info("1515", &parent_name, &parent_cwd);

    assert_string_equal(parent_name, "");
    assert_string_equal(parent_cwd, "");

    if (parent_name != NULL) {
        free(parent_name);
        parent_name = NULL;
    }

    if (parent_cwd != NULL) {
        free(parent_cwd);
        parent_cwd = NULL;
    }
}

void test_get_process_parent_info_passsed(void **state) {
    (void) state;

    char *parent_name;
    char *parent_cwd;

    parent_name = malloc(10);
    parent_cwd = malloc(10);

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    get_parent_process_info("1515", &parent_name, &parent_cwd);

    assert_string_equal(parent_name, "");
    assert_string_equal(parent_cwd, "");

    if (parent_name != NULL) {
        free(parent_name);
        parent_name = NULL;
    }

    if (parent_cwd != NULL) {
        free(parent_cwd);
        parent_cwd = NULL;
    }
}

void test_audit_parse(void **state) {
    (void) state;

    char * buffer = " \
        type=SYSCALL msg=audit(1571914029.306:3004254): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c5f8170490 a2=0 a3=7ff365c5eca0 items=2 ppid=3211 pid=44082 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"test\" exe=\"74657374C3B1\" key=\"wazuh_fim\" \
        type=CWD msg=audit(1571914029.306:3004254): cwd=\"/root/test\" \
        type=PATH msg=audit(1571914029.306:3004254): item=0 name=\"/root/test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571914029.306:3004254): item=1 name=\"test\" inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571914029.306:3004254): proctitle=726D0074657374 \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_string(__wrap__mdebug1, formatted_msg, "(6334): Audit: Invalid 'auid' value read. Check Audit configuration (PAM).");

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "root");

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6247): audit_event: uid=root, auid=, euid=root, gid=root, pid=44082, ppid=3211, inode=19, path=/root/test/test, pname=74657374C3B1");

    expect_string(__wrap_realpath, path, "/root/test/test");
    will_return(__wrap_realpath, "/root/test/test");
    will_return(__wrap_realpath, (char *) 1);

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 44082);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "74657374C3B1");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/test");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "19");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3211);

    audit_parse(buffer);
}


void test_audit_parse3(void **state) {
    (void) state;

    char * buffer = " \
        type=SYSCALL msg=audit(1571914029.306:3004254): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c5f8170490 a2=0 a3=7ff365c5eca0 items=3 ppid=3211 pid=44082 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"test\" exe=\"74657374C3B1\" key=\"wazuh_fim\" \
        type=CWD msg=audit(1571914029.306:3004254): cwd=\"/root/test\" \
        type=PATH msg=audit(1571925844.299:3004308): item=0 name=\"./\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=1 name=\"folder/\" inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=2 name=\"./test\" inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571914029.306:3004254): proctitle=726D0074657374 \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "root");

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6247): audit_event: uid=root, auid=, euid=root, gid=root, pid=44082, ppid=3211, inode=28, path=/root/test/test, pname=74657374C3B1");

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 44082);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "74657374C3B1");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/test");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "28");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3211);

    audit_parse(buffer);
}


void test_audit_parse4(void **state) {
    (void) state;

    char * buffer = " \
        type=SYSCALL msg=audit(1571923546.947:3004294): arch=c000003e syscall=316 success=yes exit=0 a0=ffffff9c a1=7ffe425fc770 a2=ffffff9c a3=7ffe425fc778 items=4 ppid=3212 pid=51452 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"mv\" exe=66696C655FC3B1 key=\"wazuh_fim\" \
        type=CWD msg=audit(1571923546.947:3004294): cwd=2F726F6F742F746573742F74657374C3B1 \
        type=PATH msg=audit(1571923546.947:3004294): item=0 name=\"./\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571923546.947:3004294): item=1 name=\"folder/\" inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571923546.947:3004294): item=2 name=\"./test\" inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571923546.947:3004294): item=3 name=\"folder/test\" inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571923546.947:3004294): proctitle=6D760066696C655FC3B1002E2E2F74657374C3B1322F66696C655FC3B163 \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "root");

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6248): audit_event_1/2: uid=root, auid=root, euid=root, gid=root, pid=51452, ppid=3212, inode=19, path=/root/test/testñ/test, pname=file_ñ");
    expect_string(__wrap__mdebug2, formatted_msg,
        "(6249): audit_event_2/2: uid=root, auid=root, euid=root, gid=root, pid=51452, ppid=3212, inode=19, path=/root/test/testñ/folder/test, pname=file_ñ");

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 51452);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "file_ñ");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/testñ/test");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "19");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3212);

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 51452);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "file_ñ");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/testñ/folder/test");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "19");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3212);

    audit_parse(buffer);
}


void test_audit_parse_hex(void **state) {
    (void) state;

    char * buffer = " \
        type=SYSCALL msg=audit(1571923546.947:3004294): arch=c000003e syscall=316 success=yes exit=0 a0=ffffff9c a1=7ffe425fc770 a2=ffffff9c a3=7ffe425fc778 items=4 ppid=3212 pid=51452 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"mv\" exe=66696C655FC3B1 key=\"wazuh_fim\" \
        type=CWD msg=audit(1571923546.947:3004294): cwd=2F726F6F742F746573742F74657374C3B1 \
        type=PATH msg=audit(1571923546.947:3004294): item=0 name=2F726F6F742F746573742F74657374C3B1 inode=19 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571923546.947:3004294): item=1 name=2E2E2F74657374C3B1322F inode=30 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571923546.947:3004294): item=2 name=66696C655FC3B1 inode=29 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571923546.947:3004294): item=3 name=2E2E2F74657374C3B1322F66696C655FC3B163 inode=29 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571923546.947:3004294): proctitle=6D760066696C655FC3B1002E2E2F74657374C3B1322F66696C655FC3B163 \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "root");

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6248): audit_event_1/2: uid=root, auid=root, euid=root, gid=root, pid=51452, ppid=3212, inode=29, path=/root/test/testñ/file_ñ, pname=file_ñ");
    expect_string(__wrap__mdebug2, formatted_msg,
        "(6249): audit_event_2/2: uid=root, auid=root, euid=root, gid=root, pid=51452, ppid=3212, inode=29, path=/root/test/testñ2/file_ñc, pname=file_ñ");

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 51452);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "file_ñ");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/testñ/file_ñ");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "29");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3212);

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 51452);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "file_ñ");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/testñ2/file_ñc");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "29");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3212);

    audit_parse(buffer);
}


void test_audit_parse_empty_fields(void **state) {
    (void) state;

    char * buffer = " \
        type=SYSCALL msg=audit(1571914029.306:3004254): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c5f8170490 a2=0 a3=7ff365c5eca0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"test\" key=\"wazuh_fim\" \
        type=PROCTITLE msg=audit(1571914029.306:3004254): proctitle=726D0074657374 \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

    audit_parse(buffer);
}


void test_audit_parse_delete(void **state) {
    (void) state;

    char * buffer = "type=CONFIG_CHANGE msg=audit(1571920603.069:3004276): auid=0 ses=5 op=\"remove_rule\" key=\"wazuh_fim\" list=4 res=1";

    // In audit_reload_rules()
    char *entry = "/var/test";
    syscheck.dir = calloc (2, sizeof(char *));
    syscheck.dir[0] = calloc(strlen(entry) + 2, sizeof(char));
    snprintf(syscheck.dir[0], strlen(entry) + 1, "%s", entry);
    syscheck.opts = calloc (2, sizeof(int *));
    syscheck.opts[0] |= WHODATA_ACTIVE;
    syscheck.max_audit_entries = 100;

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

    expect_string(__wrap__mwarn, formatted_msg, "(6911): Detected Audit rules manipulation: Audit rules removed.");
    expect_string(__wrap__mdebug1, formatted_msg, "(6275): Reloading Audit rules.");

    // Audit open
    will_return(__wrap_audit_open, 1);

    // Read loaded rules in Audit
    will_return(__wrap_audit_get_rule_list, 5);

    // Audit close
    will_return(__wrap_audit_close, 1);

    // Audit added rules
    will_return(__wrap_W_Vector_length, 3);

    // Rule already not added
    will_return(__wrap_search_audit_rule, 1);

    // Add rule
    expect_value(__wrap_W_Vector_insert_unique, v, audit_added_dirs);
    expect_string(__wrap_W_Vector_insert_unique, element, "/var/test");
    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_W_Vector_insert_unique, 1);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Detected rules manipulation: Audit rules removed");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "(6276): Audit rules reloaded. Rules loaded: 1");

    audit_parse(buffer);

    free(syscheck.opts);
    free(syscheck.dir[0]);
    free(syscheck.dir);
}


void test_audit_parse_delete_recursive(void **state) {
    (void) state;

    char * buffer = "type=CONFIG_CHANGE msg=audit(1571920603.069:3004276): auid=0 ses=5 op=remove_rule key=\"wazuh_fim\" list=4 res=1";

    // In audit_reload_rules()
    char *entry = "/var/test";
    syscheck.dir = calloc (2, sizeof(char *));
    syscheck.dir[0] = calloc(strlen(entry) + 2, sizeof(char));
    snprintf(syscheck.dir[0], strlen(entry) + 1, "%s", entry);
    syscheck.opts = calloc (2, sizeof(int *));
    syscheck.opts[0] |= WHODATA_ACTIVE;
    syscheck.max_audit_entries = 100;

    expect_string_count(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'", 4);

    // Audit open
    will_return_always(__wrap_audit_open, 5);

    // Read loaded rules in Audit
    will_return_always(__wrap_audit_get_rule_list, 5);

    // Audit close
    will_return_always(__wrap_audit_close, 5);

    // Audit added rules
    will_return_always(__wrap_W_Vector_length, 3);

    // Rule already not added
    will_return_always(__wrap_search_audit_rule, 5);

    expect_string_count(__wrap_SendMSG, message, "ossec: Audit: Detected rules manipulation: Audit rules removed", 4);
    expect_string(__wrap_SendMSG, message, "ossec: Audit: Detected rules manipulation: Max rules reload retries");
    expect_string_count(__wrap_SendMSG, locmsg, SYSCHECK, 5);
    expect_value_count(__wrap_SendMSG, loc, LOCALFILE_MQ, 5);
    will_return_always(__wrap_SendMSG, 1);

    expect_string(__wrap__mwarn, formatted_msg, "(6911): Detected Audit rules manipulation: Audit rules removed.");
    expect_string(__wrap__mdebug1, formatted_msg, "(6275): Reloading Audit rules.");
    expect_string(__wrap__merror, formatted_msg, "(6639): Error checking Audit rules list.");
    expect_string(__wrap__mdebug1, formatted_msg, "(6276): Audit rules reloaded. Rules loaded: 0");

    expect_string(__wrap__mwarn, formatted_msg, "(6911): Detected Audit rules manipulation: Audit rules removed.");
    expect_string(__wrap__mdebug1, formatted_msg, "(6275): Reloading Audit rules.");
    expect_string(__wrap__merror, formatted_msg, "(6639): Error checking Audit rules list.");
    expect_string(__wrap__mdebug1, formatted_msg, "(6276): Audit rules reloaded. Rules loaded: 0");

    expect_string(__wrap__mwarn, formatted_msg, "(6911): Detected Audit rules manipulation: Audit rules removed.");
    expect_string(__wrap__mdebug1, formatted_msg, "(6275): Reloading Audit rules.");
    expect_string(__wrap__merror, formatted_msg, "(6639): Error checking Audit rules list.");
    expect_string(__wrap__mdebug1, formatted_msg, "(6276): Audit rules reloaded. Rules loaded: 0");

    expect_string(__wrap__mwarn, formatted_msg, "(6911): Detected Audit rules manipulation: Audit rules removed.");

    int i;
    for (i = 0; i < 4; i++) {
        audit_parse(buffer);
    }

    free(syscheck.opts);
    free(syscheck.dir[0]);
    free(syscheck.dir);
}


void test_audit_parse_mv(void **state) {
    (void) state;

    char * buffer = " \
        type=SYSCALL msg=audit(1571925844.299:3004308): arch=c000003e syscall=82 success=yes exit=0 a0=7ffdbb76377e a1=556c16f6c2e0 a2=0 a3=100 items=5 ppid=3210 pid=52277 auid=20 uid=30 gid=40 euid=50 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"mv\" exe=\"/usr/bin/mv\" key=\"wazuh_fim\" \
        type=CWD msg=audit(1571925844.299:3004308): cwd=\"/root/test\" \
        type=PATH msg=audit(1571925844.299:3004308): item=0 name=\"./\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=1 name=\"folder/\" inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=2 name=\"./test\" inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=3 name=\"folder/test\" inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=4 name=\"folder/test\" inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571925844.299:3004308): proctitle=6D76002E2F7465737400666F6C646572 \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

    expect_value(__wrap_get_user, uid, 30);
    will_return(__wrap_get_user, strdup("user30"));
    expect_value(__wrap_get_user, uid, 20);
    will_return(__wrap_get_user, strdup("user20"));
    expect_value(__wrap_get_user, uid, 50);
    will_return(__wrap_get_user, strdup("user50"));

    expect_value(__wrap_get_group, gid, 40);
    will_return(__wrap_get_group, "src");

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6247): audit_event: uid=user30, auid=user20, euid=user50, gid=src, pid=52277, ppid=3210, inode=28, path=/root/test/folder/test, pname=/usr/bin/mv");

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 52277);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "30");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "40");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "/usr/bin/mv");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/folder/test");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "20");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "50");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "28");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3210);

    audit_parse(buffer);
}


void test_audit_parse_mv_hex(void **state) {
    (void) state;

    char * buffer = " \
        type=SYSCALL msg=audit(1571925844.299:3004308): arch=c000003e syscall=82 success=yes exit=0 a0=7ffdbb76377e a1=556c16f6c2e0 a2=0 a3=100 items=5 ppid=3210 pid=52277 auid=20 uid=30 gid=40 euid=50 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"mv\" exe=\"/usr/bin/mv\" key=\"wazuh_fim\" \
        type=CWD msg=audit(1571925844.299:3004308): cwd=\"/root/test\" \
        type=PATH msg=audit(1571925844.299:3004308): item=0 name=\"./\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=1 name=\"folder/\" inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=2 name=\"./test\" inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=3 name=666F6C6465722F74657374 inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=4 name=666F6C6465722F74657374 inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571925844.299:3004308): proctitle=6D76002E2F7465737400666F6C646572 \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

    expect_value(__wrap_get_user, uid, 30);
    will_return(__wrap_get_user, strdup("user30"));
    expect_value(__wrap_get_user, uid, 20);
    will_return(__wrap_get_user, strdup("user20"));
    expect_value(__wrap_get_user, uid, 50);
    will_return(__wrap_get_user, strdup("user50"));

    expect_value(__wrap_get_group, gid, 40);
    will_return(__wrap_get_group, "src");

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6247): audit_event: uid=user30, auid=user20, euid=user50, gid=src, pid=52277, ppid=3210, inode=28, path=/root/test/folder/test, pname=/usr/bin/mv");

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 52277);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "30");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "40");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "/usr/bin/mv");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/folder/test");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "20");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "50");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "28");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3210);

    audit_parse(buffer);
}


void test_audit_parse_rm(void **state) {
    (void) state;

    char * buffer = " \
        type=SYSCALL msg=audit(1571988027.797:3004340): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55578e6d8490 a2=200 a3=7f9cd931bca0 items=3 ppid=3211 pid=56650 auid=2 uid=30 gid=5 euid=2 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"rm\" exe=\"/usr/bin/rm\" key=\"wazuh_fim\" \
        type=CWD msg=audit(1571988027.797:3004340): cwd=\"/root/test\" \
        type=PATH msg=audit(1571988027.797:3004340): item=0 name=\"/root/test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=1 name=(null) inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=2 name=(null) inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571988027.797:3004340): proctitle=726D002D726600666F6C6465722F \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

    expect_value(__wrap_get_user, uid, 30);
    will_return(__wrap_get_user, strdup("user30"));
    expect_value(__wrap_get_user, uid, 2);
    will_return(__wrap_get_user, strdup("daemon"));
    expect_value(__wrap_get_user, uid, 2);
    will_return(__wrap_get_user, strdup("daemon"));

    expect_value(__wrap_get_group, gid, 5);
    will_return(__wrap_get_group, "tty");

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6247): audit_event: uid=user30, auid=daemon, euid=daemon, gid=tty, pid=56650, ppid=3211, inode=24, path=/root/test/, pname=/usr/bin/rm");

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 56650);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "30");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "5");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "/usr/bin/rm");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "2");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "2");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "24");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3211);

    audit_parse(buffer);
}


void test_audit_parse_chmod(void **state) {
    (void) state;

    char * buffer = " \
        type=SYSCALL msg=audit(1571992092.822:3004348): arch=c000003e syscall=268 success=yes exit=0 a0=ffffff9c a1=5648a8ab74c0 a2=1ff a3=fff items=1 ppid=3211 pid=58280 auid=4 uid=99 gid=78 euid=29 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"chmod\" exe=\"/usr/bin/chmod\" key=\"wazuh_fim\" \
        type=CWD msg=audit(1571992092.822:3004348): cwd=\"/root/test\" \
        type=PATH msg=audit(1571992092.822:3004348): item=0 name=\"/root/test/file\" inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571992092.822:3004348): proctitle=63686D6F6400373737002F726F6F742F746573742F66696C65 \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

    expect_value(__wrap_get_user, uid, 99);
    will_return(__wrap_get_user, strdup("user99"));
    expect_value(__wrap_get_user, uid, 4);
    will_return(__wrap_get_user, strdup("lp"));
    expect_value(__wrap_get_user, uid, 29);
    will_return(__wrap_get_user, strdup("user29"));

    expect_value(__wrap_get_group, gid, 78);
    will_return(__wrap_get_group, "");

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6247): audit_event: uid=user99, auid=lp, euid=user29, gid=, pid=58280, ppid=3211, inode=19, path=/root/test/file, pname=/usr/bin/chmod");


    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 58280);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "99");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "78");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "/usr/bin/chmod");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/file");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "4");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "29");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "19");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3211);

    audit_parse(buffer);
}


void test_audit_parse_rm_hc(void **state) {
    (void) state;

    char * buffer = " \
        type=SYSCALL msg=audit(1571988027.797:3004340): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55578e6d8490 a2=200 a3=7f9cd931bca0 items=3 ppid=3211 pid=56650 auid=2 uid=30 gid=5 euid=2 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"rm\" exe=\"/usr/bin/rm\" key=\"wazuh_hc\" \
        type=CWD msg=audit(1571988027.797:3004340): cwd=\"/root/test\" \
        type=PATH msg=audit(1571988027.797:3004340): item=0 name=\"/root/test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=1 name=(null) inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=2 name=(null) inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571988027.797:3004340): proctitle=726D002D726600666F6C6465722F \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_hc\"'");
    expect_string(__wrap__mdebug2, formatted_msg, "(6253): Whodata health-check: Detected file deletion event (263)");

    audit_parse(buffer);
}


void test_audit_parse_add_hc(void **state) {
    (void) state;

    char * buffer = " \
        type=SYSCALL msg=audit(1571988027.797:3004340): arch=c000003e syscall=257 success=yes exit=0 a0=ffffff9c a1=55578e6d8490 a2=200 a3=7f9cd931bca0 items=3 ppid=3211 pid=56650 auid=2 uid=30 gid=5 euid=2 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"touch\" exe=\"/usr/bin/touch\" key=\"wazuh_hc\" \
        type=CWD msg=audit(1571988027.797:3004340): cwd=\"/root/test\" \
        type=PATH msg=audit(1571988027.797:3004340): item=0 name=\"/root/test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=1 name=(null) inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=2 name=(null) inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571988027.797:3004340): proctitle=726D002D726600666F6C6465722F \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_hc\"'");
    expect_string(__wrap__mdebug2, formatted_msg, "(6252): Whodata health-check: Detected file creation event (257)");

    audit_parse(buffer);
}


void test_audit_parse_unknown_hc(void **state) {
    (void) state;

    char * buffer = " \
        type=SYSCALL msg=audit(1571988027.797:3004340): arch=c000003e syscall=90 success=yes exit=0 a0=ffffff9c a1=55578e6d8490 a2=200 a3=7f9cd931bca0 items=3 ppid=3211 pid=56650 auid=2 uid=30 gid=5 euid=2 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"chmod\" exe=\"/usr/bin/chmod\" key=\"wazuh_hc\" \
        type=CWD msg=audit(1571988027.797:3004340): cwd=\"/root/test\" \
        type=PATH msg=audit(1571988027.797:3004340): item=0 name=\"/root/test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=1 name=(null) inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571988027.797:3004340): item=2 name=(null) inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1571988027.797:3004340): proctitle=726D002D726600666F6C6465722F \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_hc\"'");
    expect_string(__wrap__mdebug2, formatted_msg, "(6254): Whodata health-check: Unrecognized event (90)");

    audit_parse(buffer);
}


void test_audit_parse_delete_folder(void **state) {
    (void) state;

    char * buffer = " \
        type=CONFIG_CHANGE msg=audit(1572878838.610:220): op=remove_rule dir=\"/root/test\" key=\"wazuh_fim\" list=4 res=1 \
        type=SYSCALL msg=audit(1572878838.610:220): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c2b7d7f490 a2=200 a3=7f2b8055bca0 items=2 ppid=4340 pid=62845 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=7 comm=\"rm\" exe=\"/usr/bin/rm\" key=(null) \
        type=CWD msg=audit(1572878838.610:220): cwd=\"/root\" \
        type=PATH msg=audit(1572878838.610:220): item=0 name=\"/root\" inode=655362 dev=08:02 mode=040700 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1572878838.610:220): item=1 name=\"test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1572878838.610:220): proctitle=726D002D72660074657374 \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");
    expect_string(__wrap__minfo, formatted_msg, "(6027): Monitored directory '/root/test' was removed: Audit rule removed.");

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "root");

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6247): audit_event: uid=root, auid=root, euid=root, gid=root, pid=62845, ppid=4340, inode=110, path=/root/test, pname=/usr/bin/rm");

    expect_string(__wrap_realpath, path, "/root/test");
    will_return(__wrap_realpath, "/root/test");
    will_return(__wrap_realpath, (char *) 1);

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 62845);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "/usr/bin/rm");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "110");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 4340);

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Monitored directory was removed: Audit rule removed");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    audit_parse(buffer);
}


void test_audit_parse_delete_folder_hex(void **state) {
    (void) state;

    char * buffer = " \
        type=CONFIG_CHANGE msg=audit(1572878838.610:220): op=remove_rule dir=2F726F6F742F746573742F74657374C3B1 key=\"wazuh_fim\" list=4 res=1 \
        type=SYSCALL msg=audit(1572878838.610:220): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c2b7d7f490 a2=200 a3=7f2b8055bca0 items=2 ppid=4340 pid=62845 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=7 comm=\"rm\" exe=\"/usr/bin/rm\" key=(null) \
        type=CWD msg=audit(1572878838.610:220): cwd=\"/root\" \
        type=PATH msg=audit(1572878838.610:220): item=0 name=\"/root\" inode=655362 dev=08:02 mode=040700 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1572878838.610:220): item=1 name=\"test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1572878838.610:220): proctitle=726D002D72660074657374 \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");
    expect_string(__wrap__minfo, formatted_msg, "(6027): Monitored directory '/root/test/testñ' was removed: Audit rule removed.");

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "root");

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6247): audit_event: uid=root, auid=root, euid=root, gid=root, pid=62845, ppid=4340, inode=110, path=/root/test, pname=/usr/bin/rm");

    expect_string(__wrap_realpath, path, "/root/test");
    will_return(__wrap_realpath, "/root/test");
    will_return(__wrap_realpath, (char *) 1);


    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 62845);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "/usr/bin/rm");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test");
    expect_string(__wrap_fim_whodata_event, w_evt->audit_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "110");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 4340);

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Monitored directory was removed: Audit rule removed");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    audit_parse(buffer);
}


void test_audit_parse_delete_folder_hex3_error(void **state) {
    (void) state;

    char * buffer = " \
        type=CONFIG_CHANGE msg=audit(1572878838.610:220): op=remove_rule dir=0 key=\"wazuh_fim\" list=4 res=1 \
        type=SYSCALL msg=audit(1572878838.610:220): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c2b7d7f490 a2=200 a3=7f2b8055bca0 items=3 ppid=4340 pid=62845 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=7 comm=\"rm\" exe=1 key=(null) \
        type=CWD msg=audit(1572878838.610:220): cwd=2 \
        type=PATH msg=audit(1571925844.299:3004308): item=0 name=3 inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=1 name=4 inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=2 name=5 inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1572878838.610:220): proctitle=726D002D72660074657374 \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '0'");
    expect_string(__wrap__mwarn, formatted_msg, "(6911): Detected Audit rules manipulation: Audit rules removed.");

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "root");

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '1'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '2'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '3'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '4'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '5'");

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Detected rules manipulation: Audit rules removed");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Detected rules manipulation: Max rules reload retries");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    audit_parse(buffer);
}


void test_audit_parse_delete_folder_hex4_error(void **state) {
    (void) state;

    char * buffer = " \
        type=CONFIG_CHANGE msg=audit(1572878838.610:220): op=remove_rule dir=0 key=\"wazuh_fim\" list=4 res=1 \
        type=SYSCALL msg=audit(1572878838.610:220): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c2b7d7f490 a2=200 a3=7f2b8055bca0 items=4 ppid=4340 pid=62845 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=7 comm=\"rm\" exe=1 key=(null) \
        type=CWD msg=audit(1572878838.610:220): cwd=2 \
        type=PATH msg=audit(1571925844.299:3004308): item=0 name=3 inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=1 name=4 inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=2 name=5 inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=3 name=6 inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1572878838.610:220): proctitle=726D002D72660074657374 \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '0'");
    expect_string(__wrap__mwarn, formatted_msg, "(6911): Detected Audit rules manipulation: Audit rules removed.");

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "root");

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '1'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '2'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '3'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '4'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '5'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '6'");

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Detected rules manipulation: Audit rules removed");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Detected rules manipulation: Max rules reload retries");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    audit_parse(buffer);
}


void test_audit_parse_delete_folder_hex5_error(void **state) {
    (void) state;

    char * buffer = " \
        type=CONFIG_CHANGE msg=audit(1572878838.610:220): op=remove_rule dir=0 key=\"wazuh_fim\" list=4 res=1 \
        type=SYSCALL msg=audit(1572878838.610:220): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c2b7d7f490 a2=200 a3=7f2b8055bca0 items=5 ppid=4340 pid=62845 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=7 comm=\"rm\" exe=1 key=(null) \
        type=CWD msg=audit(1572878838.610:220): cwd=2 \
        type=PATH msg=audit(1571925844.299:3004308): item=0 name=3 inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=1 name=4 inode=24 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=2 name=5 inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=3 name=6 inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PATH msg=audit(1571925844.299:3004308): item=4 name=7 inode=28 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 \
        type=PROCTITLE msg=audit(1572878838.610:220): proctitle=726D002D72660074657374 \
    ";

    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '0'");
    expect_string(__wrap__mwarn, formatted_msg, "(6911): Detected Audit rules manipulation: Audit rules removed.");

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "root");

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '1'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '2'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '3'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '4'");
    expect_string(__wrap__merror, formatted_msg, "Error found while decoding HEX bufer: '7'");

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Detected rules manipulation: Audit rules removed");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    expect_string(__wrap_SendMSG, message, "ossec: Audit: Detected rules manipulation: Max rules reload retries");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    audit_parse(buffer);
}

/* audit_health_check() tests */
void test_audit_health_check_fail_to_add_rule(void **state) {
    int ret;

    will_return(__wrap_audit_add_rule, -1);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_AUDIT_HEALTHCHECK_RULE);

    ret = audit_health_check(123456);

    assert_int_equal(ret, -1);
    assert_int_equal(hc_thread_active, 0);
}

void test_audit_health_check_fail_to_create_hc_file(void **state) {
    int ret;

    hc_thread_active = 0;

    will_return(__wrap_audit_add_rule, -17);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_AUDIT_HEALTHCHECK_START);

    expect_function_call(__wrap_pthread_cond_init);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_cond_wait);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string_count(__wrap_fopen, path, "/var/ossec/tmp/audit_hc", 10);
    expect_string_count(__wrap_fopen, mode, "w", 10);
    will_return_count(__wrap_fopen, 0, 10);

    expect_string_count(__wrap__mdebug1, formatted_msg, FIM_AUDIT_HEALTHCHECK_FILE, 10);

    expect_value_count(__wrap_sleep, seconds, 1, 10);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_HEALTHCHECK_CREATE_ERROR);

    expect_string(__wrap_unlink, file, "/var/ossec/tmp/audit_hc");
    will_return(__wrap_unlink, 0);

    expect_string(__wrap_audit_delete_rule, path, "/var/ossec/tmp");
    expect_string(__wrap_audit_delete_rule, key, "wazuh_hc");
    will_return(__wrap_audit_delete_rule, 1);

    ret = audit_health_check(123456);

    assert_int_equal(ret, -1);
    assert_int_equal(hc_thread_active, 0);
}

void test_audit_health_check_no_creation_event_detected(void **state) {
    int ret;

    hc_thread_active = 0;

    will_return(__wrap_audit_add_rule, -17);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_AUDIT_HEALTHCHECK_START);

    expect_function_call(__wrap_pthread_cond_init);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_cond_wait);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string_count(__wrap_fopen, path, "/var/ossec/tmp/audit_hc", 10);
    expect_string_count(__wrap_fopen, mode, "w", 10);
    will_return_count(__wrap_fopen, 1, 10);

    expect_value_count(__wrap_fclose, _File, 1, 10);
    will_return_count(__wrap_fclose, 0, 10);

    expect_value_count(__wrap_sleep, seconds, 1, 10);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_HEALTHCHECK_CREATE_ERROR);

    expect_string(__wrap_unlink, file, "/var/ossec/tmp/audit_hc");
    will_return(__wrap_unlink, 0);

    expect_string(__wrap_audit_delete_rule, path, "/var/ossec/tmp");
    expect_string(__wrap_audit_delete_rule, key, "wazuh_hc");
    will_return(__wrap_audit_delete_rule, 1);

    ret = audit_health_check(123456);

    assert_int_equal(ret, -1);
    assert_int_equal(hc_thread_active, 0);
}

void test_audit_health_check_success(void **state) {
    int ret;

    hc_thread_active = 0;

    will_return(__wrap_audit_add_rule, 1);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_AUDIT_HEALTHCHECK_START);

    expect_function_call(__wrap_pthread_cond_init);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_cond_wait);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string(__wrap_fopen, path, "/var/ossec/tmp/audit_hc");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    expect_value(__wrap_sleep, seconds, 1);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_HEALTHCHECK_SUCCESS);

    expect_string(__wrap_unlink, file, "/var/ossec/tmp/audit_hc");
    will_return(__wrap_unlink, 0);

    expect_string(__wrap_audit_delete_rule, path, "/var/ossec/tmp");
    expect_string(__wrap_audit_delete_rule, key, "wazuh_hc");
    will_return(__wrap_audit_delete_rule, 1);

    ret = audit_health_check(123456);

    assert_int_equal(ret, 0);
    assert_int_equal(hc_thread_active, 0);
}


void test_audit_read_events_select_error(void **state) {
    (void) state;
    int *audit_sock = *state;
    audit_thread_active = 1;
    errno = EEXIST;

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);

    // Switch
    will_return(__wrap_select, -1);
    expect_string(__wrap__merror, formatted_msg, "(1114): Error during select()-call due to [(17)-(File exists)].");
    expect_value(__wrap_sleep, seconds, 1);

    audit_read_events(audit_sock, READING_MODE);
}

void test_audit_read_events_select_case_0(void **state) {
    (void) state;
    int *audit_sock = *state;
    audit_thread_active = 1;
    errno = EEXIST;
    char * buffer = " \
        type=SYSCALL msg=audit(1571914029.306:3004254): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c5f8170490 a2=0 a3=7ff365c5eca0 items=2 ppid=3211 pid=44082 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"test\" exe=\"74657374C3B1\" key=\"wazuh_fim\"\n\
        type=CWD msg=audit(1571914029.306:3004254): cwd=\"/root/test\"\n\
        type=PATH msg=audit(1571914029.306:3004254): item=0 name=\"/root/test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0\n\
        type=PATH msg=audit(1571914029.306:3004254): item=1 name=\"test\" inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0\n\
        type=PROCTITLE msg=audit(1571914029.306:3004254): proctitle=726D0074657374\n";

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);
    // Switch
    will_return(__wrap_select, 1);
    will_return(__wrap_select, 0);

    // If (!byteRead)
    expect_value(__wrap_recv, __fd, *audit_sock);
    will_return(__wrap_recv, strlen(buffer));
    will_return(__wrap_recv, buffer);

    // In audit_parse()
    expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("root"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "root");

    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6247): audit_event: uid=root, auid=, euid=root, gid=root, pid=44082, ppid=3211, inode=19, path=/root/test/test, pname=74657374C3B1");

    expect_string(__wrap_realpath, path, "/root/test/test");
    will_return(__wrap_realpath, "/root/test/test");
    will_return(__wrap_realpath, (char *) 1);

    expect_value(__wrap_fim_whodata_event, w_evt->process_id, 44082);
    expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->process_name, "74657374C3B1");
    expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/test");
    expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
    expect_string(__wrap_fim_whodata_event, w_evt->inode, "19");
    expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3211);

    audit_read_events(audit_sock, READING_MODE);
}

void test_audit_read_events_select_success_recv_error_audit_connection_closed(void **state) {
    (void) state;
    int *audit_sock = *state;
    audit_thread_active = 1;
    errno = EEXIST;
    int counter = 0;
    int max_retries = 5;

    will_return(__wrap_FOREVER, 1);

    // Switch
    will_return(__wrap_select, 1);

    // If (!byteRead)
    expect_value(__wrap_recv, __fd, *audit_sock);
    will_return(__wrap_recv, 0);
    expect_string(__wrap__mwarn, formatted_msg, "(6912): Audit: connection closed.");
    expect_value(__wrap_sleep, seconds, 1);
    expect_string(__wrap__minfo, formatted_msg, "(6029): Audit: reconnecting... (1)");

    // init_auditd_socket failure
    expect_any(__wrap_OS_ConnectUnixDomain, path);
    expect_any(__wrap_OS_ConnectUnixDomain, type);
    expect_any(__wrap_OS_ConnectUnixDomain, max_msg_size);
    will_return(__wrap_OS_ConnectUnixDomain, -5);
    expect_string(__wrap__merror, formatted_msg, "(6636): Cannot connect to socket '/var/ossec/queue/ossec/audit'.");

    while (++counter < max_retries){
        expect_any(__wrap__minfo, formatted_msg);
        expect_value(__wrap_sleep, seconds, 1);
        // init_auditd_socket failure
        expect_any(__wrap_OS_ConnectUnixDomain, path);
        expect_any(__wrap_OS_ConnectUnixDomain, type);
        expect_any(__wrap_OS_ConnectUnixDomain, max_msg_size);
        will_return(__wrap_OS_ConnectUnixDomain, -5);
        expect_string(__wrap__merror, formatted_msg, "(6636): Cannot connect to socket '/var/ossec/queue/ossec/audit'.");
    }
    expect_string(__wrap_SendMSG, message, "ossec: Audit: Connection closed");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    audit_read_events(audit_sock, READING_MODE);
}

void test_audit_read_events_select_success_recv_error_audit_reconnect(void **state) {
    (void) state;
    int *audit_sock = *state;
    audit_thread_active = 1;
    errno = EEXIST;

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);

    // Switch
    will_return(__wrap_select, 1);

    // If (!byteRead)
    expect_value(__wrap_recv, __fd, *audit_sock);
    will_return(__wrap_recv, 0);
    expect_string(__wrap__mwarn, formatted_msg, "(6912): Audit: connection closed.");
    expect_value(__wrap_sleep, seconds, 1);
    expect_string(__wrap__minfo, formatted_msg, "(6029): Audit: reconnecting... (1)");

    // init_auditd_socket failure
    expect_any(__wrap_OS_ConnectUnixDomain, path);
    expect_any(__wrap_OS_ConnectUnixDomain, type);
    expect_any(__wrap_OS_ConnectUnixDomain, max_msg_size);
    will_return(__wrap_OS_ConnectUnixDomain, -5);
    expect_string(__wrap__merror, formatted_msg, "(6636): Cannot connect to socket '/var/ossec/queue/ossec/audit'.");

    // While (*audit_sock < 0)
    // init_auditd_socket succes
    expect_any(__wrap__minfo, formatted_msg);
    expect_value(__wrap_sleep, seconds, 1);
    expect_any(__wrap_OS_ConnectUnixDomain, path);
    expect_any(__wrap_OS_ConnectUnixDomain, type);
    expect_any(__wrap_OS_ConnectUnixDomain, max_msg_size);
    will_return(__wrap_OS_ConnectUnixDomain, 124);

    expect_string(__wrap__minfo, formatted_msg, "(6030): Audit: connected.");
    will_return(__wrap_audit_open, 1);
    will_return(__wrap_audit_close, 1);

    // In audit_reload_rules()
    syscheck.dir = calloc (2, sizeof(char *));
    syscheck.dir[0] = NULL;
    expect_string(__wrap__mdebug1, formatted_msg, "(6275): Reloading Audit rules.");
    // In add_audit_rules_syscheck()
    will_return(__wrap_audit_get_rule_list, 1);
    expect_string(__wrap__mdebug1, formatted_msg, "(6276): Audit rules reloaded. Rules loaded: 0");

    audit_read_events(audit_sock, READING_MODE);

    free(syscheck.dir);
}

void test_audit_read_events_select_success_recv_success(void **state) {
    (void) state;
    int *audit_sock = *state;
    audit_thread_active = 1;
    errno = EEXIST;
    char * buffer = " \
        type=SYSCALL msg=audit(1571914029.306:3004254): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c5f8170490 a2=0 a3=7ff365c5eca0 items=2 ppid=3211 pid=44082 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"test\" exe=\"74657374C3B1\" key=\"wazuh_fim\"\n\
        type=CWD msg=audit(1571914029.306:3004254): cwd=\"/root/test\"\n\
        type=PATH msg=audit(1571914029.306:3004254): item=0 name=\"/root/test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0\n\
        type=PATH msg=audit(1571914029.306:3004254): item=1 name=\"test\" inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0\n\
        type=PROCTITLE msg=audit(1571914029.306:3004254): proctitle=726D0074657374\n\
        type=EOE msg=audit(1571914029.306:3004254):\n\
        type=SYSCALL msg=audit(1571914029.306:3004255): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55c5f8170490 a2=0 a3=7ff365c5eca0 items=2 ppid=3211 pid=44082 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"test\" exe=\"74657374C3B1\" key=\"wazuh_fim\"\n\
        type=CWD msg=audit(1571914029.306:3004255): cwd=\"/root/test\"\n\
        type=PATH msg=audit(1571914029.306:3004255): item=0 name=\"/root/test\" inode=110 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0\n\
        type=PATH msg=audit(1571914029.306:3004255): item=1 name=\"test\" inode=19 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0\n\
        type=PROCTITLE msg=audit(1571914029.306:3004255): proctitle=726D0074657374\n\
        type=EOE msg=audit(1571914029.306:3004255):\n";

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);

    // Switch
    will_return(__wrap_select, 1);

    // If (!byteRead)
    expect_value(__wrap_recv, __fd, *audit_sock);
    will_return(__wrap_recv, strlen(buffer));
    will_return(__wrap_recv, buffer);

    for (int i = 0; i<2; i++){
        // In audit_parse()
        expect_string(__wrap__mdebug2, formatted_msg, "(6251): Match audit_key: 'key=\"wazuh_fim\"'");

        expect_value(__wrap_get_user, uid, 0);
        will_return(__wrap_get_user, strdup("root"));
        expect_value(__wrap_get_user, uid, 0);
        will_return(__wrap_get_user, strdup("root"));

        expect_value(__wrap_get_group, gid, 0);
        will_return(__wrap_get_group, "root");

        will_return(__wrap_readlink, 0);
        will_return(__wrap_readlink, 0);

        expect_string(__wrap__mdebug2, formatted_msg,
            "(6247): audit_event: uid=root, auid=, euid=root, gid=root, pid=44082, ppid=3211, inode=19, path=/root/test/test, pname=74657374C3B1");

        expect_string(__wrap_realpath, path, "/root/test/test");
        will_return(__wrap_realpath, "/root/test/test");
        will_return(__wrap_realpath, (char *) 1);

        expect_value(__wrap_fim_whodata_event, w_evt->process_id, 44082);
        expect_string(__wrap_fim_whodata_event, w_evt->user_id, "0");
        expect_string(__wrap_fim_whodata_event, w_evt->group_id, "0");
        expect_string(__wrap_fim_whodata_event, w_evt->process_name, "74657374C3B1");
        expect_string(__wrap_fim_whodata_event, w_evt->path, "/root/test/test");
        expect_string(__wrap_fim_whodata_event, w_evt->effective_uid, "0");
        expect_string(__wrap_fim_whodata_event, w_evt->inode, "19");
        expect_value(__wrap_fim_whodata_event, w_evt->ppid, 3211);
    }

    audit_read_events(audit_sock, READING_MODE);
}

void test_audit_read_events_select_success_recv_success_no_endline(void **state) {
    (void) state;
    int *audit_sock = *state;
    audit_thread_active = 1;
    errno = EEXIST;
    char * buffer = " \
        type=SYSCALL msg=audit(1571914029.306:3004254): arch=c000003e syscall=263 success=yes exit\
    ";

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);

    // Switch
    will_return(__wrap_select, 1);

    // If (!byteRead)
    expect_value(__wrap_recv, __fd, *audit_sock);
    will_return(__wrap_recv, strlen(buffer));
    will_return(__wrap_recv, buffer);

    audit_read_events(audit_sock, READING_MODE);
}

void test_audit_read_events_select_success_recv_success_no_id(void **state) {
    (void) state;
    int *audit_sock = *state;
    audit_thread_active = 1;
    errno = EEXIST;
    char * buffer = " \
        type=SYSC arch=c000003e syscall=263 success=yes exit\n\
    ";

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);

    // Switch
    will_return(__wrap_select, 1);

    // If (!byteRead)
    expect_value(__wrap_recv, __fd, *audit_sock);
    will_return(__wrap_recv, strlen(buffer));
    will_return(__wrap_recv, buffer);

    expect_string(__wrap__mwarn, formatted_msg, "(6928): Couldn't get event ID from Audit message. Line: '         type=SYSC arch=c000003e syscall=263 success=yes exit'.");

    audit_read_events(audit_sock, READING_MODE);
}

void test_audit_read_events_select_success_recv_success_too_long(void **state) {
    (void) state;
    int *audit_sock = *state;
    audit_thread_active = 1;
    errno = EEXIST;

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);

    // Event too long, 65535 char
    char * buffer = malloc(65530 * sizeof(char));
    char * extra_buffer = "aaaaaaaaaa";
    strcpy (buffer,"type=SYSCALLmsg=audit(1571914029.306:3004254):");
    for (int i = 0; i < 6548; i++) {
        strcat (buffer, extra_buffer);
    }
    strcat (buffer,"\n");

    // Switch
    will_return(__wrap_select, 1);

    // If (!byteRead)
    expect_value(__wrap_recv, __fd, *audit_sock);
    will_return(__wrap_recv, strlen(buffer));
    will_return(__wrap_recv, buffer);


    char * buffer2 = "type=SYSCALLmsg=audit(1571914029.306:3004254):aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";

    will_return(__wrap_select, 1);

    // If (!byteRead)
    expect_value(__wrap_recv, __fd, *audit_sock);
    will_return(__wrap_recv, strlen(buffer2));
    will_return(__wrap_recv, buffer2);

    expect_string(__wrap__mwarn, formatted_msg, "(6929): Caching Audit message: event too long. Event with ID: '1571914029.306:3004254' will be discarded.");

    audit_read_events(audit_sock, READING_MODE);

    os_free(buffer);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_check_auditd_enabled_success),
        cmocka_unit_test(test_check_auditd_enabled_openproc_error),
        cmocka_unit_test(test_check_auditd_enabled_readproc_error),
        cmocka_unit_test(test_init_auditd_socket_success),
        cmocka_unit_test(test_init_auditd_socket_failure),
        cmocka_unit_test(test_set_auditd_config_wrong_audit_version),
        cmocka_unit_test(test_set_auditd_config_audit2_plugin_created),
        cmocka_unit_test(test_set_auditd_config_audit3_plugin_created),
        cmocka_unit_test(test_set_auditd_config_audit_socket_not_created),
        cmocka_unit_test(test_set_auditd_config_audit_socket_not_created_restart),
        cmocka_unit_test(test_set_auditd_config_audit_plugin_not_created),
        cmocka_unit_test(test_set_auditd_config_audit_plugin_not_created_fopen_error),
        cmocka_unit_test(test_set_auditd_config_audit_plugin_not_created_fclose_error),
        cmocka_unit_test(test_set_auditd_config_audit_plugin_not_created_recreate_symlink),
        cmocka_unit_test(test_set_auditd_config_audit_plugin_not_created_recreate_symlink_restart),
        cmocka_unit_test(test_set_auditd_config_audit_plugin_not_created_recreate_symlink_error),
        cmocka_unit_test(test_set_auditd_config_audit_plugin_not_created_recreate_symlink_unlink_error),
        cmocka_unit_test_teardown(test_audit_get_id, free_string),
        cmocka_unit_test(test_audit_get_id_begin_error),
        cmocka_unit_test(test_audit_get_id_end_error),
        cmocka_unit_test(test_init_regex),
        cmocka_unit_test_setup_teardown(test_add_audit_rules_syscheck_added, setup_add_audit_rules, teardown_add_audit_rules),
        cmocka_unit_test_setup_teardown(test_add_audit_rules_syscheck_not_added, setup_add_audit_rules, teardown_add_audit_rules),
        cmocka_unit_test_setup_teardown(test_add_audit_rules_syscheck_not_added_new, setup_add_audit_rules, teardown_add_audit_rules),
        cmocka_unit_test_setup_teardown(test_add_audit_rules_syscheck_not_added_error, setup_add_audit_rules, teardown_add_audit_rules),
        cmocka_unit_test_setup_teardown(test_add_audit_rules_syscheck_not_added_first_error, setup_add_audit_rules, teardown_add_audit_rules),
        cmocka_unit_test_setup_teardown(test_add_audit_rules_syscheck_max, setup_add_audit_rules, teardown_add_audit_rules),
        cmocka_unit_test(test_filterkey_audit_events_custom),
        cmocka_unit_test(test_filterkey_audit_events_discard),
        cmocka_unit_test(test_filterkey_audit_events_fim),
        cmocka_unit_test(test_filterkey_audit_events_hc),
        cmocka_unit_test_teardown(test_gen_audit_path, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path2, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path3, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path4, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path5, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path6, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path7, free_string),
        cmocka_unit_test_teardown(test_gen_audit_path8, free_string),
        cmocka_unit_test(test_get_process_parent_info_failed),
        cmocka_unit_test(test_get_process_parent_info_passsed),
        cmocka_unit_test(test_audit_parse),
        cmocka_unit_test(test_audit_parse3),
        cmocka_unit_test(test_audit_parse4),
        cmocka_unit_test(test_audit_parse_hex),
        cmocka_unit_test(test_audit_parse_empty_fields),
        cmocka_unit_test_setup_teardown(test_audit_parse_delete, setup_add_audit_rules, teardown_add_audit_rules),
        cmocka_unit_test_setup_teardown(test_audit_parse_delete_recursive, setup_add_audit_rules, teardown_add_audit_rules),
        cmocka_unit_test(test_audit_parse_mv),
        cmocka_unit_test(test_audit_parse_mv_hex),
        cmocka_unit_test(test_audit_parse_rm),
        cmocka_unit_test(test_audit_parse_chmod),
        cmocka_unit_test(test_audit_parse_rm_hc),
        cmocka_unit_test(test_audit_parse_add_hc),
        cmocka_unit_test(test_audit_parse_unknown_hc),
        cmocka_unit_test(test_audit_parse_delete_folder),
        cmocka_unit_test(test_audit_parse_delete_folder_hex),
        cmocka_unit_test(test_audit_parse_delete_folder_hex3_error),
        cmocka_unit_test(test_audit_parse_delete_folder_hex4_error),
        cmocka_unit_test(test_audit_parse_delete_folder_hex5_error),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_error, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_case_0, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_success_recv_error_audit_connection_closed, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_success_recv_error_audit_reconnect, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_success_recv_success, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_success_recv_success_no_endline, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_success_recv_success_no_id, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_success_recv_success_too_long, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test(test_audit_health_check_fail_to_add_rule),
        cmocka_unit_test(test_audit_health_check_fail_to_create_hc_file),
        cmocka_unit_test(test_audit_health_check_no_creation_event_detected),
        cmocka_unit_test_setup_teardown(test_audit_health_check_success, setup_hc_success, teardown_hc_success),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
