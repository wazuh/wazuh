/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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

#include "wrappers/common.h"
#include "syscheckd/syscheck.h"

#include "wrappers/externals/audit/libaudit_wrappers.h"
#include "wrappers/externals/procpc/readproc_wrappers.h"
#include "wrappers/libc/stdio_wrappers.h"
#include "wrappers/libc/stdlib_wrappers.h"
#include "wrappers/posix/unistd_wrappers.h"
#include "wrappers/wazuh/shared/audit_op_wrappers.h"
#include "wrappers/wazuh/shared/debug_op_wrappers.h"
#include "wrappers/wazuh/shared/file_op_wrappers.h"
#include "wrappers/wazuh/shared/fs_op_wrappers.h"
#include "wrappers/wazuh/shared/mq_op_wrappers.h"
#include "wrappers/wazuh/shared/syscheck_op_wrappers.h"
#include "wrappers/wazuh/shared/vector_op_wrappers.h"
#include "wrappers/wazuh/syscheckd/create_db_wrappers.h"
#include "wrappers/wazuh/os_net/os_net_wrappers.h"

#include "external/procps/readproc.h"

extern volatile int audit_health_check_creation;
extern volatile int hc_thread_active;
extern volatile int audit_thread_active;
int hc_success = 0;

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

static int setup_syscheck_dir_links(void **state) {
    syscheck.dir = calloc(2, sizeof(char *));
    syscheck.opts = calloc(2, sizeof(int));

    if (syscheck.dir == NULL) {
        return -1;
    }

    if (setup_add_audit_rules(NULL) == -1) {
        return -1;
    }

    syscheck.dir[0] = strdup("/test0");
    syscheck.opts[0] |= WHODATA_ACTIVE;
    syscheck.dir[1] = strdup("/test1");
    syscheck.opts[1] |= WHODATA_ACTIVE;

    return 0;
}

static int teardown_syscheck_dir_links(void **state) {
    int i = 0;

    for (i = 0; i <= 1; i++) {
        if (syscheck.dir[i] != NULL) {
            free(syscheck.dir[i]);
            syscheck.dir[i] = NULL;
        }
    }

    if (syscheck.dir != NULL) {
        free(syscheck.dir);
        syscheck.dir = NULL;
    }

    if (syscheck.opts != NULL) {
        free(syscheck.opts);
        syscheck.opts = NULL;
    }

    teardown_add_audit_rules(NULL);

    return 0;
}

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


/* tests */

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
    char buffer[OS_SIZE_128] = {0};

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

    // Mutex inside get_real_path
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string(__wrap__merror, formatted_msg, "(6637): Could not read audit loaded rules.");

    // Rule already not added
    will_return(__wrap_search_audit_rule, 0);

    will_return(__wrap_audit_add_rule, -EEXIST);
    snprintf(buffer, OS_SIZE_128, FIM_AUDIT_ALREADY_ADDED, syscheck.dir[0]);
    expect_string(__wrap__mdebug1, formatted_msg, buffer);

    int ret;
    ret = add_audit_rules_syscheck(0);

    free(syscheck.opts);
    free(syscheck.dir[0]);
    free(syscheck.dir);

    assert_int_equal(ret, 0);
}


void test_add_audit_rules_syscheck_not_added_new(void **state) {
    (void) state;

    char *entry = "/var/test";
    char dbg_msg[OS_SIZE_128] = {0};

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

    // Mutex inside get_real_path
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string(__wrap__merror, formatted_msg, "(6637): Could not read audit loaded rules.");

    // Rule already not added
    will_return(__wrap_search_audit_rule, 0);

    // Add rule
    will_return(__wrap_audit_add_rule, 1);
    snprintf(dbg_msg, OS_SIZE_128, FIM_AUDIT_NEWRULE, entry);
    expect_string(__wrap__mdebug1, formatted_msg, dbg_msg);
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

    // Mutex inside get_real_path
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
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

    // Mutex inside get_real_path
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    expect_string(__wrap__merror, formatted_msg, "(6637): Could not read audit loaded rules.");

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
    will_return(__wrap_realpath, strdup("/root/test/test"));

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
        will_return(__wrap_realpath, strdup("/root/test/test"));

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

void test_audit_no_rules_to_realtime(void **state) {
    char error_msg[OS_SIZE_128];
    // Mutex inside get_real_path
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    will_return(__wrap_search_audit_rule, 0);

    snprintf(error_msg, OS_SIZE_128, FIM_ERROR_WHODATA_ADD_DIRECTORY, "/test0");
    expect_string(__wrap__mwarn, formatted_msg, error_msg);
    // Mutex inside get_real_path
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    will_return(__wrap_search_audit_rule, 1);

    audit_no_rules_to_realtime();

    // Check that the options have been correctly changed
    if (syscheck.opts[0] & WHODATA_ACTIVE) {
        fail();
    }

    if (syscheck.opts[1] & REALTIME_ACTIVE) {
        fail();
    }
}

void test_add_audit_rules_syscheck_duplicate_entry(void **state) {
    (void) state;

    char *entry = "/var/test";
    char buffer [OS_SIZE_128] = {0};

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

    // Mutex inside get_real_path
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    // Rule already added
    will_return(__wrap_search_audit_rule, 1);
    snprintf(buffer, OS_SIZE_128, FIM_AUDIT_RULEDUP, entry);
    expect_string(__wrap__mdebug1, formatted_msg, buffer);

    int ret;
    ret = add_audit_rules_syscheck(0);

    free(syscheck.dir[0]);
    free(syscheck.dir);
    free(syscheck.opts);

    assert_int_equal(ret, 0);
}


void test_add_audit_rules_syscheck_max(void **state) {
    (void) state;

    char *entry = "/var/test";
    char *entry2 = "/var/test2";
    char dbg1[OS_SIZE_128] = {0};
    char dbg2[OS_SIZE_128] = {0};

    syscheck.dir = calloc(3, sizeof(char *));
    syscheck.dir[0] = calloc(strlen(entry) + 2, sizeof(char));
    syscheck.dir[1] = calloc(strlen(entry2) + 2, sizeof(char));
    snprintf(syscheck.dir[0], strlen(entry) + 1, "%s", entry);
    snprintf(syscheck.dir[1], strlen(entry2) + 1, "%s", entry2);
    syscheck.opts = calloc(3, sizeof(int *));
    syscheck.opts[0] |= WHODATA_ACTIVE;
    syscheck.opts[1] |= WHODATA_ACTIVE;
    syscheck.max_audit_entries = 1;

    // Audit open
    will_return(__wrap_audit_open, 1);

    // Read loaded rules in Audit
    will_return(__wrap_audit_get_rule_list, 5);

    // Audit close
    will_return(__wrap_audit_close, 1);

    // Mutex inside get_real_path
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    // Audit search_audit_rule will be called 2 times.
    will_return_always(__wrap_search_audit_rule, 0);

    // audit_add_rule_data
    will_return_always(__wrap_audit_add_rule, 1);

    snprintf(dbg1, OS_SIZE_128, FIM_AUDIT_NEWRULE, entry);
    snprintf(dbg2, OS_SIZE_128, FIM_ERROR_WHODATA_MAXNUM_WATCHES, entry2, syscheck.max_audit_entries);
    expect_string(__wrap__mdebug1, formatted_msg, dbg1);
    expect_string(__wrap__merror, formatted_msg, dbg2);

    int ret;
    ret = add_audit_rules_syscheck(0);

    free(syscheck.dir[0]);
    free(syscheck.dir[1]);
    free(syscheck.dir);
    free(syscheck.opts);

    assert_int_equal(ret, 1);
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
        cmocka_unit_test_setup_teardown(test_add_audit_rules_syscheck_duplicate_entry, setup_add_audit_rules, teardown_add_audit_rules),
        cmocka_unit_test_setup_teardown(test_add_audit_rules_syscheck_not_added, setup_add_audit_rules, teardown_add_audit_rules),
        cmocka_unit_test_setup_teardown(test_add_audit_rules_syscheck_not_added_new, setup_add_audit_rules, teardown_add_audit_rules),
        cmocka_unit_test_setup_teardown(test_add_audit_rules_syscheck_not_added_error, setup_add_audit_rules, teardown_add_audit_rules),
        cmocka_unit_test_setup_teardown(test_add_audit_rules_syscheck_not_added_first_error, setup_add_audit_rules, teardown_add_audit_rules),
        cmocka_unit_test_setup_teardown(test_add_audit_rules_syscheck_max, setup_add_audit_rules, teardown_add_audit_rules),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_error, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_case_0, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_success_recv_error_audit_connection_closed, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_success_recv_error_audit_reconnect, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_success_recv_success, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_success_recv_success_no_endline, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_success_recv_success_no_id, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test_setup_teardown(test_audit_read_events_select_success_recv_success_too_long, test_audit_read_events_setup, test_audit_read_events_teardown),
        cmocka_unit_test_setup_teardown(test_audit_no_rules_to_realtime, setup_syscheck_dir_links, teardown_syscheck_dir_links),

        };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
