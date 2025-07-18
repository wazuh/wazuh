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

#include "../syscheckd/include/syscheck.h"
#include "../config/syscheck-config.h"

#include "../wrappers/common.h"
#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/wazuh/os_regex/os_regex_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* redefinitons/wrapping */
typedef struct entry_struct_s {
    directory_t *dir1;
    directory_t *dir2;
    char *filerestrict;
} entry_struct_t;

static int setup_read_config(void **state) {
    test_mode = 0;

    return 0;
}

static int restart_syscheck(void **state)
{
    test_mode = 1;
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    cJSON *data = *state;
    if (data) {
        cJSON_Delete(data);
    }
    Free_Syscheck(&syscheck);
    memset(&syscheck, 0, sizeof(syscheck_config));
    return 0;
}

/* setup and teardown */

static int setup_group(void **state) {
    test_mode = 1;

    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;

    return 0;
}

static int setup_entry(void **state) {
    entry_struct_t *entries = calloc(1, sizeof(entry_struct_t));
    if (entries == NULL) {
        return 1;
    }

    *state = entries;
    return 0;
}

static int teardown_entry(void **state) {
    entry_struct_t *entries = *state;

    if (entries->dir1) {
        free_directory(entries->dir1);
    }

    if (entries->dir2) {
        free_directory(entries->dir2);
    }

    if (entries->filerestrict) {
        free(entries->filerestrict);
    }

    free(entries);
    return 0;
}
/* tests */

void test_Read_Syscheck_Config_success(void **state)
{
    (void) state;
    int ret;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_any_always(__wrap__mdebug1, formatted_msg);
    expect_any_always(__wrap__mwarn, formatted_msg);


    test_mode = 0;
    ret = Read_Syscheck_Config("test_syscheck_max_dir.conf");
    test_mode = 1;

    assert_int_equal(ret, 0);
    assert_int_equal(syscheck.rootcheck, 0);

    assert_int_equal(syscheck.disabled, 0);
    assert_int_equal(syscheck.skip_fs.nfs, 1);
    assert_int_equal(syscheck.skip_fs.dev, 1);
    assert_int_equal(syscheck.skip_fs.sys, 1);
    assert_int_equal(syscheck.skip_fs.proc, 1);
    assert_int_equal(syscheck.scan_on_start, 1);
    assert_int_equal(syscheck.time, 43200);
    assert_non_null(syscheck.ignore);
    assert_non_null(syscheck.ignore_regex);
    assert_non_null(syscheck.nodiff);
    assert_non_null(syscheck.nodiff_regex);
    assert_null(syscheck.scan_day);
    assert_null(syscheck.scan_time);
    assert_non_null(syscheck.directories);
    // Directories configuration have 100 directories in one line. It only can monitor 64 per line.
    // With the first 10 directories in other lines, the count should be 74 (75 should be NULL)
    for (int i = 0; i < 70; i++){
        assert_non_null(((directory_t *)OSList_GetDataFromIndex(syscheck.directories, i)));
    }
    assert_null(((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 74)));
    assert_int_equal(syscheck.restart_audit, 1);
    assert_int_equal(syscheck.enable_whodata, 1);
    assert_null(syscheck.realtime);
    assert_int_equal(syscheck.audit_healthcheck, 1);
    assert_int_equal(syscheck.process_priority, 10);
    assert_int_equal(syscheck.allow_remote_prefilter_cmd, true);
    assert_non_null(syscheck.prefilter_cmd);    // It should be a valid binary absolute path
    assert_int_equal(syscheck.max_eps, 200);
    assert_int_equal(syscheck.disk_quota_enabled, true);
    assert_int_equal(syscheck.disk_quota_limit, 1024 * 1024);
    assert_int_equal(syscheck.file_size_enabled, true);
    assert_int_equal(syscheck.file_size_limit, 50 * 1024);
    assert_int_equal(syscheck.diff_folder_size, 0);
    assert_int_equal(syscheck.file_limit_enabled, 1);
    assert_int_equal(syscheck.file_entry_limit, 50000);
#ifdef WIN32
    assert_int_equal(syscheck.registry_limit_enabled, 1);
    assert_int_equal(syscheck.db_entry_registry_limit, 50000);
#endif
}

void test_Read_Syscheck_Config_invalid(void **state)
{
    (void) state;
    int ret;

    expect_any_always(__wrap__mdebug1, formatted_msg);
    expect_string(__wrap__merror, formatted_msg, "(1226): Error reading XML file 'invalid.conf': XMLERR: File 'invalid.conf' not found. (line 0).");

    ret = Read_Syscheck_Config("invalid.conf");

    assert_int_equal(ret, OS_INVALID);
}

void test_Read_Syscheck_Config_undefined(void **state)
{
    (void) state;
    int ret;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_any_always(__wrap__mdebug1, formatted_msg);

    ret = Read_Syscheck_Config("test_syscheck2.conf");

    assert_int_equal(ret, 0);
    assert_int_equal(syscheck.rootcheck, 0);

    assert_int_equal(syscheck.disabled, 0);
    assert_int_equal(syscheck.skip_fs.nfs, 0);
    assert_int_equal(syscheck.skip_fs.dev, 0);
    assert_int_equal(syscheck.skip_fs.sys, 0);
    assert_int_equal(syscheck.skip_fs.proc, 0);
    assert_int_equal(syscheck.scan_on_start, 0);
    assert_int_equal(syscheck.time, 43200);
    assert_null(syscheck.ignore);
    assert_null(syscheck.ignore_regex);
    assert_null(syscheck.nodiff);
    assert_null(syscheck.nodiff_regex);
    assert_null(syscheck.scan_day);
    assert_null(syscheck.scan_time);
    assert_non_null(syscheck.directories);
    assert_int_equal(syscheck.restart_audit, 0);
    assert_int_equal(syscheck.enable_whodata, 1);
    assert_null(syscheck.realtime);
    assert_int_equal(syscheck.audit_healthcheck, 0);
    assert_int_equal(syscheck.process_priority, 10);
    assert_int_equal(syscheck.allow_remote_prefilter_cmd, false);
    assert_null(syscheck.prefilter_cmd);
    assert_int_equal(syscheck.max_eps, 200);
    assert_int_equal(syscheck.disk_quota_enabled, true);
    assert_int_equal(syscheck.disk_quota_limit, 2 * 1024 * 1024);
    assert_int_equal(syscheck.file_size_enabled, true);
    assert_int_equal(syscheck.file_size_limit, 5);
    assert_int_equal(syscheck.diff_folder_size, 0);
    assert_int_equal(syscheck.file_limit_enabled, 1);
    assert_int_equal(syscheck.file_entry_limit, 50000);
#ifdef WIN32
    assert_int_equal(syscheck.db_entry_registry_limit, 50000);
#endif
}

void test_Read_Syscheck_Config_unparsed(void **state)
{
    (void) state;
    int ret;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    expect_any_always(__wrap__mdebug1, formatted_msg);

    ret = Read_Syscheck_Config("test_empty_config.conf");

    assert_int_equal(ret, 1);

    // Default values
    assert_int_equal(syscheck.rootcheck, 0);
    assert_int_equal(syscheck.disabled, 1);
    assert_int_equal(syscheck.skip_fs.nfs, 1);
    assert_int_equal(syscheck.skip_fs.dev, 1);
    assert_int_equal(syscheck.skip_fs.sys, 1);
    assert_int_equal(syscheck.skip_fs.proc, 1);
    assert_int_equal(syscheck.scan_on_start, 1);
    assert_int_equal(syscheck.time, 43200);
    assert_null(syscheck.ignore);
    assert_null(syscheck.ignore_regex);
    assert_null(syscheck.nodiff);
    assert_null(syscheck.nodiff_regex);
    assert_null(syscheck.scan_day);
    assert_null(syscheck.scan_time);
    assert_non_null(syscheck.directories);
    assert_null(OSList_GetFirstNode(syscheck.directories));
    assert_int_equal(syscheck.restart_audit, 1);
    assert_int_equal(syscheck.enable_whodata, 0);
    assert_null(syscheck.realtime);
    assert_int_equal(syscheck.audit_healthcheck, 1);
    assert_int_equal(syscheck.process_priority, 10);
    assert_int_equal(syscheck.allow_remote_prefilter_cmd, false);
    assert_null(syscheck.prefilter_cmd);
    assert_int_equal(syscheck.max_eps, 50);
    assert_int_equal(syscheck.disk_quota_enabled, true);
    assert_int_equal(syscheck.disk_quota_limit, 1024 * 1024);
    assert_int_equal(syscheck.file_size_enabled, true);
    assert_int_equal(syscheck.file_size_limit, 50 * 1024);
    assert_int_equal(syscheck.diff_folder_size, 0);
}

void test_getSyscheckConfig(void **state)
{
    (void) state;
    cJSON * ret;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_any_always(__wrap__mdebug1, formatted_msg);
#ifdef TEST_WINAGENT
    expect_string(__wrap__mdebug2, formatted_msg, "Duplicated registration entry: HKEY_SOME_KEY\\the_key9");
#endif

    Read_Syscheck_Config("test_syscheck_config.conf");
    ret = getSyscheckConfig();
    *state = ret;

    assert_non_null(ret);
    assert_int_equal(cJSON_GetArraySize(ret), 1);

    cJSON *sys_items = cJSON_GetObjectItem(ret, "syscheck");
    #if defined(TEST_SERVER) || defined(TEST_AGENT)
    assert_int_equal(cJSON_GetArraySize(sys_items), 19);
    #elif defined(TEST_WINAGENT)
    assert_int_equal(cJSON_GetArraySize(sys_items), 27);
    #endif

    cJSON *disabled = cJSON_GetObjectItem(sys_items, "disabled");
    assert_string_equal(cJSON_GetStringValue(disabled), "no");
    cJSON *frequency = cJSON_GetObjectItem(sys_items, "frequency");
    assert_int_equal(frequency->valueint, 43200);

    cJSON *db_file_entry_limit = cJSON_GetObjectItem(sys_items, "file_limit");
    cJSON *db_file_entry_limit_enabled = cJSON_GetObjectItem(db_file_entry_limit, "enabled");
    assert_string_equal(cJSON_GetStringValue(db_file_entry_limit_enabled), "yes");
    cJSON *db_entry_limit_file_limit = cJSON_GetObjectItem(db_file_entry_limit, "entries");
    assert_int_equal(db_entry_limit_file_limit->valueint, 50000);

    cJSON *diff = cJSON_GetObjectItem(sys_items, "diff");

    cJSON *disk_quota = cJSON_GetObjectItem(diff, "disk_quota");
    cJSON *disk_quota_enabled = cJSON_GetObjectItem(disk_quota, "enabled");
    assert_string_equal(cJSON_GetStringValue(disk_quota_enabled), "yes");
    cJSON *disk_quota_limit = cJSON_GetObjectItem(disk_quota, "limit");
    assert_int_equal(disk_quota_limit->valueint, 1024 * 1024);

    cJSON *file_size = cJSON_GetObjectItem(diff, "file_size");
    cJSON *file_size_enabled = cJSON_GetObjectItem(file_size, "enabled");
    assert_string_equal(cJSON_GetStringValue(file_size_enabled), "yes");
    cJSON *file_size_limit = cJSON_GetObjectItem(file_size, "limit");
    assert_int_equal(file_size_limit->valueint, 50 * 1024);

    cJSON *skip_nfs = cJSON_GetObjectItem(sys_items, "skip_nfs");
    assert_string_equal(cJSON_GetStringValue(skip_nfs), "yes");
    cJSON *skip_dev = cJSON_GetObjectItem(sys_items, "skip_dev");
    assert_string_equal(cJSON_GetStringValue(skip_dev), "yes");
    cJSON *skip_sys = cJSON_GetObjectItem(sys_items, "skip_sys");
    assert_string_equal(cJSON_GetStringValue(skip_sys), "yes");
    cJSON *skip_proc = cJSON_GetObjectItem(sys_items, "skip_proc");
    assert_string_equal(cJSON_GetStringValue(skip_proc), "yes");
    cJSON *scan_on_start = cJSON_GetObjectItem(sys_items, "scan_on_start");
    assert_string_equal(cJSON_GetStringValue(scan_on_start), "yes");

    cJSON *sys_dir = cJSON_GetObjectItem(sys_items, "directories");

#if defined(TEST_SERVER) || defined(TEST_AGENT)
    assert_int_equal(cJSON_GetArraySize(sys_dir), 6);
    #elif defined(TEST_WINAGENT)
    assert_int_equal(cJSON_GetArraySize(sys_dir), 13);
#endif


    cJSON *sys_nodiff = cJSON_GetObjectItem(sys_items, "nodiff");
    assert_int_equal(cJSON_GetArraySize(sys_nodiff), 1);

    cJSON *sys_ignore = cJSON_GetObjectItem(sys_items, "ignore");
#if defined(TEST_SERVER) || defined(TEST_AGENT)
    assert_int_equal(cJSON_GetArraySize(sys_ignore), 12);
    #elif defined(TEST_WINAGENT)
    assert_int_equal(cJSON_GetArraySize(sys_ignore), 2);
#endif

#ifdef TEST_WINAGENT
    cJSON *sys_ignore_regex = cJSON_GetObjectItem(sys_items, "ignore_sregex");
    assert_int_equal(cJSON_GetArraySize(sys_ignore_regex), 1);

    cJSON *sys_windows_audit_interval = cJSON_GetObjectItem(sys_items, "windows_audit_interval");
    assert_int_equal(sys_windows_audit_interval->valueint, 0);

    cJSON *sys_registry = cJSON_GetObjectItem(sys_items, "registry");
    assert_int_equal(cJSON_GetArraySize(sys_registry), 42);
    cJSON *sys_registry_ignore = cJSON_GetObjectItem(sys_items, "key_ignore");
    assert_int_equal(cJSON_GetArraySize(sys_registry_ignore), 12);
    cJSON *sys_registry_ignore_sregex = cJSON_GetObjectItem(sys_items, "key_ignore_sregex");
    assert_int_equal(cJSON_GetArraySize(sys_registry_ignore_sregex), 1);
    cJSON *sys_registry_value_ignore = cJSON_GetObjectItem(sys_items, "value_ignore");
    assert_int_equal(cJSON_GetArraySize(sys_registry_value_ignore), 5);
    cJSON *sys_registry_value_ignore_sregex = cJSON_GetObjectItem(sys_items, "value_ignore_sregex");
    assert_int_equal(cJSON_GetArraySize(sys_registry_value_ignore_sregex), 4);
#endif

#ifndef TEST_WINAGENT
    cJSON *sys_whodata = cJSON_GetObjectItem(sys_items, "whodata");
    cJSON *whodata_restart_audit = cJSON_GetObjectItem(sys_whodata, "restart_audit");
    assert_string_equal(cJSON_GetStringValue(whodata_restart_audit), "yes");
    cJSON *whodata_audit_key = cJSON_GetObjectItem(sys_whodata, "audit_key");
    assert_int_equal(cJSON_GetArraySize(whodata_audit_key), 2);
    cJSON *whodata_startup_healthcheck = cJSON_GetObjectItem(sys_whodata, "startup_healthcheck");
    assert_string_equal(cJSON_GetStringValue(whodata_startup_healthcheck), "yes");
#endif

    cJSON *allow_remote_prefilter_cmd = cJSON_GetObjectItem(sys_items, "allow_remote_prefilter_cmd");
    assert_string_equal(cJSON_GetStringValue(allow_remote_prefilter_cmd), "yes");
    cJSON *prefilter_cmd = cJSON_GetObjectItem(sys_items, "prefilter_cmd");
#ifndef TEST_WINAGENT
    assert_string_equal(cJSON_GetStringValue(prefilter_cmd), "/bin/ls");
#else
    assert_string_equal(cJSON_GetStringValue(prefilter_cmd), "c:\\windows\\system32\\cmd.exe");
#endif

    cJSON *sys_max_eps = cJSON_GetObjectItem(sys_items, "max_eps");
    assert_int_equal(sys_max_eps->valueint, 200);
    cJSON *sys_process_priority = cJSON_GetObjectItem(sys_items, "process_priority");
    assert_int_equal(sys_process_priority->valueint, 10);
}

void test_getSyscheckConfig_no_audit(void **state)
{
    (void) state;
    cJSON * ret;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_any_always(__wrap__mdebug1, formatted_msg);

    Read_Syscheck_Config("test_syscheck2.conf");

    ret = getSyscheckConfig();
    *state = ret;

    assert_non_null(ret);
    assert_int_equal(cJSON_GetArraySize(ret), 1);

    cJSON *sys_items = cJSON_GetObjectItem(ret, "syscheck");
    #ifndef TEST_WINAGENT
    assert_int_equal(cJSON_GetArraySize(sys_items), 15);
    #else
    assert_int_equal(cJSON_GetArraySize(sys_items), 19);
    #endif

    cJSON *disabled = cJSON_GetObjectItem(sys_items, "disabled");
    assert_string_equal(cJSON_GetStringValue(disabled), "no");
    cJSON *frequency = cJSON_GetObjectItem(sys_items, "frequency");
    assert_int_equal(frequency->valueint, 43200);

    cJSON *db_file_entry_limit = cJSON_GetObjectItem(sys_items, "file_limit");
    cJSON *db_file_entry_limit_enabled = cJSON_GetObjectItem(db_file_entry_limit, "enabled");
    assert_string_equal(cJSON_GetStringValue(db_file_entry_limit_enabled), "yes");
    cJSON *db_entry_limit_file_limit = cJSON_GetObjectItem(db_file_entry_limit, "entries");
    assert_int_equal(db_entry_limit_file_limit->valueint, 50000);

    cJSON *diff = cJSON_GetObjectItem(sys_items, "diff");

    cJSON *disk_quota = cJSON_GetObjectItem(diff, "disk_quota");
    cJSON *disk_quota_enabled = cJSON_GetObjectItem(disk_quota, "enabled");
    assert_string_equal(cJSON_GetStringValue(disk_quota_enabled), "yes");
    cJSON *disk_quota_limit = cJSON_GetObjectItem(disk_quota, "limit");
    assert_int_equal(disk_quota_limit->valueint, 2 * 1024 * 1024);

    cJSON *file_size = cJSON_GetObjectItem(diff, "file_size");
    cJSON *file_size_enabled = cJSON_GetObjectItem(file_size, "enabled");
    assert_string_equal(cJSON_GetStringValue(file_size_enabled), "yes");
    cJSON *file_size_limit = cJSON_GetObjectItem(file_size, "limit");
    assert_int_equal(file_size_limit->valueint, 5);

    cJSON *skip_nfs = cJSON_GetObjectItem(sys_items, "skip_nfs");
    assert_string_equal(cJSON_GetStringValue(skip_nfs), "no");
    cJSON *skip_dev = cJSON_GetObjectItem(sys_items, "skip_dev");
    assert_string_equal(cJSON_GetStringValue(skip_dev), "no");
    cJSON *skip_sys = cJSON_GetObjectItem(sys_items, "skip_sys");
    assert_string_equal(cJSON_GetStringValue(skip_sys), "no");
    cJSON *skip_proc = cJSON_GetObjectItem(sys_items, "skip_proc");
    assert_string_equal(cJSON_GetStringValue(skip_proc), "no");
    cJSON *scan_on_start = cJSON_GetObjectItem(sys_items, "scan_on_start");
    assert_string_equal(cJSON_GetStringValue(scan_on_start), "no");

    cJSON *sys_dir = cJSON_GetObjectItem(sys_items, "directories");
#ifndef TEST_WINAGENT
    assert_int_equal(cJSON_GetArraySize(sys_dir), 8);
#else
    assert_int_equal(cJSON_GetArraySize(sys_dir), 6);
#endif

    cJSON *sys_nodiff = cJSON_GetObjectItem(sys_items, "nodiff");
    assert_null(sys_nodiff);

    cJSON *sys_ignore = cJSON_GetObjectItem(sys_items, "ignore");
    assert_null(sys_ignore);

#ifndef TEST_WINAGENT
    cJSON *sys_whodata = cJSON_GetObjectItem(sys_items, "whodata");
    cJSON *whodata_restart_audit = cJSON_GetObjectItem(sys_whodata, "restart_audit");
    assert_string_equal(cJSON_GetStringValue(whodata_restart_audit), "no");
    cJSON *whodata_audit_key = cJSON_GetObjectItem(sys_whodata, "audit_key");
    assert_null(whodata_audit_key);
    cJSON *whodata_startup_healthcheck = cJSON_GetObjectItem(sys_whodata, "startup_healthcheck");
    assert_string_equal(cJSON_GetStringValue(whodata_startup_healthcheck), "no");
#else
    cJSON *windows_audit_interval = cJSON_GetObjectItem(sys_items, "windows_audit_interval");
    assert_int_equal(windows_audit_interval->valueint, 0);
    cJSON *win_registry = cJSON_GetObjectItem(sys_items, "registry");
    assert_int_equal(cJSON_GetArraySize(win_registry), 33);
    cJSON *win_registry_ignore = cJSON_GetObjectItem(sys_items, "key_ignore");
    assert_int_equal(cJSON_GetArraySize(win_registry_ignore), 11);
    cJSON *win_registry_ignore_regex = cJSON_GetObjectItem(sys_items, "key_ignore_sregex");
    assert_int_equal(cJSON_GetArraySize(win_registry_ignore_regex), 1);
#endif

    cJSON *allow_remote_prefilter_cmd = cJSON_GetObjectItem(sys_items, "allow_remote_prefilter_cmd");
    assert_string_equal(cJSON_GetStringValue(allow_remote_prefilter_cmd), "no");
    cJSON *prefilter_cmd = cJSON_GetObjectItem(sys_items, "prefilter_cmd");
    assert_null(prefilter_cmd);
}

#ifndef TEST_WINAGENT
void test_getSyscheckConfig_no_directories(void **state)
{
    (void) state;
    cJSON * ret;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_any_always(__wrap__mdebug1, formatted_msg);

    Read_Syscheck_Config("test_empty_config.conf");

    ret = getSyscheckConfig();

    assert_null(ret);
}
#else
void test_getSyscheckConfig_no_directories(void **state)
{
    (void) state;
    cJSON * ret;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_any_always(__wrap__mdebug1, formatted_msg);

    Read_Syscheck_Config("test_empty_config.conf");

    ret = getSyscheckConfig();


    assert_non_null(ret);
    assert_int_equal(cJSON_GetArraySize(ret), 1);

    cJSON *sys_items = cJSON_GetObjectItem(ret, "syscheck");
    assert_int_equal(cJSON_GetArraySize(sys_items), 16);
    cJSON *disabled = cJSON_GetObjectItem(sys_items, "disabled");
    assert_string_equal(cJSON_GetStringValue(disabled), "yes");
    cJSON *frequency = cJSON_GetObjectItem(sys_items, "frequency");
    assert_int_equal(frequency->valueint, 43200);

    cJSON *file_limit = cJSON_GetObjectItem(sys_items, "file_limit");
    cJSON *file_limit_enabled = cJSON_GetObjectItem(file_limit, "enabled");
    assert_string_equal(cJSON_GetStringValue(file_limit_enabled), "yes");
    cJSON *file_limit_entries = cJSON_GetObjectItem(file_limit, "entries");
    assert_int_equal(file_limit_entries->valueint, 100000);

    cJSON *registry_limit = cJSON_GetObjectItem(sys_items, "registry_limit");
    cJSON *registry_limit_enabled = cJSON_GetObjectItem(registry_limit, "enabled");
    assert_string_equal(cJSON_GetStringValue(registry_limit_enabled), "yes");
    cJSON *registry_limit_entries = cJSON_GetObjectItem(registry_limit, "entries");

    assert_int_equal(registry_limit_entries->valueint, 100000);

    cJSON *diff = cJSON_GetObjectItem(sys_items, "diff");

    cJSON *disk_quota = cJSON_GetObjectItem(diff, "disk_quota");
    cJSON *disk_quota_enabled = cJSON_GetObjectItem(disk_quota, "enabled");
    assert_string_equal(cJSON_GetStringValue(disk_quota_enabled), "yes");
    cJSON *disk_quota_limit = cJSON_GetObjectItem(disk_quota, "limit");
    assert_int_equal(disk_quota_limit->valueint, 1024 * 1024);

    cJSON *file_size = cJSON_GetObjectItem(diff, "file_size");
    cJSON *file_size_enabled = cJSON_GetObjectItem(file_size, "enabled");
    assert_string_equal(cJSON_GetStringValue(file_size_enabled), "yes");
    cJSON *file_size_limit = cJSON_GetObjectItem(file_size, "limit");
    assert_int_equal(file_size_limit->valueint, 50 * 1024);

    cJSON *skip_nfs = cJSON_GetObjectItem(sys_items, "skip_nfs");
    assert_string_equal(cJSON_GetStringValue(skip_nfs), "yes");
    cJSON *skip_dev = cJSON_GetObjectItem(sys_items, "skip_dev");
    assert_string_equal(cJSON_GetStringValue(skip_dev), "yes");
    cJSON *skip_sys = cJSON_GetObjectItem(sys_items, "skip_sys");
    assert_string_equal(cJSON_GetStringValue(skip_sys), "yes");
    cJSON *skip_proc = cJSON_GetObjectItem(sys_items, "skip_proc");
    assert_string_equal(cJSON_GetStringValue(skip_proc), "yes");
    cJSON *scan_on_start = cJSON_GetObjectItem(sys_items, "scan_on_start");
    assert_string_equal(cJSON_GetStringValue(scan_on_start), "yes");
    cJSON *windows_audit_interval = cJSON_GetObjectItem(sys_items, "windows_audit_interval");
    assert_int_equal(windows_audit_interval->valueint, 0);
    cJSON *registry = cJSON_GetObjectItem(sys_items, "registry");
    assert_int_equal(cJSON_GetArraySize(registry), 0);
    cJSON *allow_remote_prefilter_cmd = cJSON_GetObjectItem(sys_items, "allow_remote_prefilter_cmd");
    assert_string_equal(cJSON_GetStringValue(allow_remote_prefilter_cmd), "no");
    cJSON *max_eps = cJSON_GetObjectItem(sys_items, "max_eps");
    assert_int_equal(max_eps->valueint, 50);
    cJSON *process_priority = cJSON_GetObjectItem(sys_items, "process_priority");
    assert_int_equal(process_priority->valueint, 10);
}
#endif

void test_SyscheckConf_DirectoriesWithCommas(void **state) {
    (void) state;
    int ret;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_any_always(__wrap__mdebug1, formatted_msg);

    ret = Read_Syscheck_Config("test_syscheck3.conf");
    assert_int_equal(ret, 0);

    #ifdef WIN32
    assert_string_equal(((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 0))->path, "c:\\,testcommas");
    assert_string_equal(((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1))->path, "c:\\test,commas");
    assert_string_equal(((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 2))->path, "c:\\testcommas,");
    #else
    assert_string_equal(((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 0))->path, "/,testcommas");
    assert_string_equal(((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1))->path, "/test,commas");
    assert_string_equal(((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 2))->path, "/testcommas,");
    #endif
}

void test_getSyscheckInternalOptions(void **state)
{
    (void) state;
    cJSON * ret;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_any_always(__wrap__mdebug1, formatted_msg);

    Read_Syscheck_Config("test_syscheck.conf");

    ret = getSyscheckInternalOptions();
    *state = ret;

    assert_non_null(ret);
    assert_int_equal(cJSON_GetArraySize(ret), 1);
    cJSON *items = cJSON_GetObjectItem(ret, "internal");
    assert_int_equal(cJSON_GetArraySize(items), 2);
    cJSON *sys_items = cJSON_GetObjectItem(items, "syscheck");
    assert_int_equal(cJSON_GetArraySize(sys_items), 6);
    cJSON *root_items = cJSON_GetObjectItem(items, "rootcheck");
    assert_int_equal(cJSON_GetArraySize(root_items), 1);
}

void test_fim_create_directory_add_new_entry(void **state) {
    const char *path = "./mock_path";
    int options = CHECK_FOLLOW;
    const char *filerestrict = "restrict";
    int recursion_level = 0;
    const char *tag = "mock_tag";
    int diff_size_limit = 0;
    unsigned int is_wildcard = 0;
    directory_t *new_entry;
    entry_struct_t *test_struct = *state;

    new_entry = fim_create_directory(path, options, filerestrict, recursion_level, tag, diff_size_limit, is_wildcard);
    test_struct->dir1 = new_entry;

    assert_non_null(new_entry);
    assert_string_equal(tag, new_entry->tag);
    assert_string_equal(path, new_entry->path);
    assert_int_equal(is_wildcard, new_entry->is_wildcard);
}

void test_fim_create_directory_OSMatch_Compile_fail_maxsize(void **state) {
    const char *path = "./mock_path";
    int recursion_level = 0;
    const char *tag = "mock_tag";
    int options = CHECK_FOLLOW;
    int diff_size_limit = 0;
    unsigned int is_wildcard = 0;
    directory_t *new_entry;
    char error_msg[OS_MAXSTR + 1];
    entry_struct_t *test_struct = *state;

    test_struct->filerestrict = calloc(OS_PATTERN_MAXSIZE + 2, sizeof(char));
    memset(test_struct->filerestrict, 'a', OS_PATTERN_MAXSIZE + 1);

    snprintf(error_msg, OS_MAXSTR, REGEX_COMPILE, test_struct->filerestrict, OS_REGEX_MAXSIZE);

    expect_string(__wrap__merror, formatted_msg, error_msg);

    new_entry = fim_create_directory(path, options, test_struct->filerestrict, recursion_level, tag, diff_size_limit, is_wildcard);
    test_struct->dir1 = new_entry;
    assert_non_null(new_entry);
    assert_string_equal(tag, new_entry->tag);
}

void test_fim_insert_directory_duplicate_entry(void **state) {
    OSList list;
    OSListNode first_list_node;
    entry_struct_t *test_struct = *state;

    test_struct->dir1 = calloc(1, sizeof(directory_t));
    test_struct->dir2 = calloc(1, sizeof(directory_t));

    test_struct->dir2->path = strdup("same_path");
    test_struct->dir2->tag = strdup("new_entry_tag");
    first_list_node.data = test_struct->dir1;
    list.first_node = &first_list_node;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    test_struct->dir1->path = strdup(test_struct->dir2->path);
    fim_insert_directory(&list, test_struct->dir2);

    assert_string_equal(test_struct->dir2->tag, ((directory_t*)(list.first_node->data))->tag);
    // test_struct->dir1 is already freed.
    test_struct->dir1 = NULL;
    *state = test_struct;
}

void test_fim_insert_directory_insert_entry_before(void **state) {
    OSList list = {0};
    OSList_SetFreeDataPointer(&list, (void (*)(void *))free_directory);
    OSListNode *first_list_node = calloc(1, sizeof(OSListNode));
    entry_struct_t *test_struct= *state;

    test_struct->dir1 = calloc(1, sizeof(directory_t));
    test_struct->dir2 = calloc(1, sizeof(directory_t));

    test_struct->dir1->path = strdup("BPath");
    test_struct->dir2->path = strdup("APath");
    test_struct->dir2->tag = strdup("new_entry_tag");

    first_list_node->data = test_struct->dir1;
    list.first_node = first_list_node;
    list.last_node = list.first_node;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    fim_insert_directory(&list, test_struct->dir2);
    assert_string_equal(test_struct->dir2->tag, ((directory_t*)(list.first_node->data))->tag);

    OSList_CleanNodes(&list);
    test_struct->dir1 = NULL;
    test_struct->dir2 = NULL;
}

void test_fim_insert_directory_insert_entry_last(void **state) {
    OSList list = {0};

    OSList_SetFreeDataPointer(&list, (void (*)(void *))free_directory);
    OSListNode *first_list_node = calloc(1, sizeof(OSListNode));

    entry_struct_t *test_struct = *state;

    test_struct->dir1 = calloc(1, sizeof(directory_t));
    test_struct->dir2 = calloc(1, sizeof(directory_t));

    test_struct->dir1->path = strdup("APath");
    test_struct->dir2->path = strdup("BPath");
    test_struct->dir2->tag = strdup("new_entry_tag");

    first_list_node->data = test_struct->dir1;
    list.first_node = first_list_node;
    list.last_node = list.first_node;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    fim_insert_directory(&list, test_struct->dir2);
    assert_string_equal(test_struct->dir2->tag, ((directory_t*)(list.last_node->data))->tag);

    OSList_CleanNodes(&list);

    test_struct->dir1 = NULL;
    test_struct->dir2 = NULL;
}

void test_fim_copy_directory_null(void **state) {
    directory_t *dir = NULL;
    directory_t *return_dir;

    return_dir = fim_copy_directory(dir);

    assert_null(return_dir);

}

void test_fim_copy_directory_return_dir_copied(void **state) {
    directory_t directory_copied;
    directory_t *new_entry;
    directory_copied.filerestrict = NULL;
    directory_copied.path = "mock_path";
    directory_copied.options = 0;
    directory_copied.recursion_level = 3;
    directory_copied.tag = "mock_tag";
    directory_copied.diff_size_limit = 10;
    directory_copied.is_wildcard = 0;
    entry_struct_t *test_struct = *state;

    new_entry = fim_copy_directory(&directory_copied);

    assert_non_null(new_entry);
    assert_string_equal(directory_copied.tag, new_entry->tag);
    assert_string_equal(directory_copied.path, new_entry->path);
    assert_int_equal(directory_copied.is_wildcard, new_entry->is_wildcard);
    test_struct->dir1 = new_entry;
}

void test_fim_adjust_path_no_changes (void **state) {
    char *path = strdup("c:\\a\\path\\not\\replaced");

    fim_adjust_path(&path);

    assert_string_equal(path, "c:\\a\\path\\not\\replaced");

    free(path);
}

void test_fim_adjust_path_convert_sysnative (void **state) {
    char *path = strdup("C:\\windows\\sysnative\\test");

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6307): Convert 'c:\\windows\\sysnative\\test' to 'c:\\windows\\system32\\test' to process the FIM events.");

    fim_adjust_path(&path);

    assert_string_equal(path, "c:\\windows\\system32\\test");

    free(path);
}

void test_fim_adjust_path_convert_syswow64 (void **state) {

    char *path = strdup("C:\\windows\\syswow64\\test");

    fim_adjust_path(&path);

    assert_string_equal(path, "c:\\windows\\syswow64\\test");

    free(path);
}

void test_fim_adjust_path_convert_system32 (void **state) {

    char *path = strdup("c:\\windows\\system32\\test");

    fim_adjust_path(&path);

    assert_string_equal(path, "c:\\windows\\system32\\test");

    free(path);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_Read_Syscheck_Config_success, setup_read_config, restart_syscheck),
        cmocka_unit_test_setup_teardown(test_Read_Syscheck_Config_invalid, setup_read_config, restart_syscheck),
        cmocka_unit_test_setup_teardown(test_Read_Syscheck_Config_undefined, setup_read_config, restart_syscheck),
        cmocka_unit_test_setup_teardown(test_Read_Syscheck_Config_unparsed, setup_read_config, restart_syscheck),
        cmocka_unit_test_setup_teardown(test_getSyscheckConfig, setup_read_config, restart_syscheck),
        cmocka_unit_test_setup_teardown(test_getSyscheckConfig_no_audit, setup_read_config, restart_syscheck),
        cmocka_unit_test_setup_teardown(test_getSyscheckConfig_no_directories, setup_read_config, restart_syscheck),
        cmocka_unit_test_setup_teardown(test_getSyscheckInternalOptions, setup_read_config, restart_syscheck),
        cmocka_unit_test_setup_teardown(test_SyscheckConf_DirectoriesWithCommas, setup_read_config, restart_syscheck),
        cmocka_unit_test_setup_teardown(test_fim_create_directory_add_new_entry, setup_entry, teardown_entry),
        cmocka_unit_test_setup_teardown(test_fim_create_directory_OSMatch_Compile_fail_maxsize, setup_entry, teardown_entry),
        cmocka_unit_test_setup_teardown(test_fim_insert_directory_duplicate_entry, setup_entry, teardown_entry),
        cmocka_unit_test_setup_teardown(test_fim_insert_directory_insert_entry_before, setup_entry, teardown_entry),
        cmocka_unit_test_setup_teardown(test_fim_insert_directory_insert_entry_last, setup_entry, teardown_entry),
        cmocka_unit_test(test_fim_copy_directory_null),
        cmocka_unit_test_setup_teardown(test_fim_copy_directory_return_dir_copied, setup_entry, teardown_entry),
	    cmocka_unit_test(test_fim_adjust_path_no_changes),
        cmocka_unit_test(test_fim_adjust_path_convert_sysnative),
        cmocka_unit_test(test_fim_adjust_path_convert_syswow64),
        cmocka_unit_test(test_fim_adjust_path_convert_system32)
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
