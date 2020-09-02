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

#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* redefinitons/wrapping */

static int restart_syscheck(void **state)
{
    cJSON *data = *state;
    if (data) {
        cJSON_Delete(data);
    }
    Free_Syscheck(&syscheck);
    memset(&syscheck, 0, sizeof(syscheck_config));
    return 0;
}


/* tests */

void test_Read_Syscheck_Config_success(void **state)
{
    (void) state;
    int ret;

    expect_any_always(__wrap__mdebug1, formatted_msg);
    expect_any_always(__wrap__mwarn, formatted_msg);

#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif

    ret = Read_Syscheck_Config("test_syscheck_max_dir.conf");

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
    assert_non_null(syscheck.dir);
    // Directories configuration have 100 directories in one line. It only can monitor 64 per line.
    // With the first 10 directories in other lines, the count should be 74 (75 should be NULL)
    for (int i = 0; i < 74; i++){
        assert_non_null(syscheck.dir[i]);
    }
    assert_null(syscheck.dir[74]);
    assert_non_null(syscheck.opts);
    assert_int_equal(syscheck.enable_synchronization, 1);
    assert_int_equal(syscheck.restart_audit, 1);
    assert_int_equal(syscheck.enable_whodata, 1);
    assert_null(syscheck.realtime);
    assert_int_equal(syscheck.audit_healthcheck, 1);
    assert_int_equal(syscheck.process_priority, 10);
    assert_int_equal(syscheck.allow_remote_prefilter_cmd, true);
    assert_non_null(syscheck.prefilter_cmd);    // It should be a valid binary absolute path
    assert_int_equal(syscheck.sync_interval, 600);
    assert_int_equal(syscheck.sync_response_timeout, 30);
    assert_int_equal(syscheck.sync_queue_size, 64);
    assert_int_equal(syscheck.max_eps, 200);
    assert_int_equal(syscheck.disk_quota_enabled, true);
    assert_int_equal(syscheck.disk_quota_limit, 1024 * 1024);
    assert_int_equal(syscheck.file_size_enabled, true);
    assert_int_equal(syscheck.file_size_limit, 50 * 1024);
    assert_int_equal(syscheck.diff_folder_size, 0);
    assert_non_null(syscheck.diff_size_limit);
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

    expect_any_always(__wrap__mdebug1, formatted_msg);
#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif

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
    assert_non_null(syscheck.dir);
    assert_non_null(syscheck.opts);
    assert_int_equal(syscheck.enable_synchronization, 0);
    assert_int_equal(syscheck.restart_audit, 0);
    assert_int_equal(syscheck.enable_whodata, 1);
    assert_null(syscheck.realtime);
    assert_int_equal(syscheck.audit_healthcheck, 0);
    assert_int_equal(syscheck.process_priority, 10);
    assert_int_equal(syscheck.allow_remote_prefilter_cmd, false);
    assert_null(syscheck.prefilter_cmd);
    assert_int_equal(syscheck.sync_interval, 600);
    assert_int_equal(syscheck.sync_response_timeout, 30);
    assert_int_equal(syscheck.sync_queue_size, 64);
    assert_int_equal(syscheck.max_eps, 200);
    assert_int_equal(syscheck.disk_quota_enabled, true);
    assert_int_equal(syscheck.disk_quota_limit, 2 * 1024 * 1024);
    assert_int_equal(syscheck.file_size_enabled, true);
    assert_int_equal(syscheck.file_size_limit, 5);
    assert_int_equal(syscheck.diff_folder_size, 0);
    assert_non_null(syscheck.diff_size_limit);
}

void test_Read_Syscheck_Config_unparsed(void **state)
{
    (void) state;
    int ret;

    expect_any_always(__wrap__mdebug1, formatted_msg);
#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif

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
#ifndef TEST_WINAGENT
    assert_null(syscheck.dir);
#else
    assert_non_null(syscheck.dir);
#endif
    assert_null(syscheck.opts);
    assert_int_equal(syscheck.enable_synchronization, 1);
    assert_int_equal(syscheck.restart_audit, 1);
    assert_int_equal(syscheck.enable_whodata, 0);
    assert_null(syscheck.realtime);
    assert_int_equal(syscheck.audit_healthcheck, 1);
    assert_int_equal(syscheck.process_priority, 10);
    assert_int_equal(syscheck.allow_remote_prefilter_cmd, false);
    assert_null(syscheck.prefilter_cmd);
    assert_int_equal(syscheck.sync_interval, 300);
    assert_int_equal(syscheck.sync_response_timeout, 30);
    assert_int_equal(syscheck.sync_queue_size, 16384);
    assert_int_equal(syscheck.max_eps, 100);
    assert_int_equal(syscheck.disk_quota_enabled, true);
    assert_int_equal(syscheck.disk_quota_limit, 1024 * 1024);
    assert_int_equal(syscheck.file_size_enabled, true);
    assert_int_equal(syscheck.file_size_limit, 50 * 1024);
    assert_int_equal(syscheck.diff_folder_size, 0);
    assert_null(syscheck.diff_size_limit);
}

void test_getSyscheckConfig(void **state)
{
    (void) state;
    cJSON * ret;

    expect_any_always(__wrap__mdebug1, formatted_msg);
#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif

    Read_Syscheck_Config("test_syscheck.conf");

    ret = getSyscheckConfig();
    *state = ret;

    assert_non_null(ret);
    assert_int_equal(cJSON_GetArraySize(ret), 1);

    cJSON *sys_items = cJSON_GetObjectItem(ret, "syscheck");
    #if defined(TEST_SERVER) || defined(TEST_AGENT)
    assert_int_equal(cJSON_GetArraySize(sys_items), 20);
    #elif defined(TEST_WINAGENT)
    assert_int_equal(cJSON_GetArraySize(sys_items), 23);
    #endif

    cJSON *disabled = cJSON_GetObjectItem(sys_items, "disabled");
    assert_string_equal(cJSON_GetStringValue(disabled), "no");
    cJSON *frequency = cJSON_GetObjectItem(sys_items, "frequency");
    assert_int_equal(frequency->valueint, 43200);

    cJSON *file_limit = cJSON_GetObjectItem(sys_items, "file_limit");
    cJSON *file_limit_enabled = cJSON_GetObjectItem(file_limit, "enabled");
    assert_string_equal(cJSON_GetStringValue(file_limit_enabled), "yes");
    cJSON *file_limit_entries = cJSON_GetObjectItem(file_limit, "entries");
    assert_int_equal(file_limit_entries->valueint, 50000);

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
    assert_int_equal(cJSON_GetArraySize(sys_dir), 10);
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
    assert_int_equal(cJSON_GetArraySize(sys_registry), 33);
    cJSON *sys_registry_ignore = cJSON_GetObjectItem(sys_items, "registry_ignore");
    assert_int_equal(cJSON_GetArraySize(sys_registry_ignore), 11);
    cJSON *sys_registry_ignore_sregex = cJSON_GetObjectItem(sys_items, "registry_ignore_sregex");
    assert_int_equal(cJSON_GetArraySize(sys_registry_ignore_sregex), 1);
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

    cJSON *sys_synchronization = cJSON_GetObjectItem(sys_items, "synchronization");
    cJSON *synchronization_enabled = cJSON_GetObjectItem(sys_synchronization, "enabled");
    assert_string_equal(cJSON_GetStringValue(synchronization_enabled), "yes");
    cJSON *synchronization_max_interval = cJSON_GetObjectItem(sys_synchronization, "max_interval");
    assert_int_equal(synchronization_max_interval->valueint, 3600);
    cJSON *synchronization_interval = cJSON_GetObjectItem(sys_synchronization, "interval");
    assert_int_equal(synchronization_interval->valueint, 600);
    cJSON *synchronization_response_timeout = cJSON_GetObjectItem(sys_synchronization, "response_timeout");
    assert_int_equal(synchronization_response_timeout->valueint, 30);
    cJSON *synchronization_queue_size = cJSON_GetObjectItem(sys_synchronization, "queue_size");
    assert_int_equal(synchronization_queue_size->valueint, 64);

    cJSON *sys_max_eps = cJSON_GetObjectItem(sys_items, "max_eps");
    assert_int_equal(sys_max_eps->valueint, 200);
    cJSON *sys_process_priority = cJSON_GetObjectItem(sys_items, "process_priority");
    assert_int_equal(sys_process_priority->valueint, 10);

    cJSON *database = cJSON_GetObjectItem(sys_items, "database");
    assert_string_equal(cJSON_GetStringValue(database), "disk");
}

void test_getSyscheckConfig_no_audit(void **state)
{
    (void) state;
    cJSON * ret;

    expect_any_always(__wrap__mdebug1, formatted_msg);
#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif

    Read_Syscheck_Config("test_syscheck2.conf");

    ret = getSyscheckConfig();
    *state = ret;

    assert_non_null(ret);
    assert_int_equal(cJSON_GetArraySize(ret), 1);

    cJSON *sys_items = cJSON_GetObjectItem(ret, "syscheck");
    #ifndef TEST_WINAGENT
    assert_int_equal(cJSON_GetArraySize(sys_items), 16);
    #else
    assert_int_equal(cJSON_GetArraySize(sys_items), 19);
    #endif

    cJSON *disabled = cJSON_GetObjectItem(sys_items, "disabled");
    assert_string_equal(cJSON_GetStringValue(disabled), "no");
    cJSON *frequency = cJSON_GetObjectItem(sys_items, "frequency");
    assert_int_equal(frequency->valueint, 43200);

    cJSON *file_limit = cJSON_GetObjectItem(sys_items, "file_limit");
    cJSON *file_limit_enabled = cJSON_GetObjectItem(file_limit, "enabled");
    assert_string_equal(cJSON_GetStringValue(file_limit_enabled), "yes");
    cJSON *file_limit_entries = cJSON_GetObjectItem(file_limit, "entries");
    assert_int_equal(file_limit_entries->valueint, 50000);

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
    assert_int_equal(cJSON_GetArraySize(sys_dir), 10);
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
    cJSON *win_registry_ignore = cJSON_GetObjectItem(sys_items, "registry_ignore");
    assert_int_equal(cJSON_GetArraySize(win_registry_ignore), 11);
    cJSON *win_registry_ignore_regex = cJSON_GetObjectItem(sys_items, "registry_ignore_sregex");
    assert_int_equal(cJSON_GetArraySize(win_registry_ignore_regex), 1);
#endif

    cJSON *allow_remote_prefilter_cmd = cJSON_GetObjectItem(sys_items, "allow_remote_prefilter_cmd");
    assert_string_equal(cJSON_GetStringValue(allow_remote_prefilter_cmd), "no");
    cJSON *prefilter_cmd = cJSON_GetObjectItem(sys_items, "prefilter_cmd");
    assert_null(prefilter_cmd);

    cJSON *sys_synchronization = cJSON_GetObjectItem(sys_items, "synchronization");
    cJSON *synchronization_enabled = cJSON_GetObjectItem(sys_synchronization, "enabled");
    assert_string_equal(cJSON_GetStringValue(synchronization_enabled), "no");
    cJSON *synchronization_max_interval = cJSON_GetObjectItem(sys_synchronization, "max_interval");
    assert_int_equal(synchronization_max_interval->valueint, 3600);
    cJSON *synchronization_interval = cJSON_GetObjectItem(sys_synchronization, "interval");
    assert_int_equal(synchronization_interval->valueint, 600);
    cJSON *synchronization_response_timeout = cJSON_GetObjectItem(sys_synchronization, "response_timeout");
    assert_int_equal(synchronization_response_timeout->valueint, 30);
    cJSON *synchronization_queue_size = cJSON_GetObjectItem(sys_synchronization, "queue_size");
    assert_int_equal(synchronization_queue_size->valueint, 64);

    cJSON *database = cJSON_GetObjectItem(sys_items, "database");
    assert_string_equal(cJSON_GetStringValue(database), "memory");
}

#ifndef TEST_WINAGENT
void test_getSyscheckConfig_no_directories(void **state)
{
    (void) state;
    cJSON * ret;

    expect_any_always(__wrap__mdebug1, formatted_msg);
#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif

    Read_Syscheck_Config("test_empty_config.conf");

    ret = getSyscheckConfig();

    assert_null(ret);
}
#else
void test_getSyscheckConfig_no_directories(void **state)
{
    (void) state;
    cJSON * ret;

    expect_any_always(__wrap__mdebug1, formatted_msg);

#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif

    Read_Syscheck_Config("test_empty_config.conf");

    ret = getSyscheckConfig();


    assert_non_null(ret);
    assert_int_equal(cJSON_GetArraySize(ret), 1);

    cJSON *sys_items = cJSON_GetObjectItem(ret, "syscheck");
    assert_int_equal(cJSON_GetArraySize(sys_items), 17);
    cJSON *disabled = cJSON_GetObjectItem(sys_items, "disabled");
    assert_string_equal(cJSON_GetStringValue(disabled), "yes");
    cJSON *frequency = cJSON_GetObjectItem(sys_items, "frequency");
    assert_int_equal(frequency->valueint, 43200);

    cJSON *file_limit = cJSON_GetObjectItem(sys_items, "file_limit");
    cJSON *file_limit_enabled = cJSON_GetObjectItem(file_limit, "enabled");
    assert_string_equal(cJSON_GetStringValue(file_limit_enabled), "yes");
    cJSON *file_limit_entries = cJSON_GetObjectItem(file_limit, "entries");
    assert_int_equal(file_limit_entries->valueint, 100000);

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
    cJSON *directories = cJSON_GetObjectItem(sys_items, "directories");
    assert_int_equal(cJSON_GetArraySize(directories), 0);
    cJSON *windows_audit_interval = cJSON_GetObjectItem(sys_items, "windows_audit_interval");
    assert_int_equal(windows_audit_interval->valueint, 0);
    cJSON *registry = cJSON_GetObjectItem(sys_items, "registry");
    assert_int_equal(cJSON_GetArraySize(registry), 0);
    cJSON *allow_remote_prefilter_cmd = cJSON_GetObjectItem(sys_items, "allow_remote_prefilter_cmd");
    assert_string_equal(cJSON_GetStringValue(allow_remote_prefilter_cmd), "no");
    cJSON *max_eps = cJSON_GetObjectItem(sys_items, "max_eps");
    assert_int_equal(max_eps->valueint, 100);
    cJSON *process_priority = cJSON_GetObjectItem(sys_items, "process_priority");
    assert_int_equal(process_priority->valueint, 10);

    cJSON *synchronization = cJSON_GetObjectItem(sys_items, "synchronization");
    assert_int_equal(cJSON_GetArraySize(synchronization), 6);
    cJSON *enabled = cJSON_GetObjectItem(synchronization, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "yes");
    cJSON *max_interval = cJSON_GetObjectItem(synchronization, "max_interval");
    assert_int_equal(max_interval->valueint, 3600);
    cJSON *interval = cJSON_GetObjectItem(synchronization, "interval");
    assert_int_equal(interval->valueint, 300);
    cJSON *response_timeout = cJSON_GetObjectItem(synchronization, "response_timeout");
    assert_int_equal(response_timeout->valueint, 30);
    cJSON *queue_size = cJSON_GetObjectItem(synchronization, "queue_size");
    assert_int_equal(queue_size->valueint, 16384);
    cJSON *sync_max_eps = cJSON_GetObjectItem(synchronization, "max_eps");
    assert_int_equal(sync_max_eps->valueint, 10);
}
#endif

void test_SyscheckConf_DirectoriesWithCommas(void **state) {
    (void) state;
    int ret;

    expect_any_always(__wrap__mdebug1, formatted_msg);

#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif

    ret = Read_Syscheck_Config("test_syscheck3.conf");
    assert_int_equal(ret, 0);

    #ifdef WIN32
    assert_string_equal(syscheck.dir[0], "c:\\,testcommas");
    assert_string_equal(syscheck.dir[1], "c:\\test,commas");
    assert_string_equal(syscheck.dir[2], "c:\\testcommas,");
    #else
    assert_string_equal(syscheck.dir[0], "/,testcommas");
    assert_string_equal(syscheck.dir[1], "/test,commas");
    assert_string_equal(syscheck.dir[2], "/testcommas,");
    #endif
}

void test_getSyscheckInternalOptions(void **state)
{
    (void) state;
    cJSON * ret;

    expect_any_always(__wrap__mdebug1, formatted_msg);
#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif

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


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_Read_Syscheck_Config_success, restart_syscheck),
        cmocka_unit_test_teardown(test_Read_Syscheck_Config_invalid, restart_syscheck),
        cmocka_unit_test_teardown(test_Read_Syscheck_Config_undefined, restart_syscheck),
        cmocka_unit_test_teardown(test_Read_Syscheck_Config_unparsed, restart_syscheck),
        cmocka_unit_test_teardown(test_getSyscheckConfig, restart_syscheck),
        cmocka_unit_test_teardown(test_getSyscheckConfig_no_audit, restart_syscheck),
        cmocka_unit_test_teardown(test_getSyscheckConfig_no_directories, restart_syscheck),
        cmocka_unit_test_teardown(test_getSyscheckInternalOptions, restart_syscheck),
        cmocka_unit_test_teardown(test_SyscheckConf_DirectoriesWithCommas, restart_syscheck),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
