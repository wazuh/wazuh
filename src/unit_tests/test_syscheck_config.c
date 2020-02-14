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
#include <string.h>

#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"

/* redefinitons/wrapping */

int __wrap__merror()
{
    return 0;
}

static int delete_json(void **state)
{
    cJSON *data = *state;
    cJSON_Delete(data);
    return 0;
}


/* tests */

void test_Read_Syscheck_Config_success(void **state)
{
    (void) state;
    int ret;

    ret = Read_Syscheck_Config("test_syscheck.conf");

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
}


void test_Read_Syscheck_Config_invalid(void **state)
{
    (void) state;
    int ret;

    ret = Read_Syscheck_Config("invalid.conf");

    assert_int_equal(ret, OS_INVALID);
}


void test_getSyscheckConfig(void **state)
{
    (void) state;
    cJSON * ret;

    Read_Syscheck_Config("test_syscheck.conf");

    ret = getSyscheckConfig();
    *state = ret;

    assert_non_null(ret);
    assert_int_equal(cJSON_GetArraySize(ret), 1);

    cJSON *sys_items = cJSON_GetObjectItem(ret, "syscheck");
    assert_int_equal(cJSON_GetArraySize(sys_items), 17);

    cJSON *disabled = cJSON_GetObjectItem(sys_items, "disabled");
    assert_string_equal(cJSON_GetStringValue(disabled), "no");
    cJSON *frequency = cJSON_GetObjectItem(sys_items, "frequency");
    assert_int_equal(frequency->valueint, 43200);
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
    assert_int_equal(cJSON_GetArraySize(sys_dir), 6);

    cJSON *sys_nodiff = cJSON_GetObjectItem(sys_items, "nodiff");
    assert_int_equal(cJSON_GetArraySize(sys_nodiff), 1);

    cJSON *sys_ignore = cJSON_GetObjectItem(sys_items, "ignore");
    assert_int_equal(cJSON_GetArraySize(sys_ignore), 12);

    cJSON *sys_whodata = cJSON_GetObjectItem(sys_items, "whodata");
    cJSON *whodata_restart_audit = cJSON_GetObjectItem(sys_whodata, "restart_audit");
    assert_string_equal(cJSON_GetStringValue(whodata_restart_audit), "yes");
    cJSON *whodata_audit_key = cJSON_GetObjectItem(sys_whodata, "audit_key");
    assert_int_equal(cJSON_GetArraySize(whodata_audit_key), 2);
    cJSON *whodata_startup_healthcheck = cJSON_GetObjectItem(sys_whodata, "startup_healthcheck");
    assert_string_equal(cJSON_GetStringValue(whodata_startup_healthcheck), "yes");

    cJSON *allow_remote_prefilter_cmd = cJSON_GetObjectItem(sys_items, "allow_remote_prefilter_cmd");
    assert_string_equal(cJSON_GetStringValue(allow_remote_prefilter_cmd), "yes");
    cJSON *prefilter_cmd = cJSON_GetObjectItem(sys_items, "prefilter_cmd");
    assert_string_equal(cJSON_GetStringValue(prefilter_cmd), "/bin/ls");

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
}


void test_getSyscheckInternalOptions(void **state)
{
    (void) state;
    cJSON * ret;

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
        cmocka_unit_test(test_Read_Syscheck_Config_success),
        cmocka_unit_test(test_Read_Syscheck_Config_invalid),
        cmocka_unit_test_teardown(test_getSyscheckConfig, delete_json),
        cmocka_unit_test_teardown(test_getSyscheckInternalOptions, delete_json),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
