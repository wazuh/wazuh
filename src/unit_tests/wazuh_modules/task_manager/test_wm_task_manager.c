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

#include "../../wrappers/posix/pthread_wrappers.h"
#include "../../wrappers/posix/select_wrappers.h"
#include "../../wrappers/posix/unistd_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/pthreads_op_wrappers.h"
#include "../../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_task_manager_wrappers.h"

#include "wmodules.h"
#include "wm_task_manager.h"
#include "wm_task_manager_tasks.h"
#include "shared.h"

int wm_task_manager_init(wm_task_manager *task_config);
void* wm_task_manager_main(wm_task_manager* task_config);
void wm_task_manager_destroy(wm_task_manager* task_config);
cJSON* wm_task_manager_dump(const wm_task_manager* task_config);

// Setup / teardown

static int setup_group(void **state) {
    wm_task_manager *config = NULL;
    os_calloc(1, sizeof(wm_task_manager), config);
    *state = config;
    return 0;
}

static int teardown_group(void **state) {
    wm_task_manager *config = *state;
    os_free(config);
    return 0;
}

static int teardown_json(void **state) {
    if (state[1]) {
        cJSON *json = state[1];
        cJSON_Delete(json);
    }
    return 0;
}

static int teardown_string(void **state) {
    if (state[1]) {
        char *string = state[1];
        os_free(string);
    }
    return 0;
}

// Wrappers

int __wrap_accept() {
    return mock();
}

// Helpers

static void expect_legacy_task_polling_interval(int value) {
    expect_value(__wrap_getDefine_Int_default, min, 300);
    expect_value(__wrap_getDefine_Int_default, max, 86400);
    expect_value(__wrap_getDefine_Int_default, default_val, 900);
    will_return(__wrap_getDefine_Int_default, value);
}

// Tests

void test_wm_task_manager_dump_enabled(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 1;

    cJSON *ret = wm_task_manager_dump(config);

    state[1] = ret;

    assert_non_null(ret);
    cJSON *conf = cJSON_GetObjectItem(ret, "task-manager");
    assert_non_null(conf);
    assert_non_null(cJSON_GetObjectItem(conf, "enabled"));
    assert_true(cJSON_IsTrue(cJSON_GetObjectItem(conf, "enabled")));
}

void test_wm_task_manager_dump_reports_the_recurring_tasks(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 1;

    cJSON *ret = wm_task_manager_dump(config);

    state[1] = ret;

    cJSON *conf = cJSON_GetObjectItem(ret, "task-manager");
    assert_non_null(conf);

    /* Absent while the dispatcher is down, which is the case in this suite: nothing has resolved the
     * recurring tasks' configuration, so there is nothing to report. Reporting the compiled defaults
     * instead would be a guess the caller could not tell apart from a live reading. */
    assert_null(cJSON_GetObjectItem(conf, "recurring_tasks"));

    /* The four XML options are reported either way -- they come from the parsed <task-manager>
     * block rather than from the dispatcher, so their presence must not depend on it. */
    assert_non_null(cJSON_GetObjectItem(conf, "task_ttl"));
    assert_non_null(cJSON_GetObjectItem(conf, "cleanup_interval"));
    assert_non_null(cJSON_GetObjectItem(conf, "max_payload_bytes"));
    assert_non_null(cJSON_GetObjectItem(conf, "max_tasks_per_poll"));
}

void test_wm_task_manager_dump_disabled(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 0;

    cJSON *ret = wm_task_manager_dump(config);

    state[1] = ret;

    assert_non_null(ret);
    cJSON *conf = cJSON_GetObjectItem(ret, "task-manager");
    assert_non_null(conf);
    assert_non_null(cJSON_GetObjectItem(conf, "enabled"));
    assert_true(cJSON_IsFalse(cJSON_GetObjectItem(conf, "enabled")));
}

void test_wm_task_manager_destroy(void **state)
{
    wm_task_manager *config = NULL;
    os_calloc(1, sizeof(wm_task_manager), config);

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8201): Module Task Manager finished.");

    wm_task_manager_destroy(config);
}

void test_wm_task_manager_init_ok(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;

    config->enabled = 1;

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "Task cache initialized");

    expect_legacy_task_polling_interval(900);

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_TASK_MODULE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

    int ret = wm_task_manager_init(config);

    assert_int_equal(ret, sock);
}

void test_wm_task_manager_init_bind_err(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 1;

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "Task cache initialized");

    expect_legacy_task_polling_interval(900);

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_TASK_MODULE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, OS_INVALID);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8251): Queue 'queue/sockets/task.sock' not accessible: 'Success'. Exiting...");

    expect_assert_failure(wm_task_manager_init(config));
}

void test_wm_task_manager_init_polling_interval_safe(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;

    config->enabled = 1;
    config->task_ttl = 2000;

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "Task cache initialized");

    expect_legacy_task_polling_interval(500);

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_TASK_MODULE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

    int ret = wm_task_manager_init(config);

    assert_int_equal(ret, sock);

    config->task_ttl = 0;
}

void test_wm_task_manager_init_polling_interval_equals_task_ttl(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;

    config->enabled = 1;
    config->task_ttl = 900;

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "Task cache initialized");

    expect_legacy_task_polling_interval(900);

    expect_string(__wrap__mtwarn, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mtwarn, formatted_msg,
        "remoted.legacy_task_polling_interval (900) is >= task-manager.task_ttl (900). "
        "A pending task may expire before the legacy task delivery poller ever gets a chance to see it.");

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, WM_TASK_MODULE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

    int ret = wm_task_manager_init(config);

    assert_int_equal(ret, sock);

    config->task_ttl = 0;
}

void test_wm_task_manager_init_disabled(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;

    config->enabled = 0;

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8202): Module disabled. Exiting...");

    expect_assert_failure(wm_task_manager_init(config));
}

/* wm_task_manager_read_json: the effective `task-manager` section of etc/wazuh-manager.conf over the module
 * default_modules[] initialised with wm_task_manager_read(NULL, NULL, module). */

void test_wm_task_manager_read_json_values(void **state)
{
    (void) state;
    wmodule module = { 0 };
    cJSON *section = cJSON_Parse("{\"task_ttl\":60,\"cleanup_interval\":30,\"max_payload_bytes\":2048,\"max_tasks_per_poll\":5}");

    assert_int_equal(wm_task_manager_read(NULL, NULL, &module), 0);
    assert_int_equal(wm_task_manager_read_json(section, &module), 0);
    cJSON_Delete(section);

    wm_task_manager *data = module.data;
    assert_true(data->enabled);
    assert_int_equal(data->task_ttl, 60);
    assert_int_equal(data->cleanup_interval, 30);
    assert_int_equal(data->max_payload_bytes, 2048);
    assert_int_equal(data->max_tasks_per_poll, 5);
    os_free(module.data);
    os_free(module.tag);
}

void test_wm_task_manager_read_json_null_section_keeps_zero_defaults(void **state)
{
    (void) state;
    wmodule module = { 0 };

    assert_int_equal(wm_task_manager_read(NULL, NULL, &module), 0);
    assert_int_equal(wm_task_manager_read_json(NULL, &module), 0);

    wm_task_manager *data = module.data;
    assert_true(data->enabled);
    assert_int_equal(data->task_ttl, 0);          // 0 = module default (dump() shows WM_TASK_DEFAULT_TTL)
    assert_int_equal(data->cleanup_interval, 0);
    assert_int_equal(data->max_payload_bytes, 0);
    assert_int_equal(data->max_tasks_per_poll, 0);
    os_free(module.data);
    os_free(module.tag);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_task_manager_dump
        cmocka_unit_test_teardown(test_wm_task_manager_dump_enabled, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_dump_reports_the_recurring_tasks, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_dump_disabled, teardown_json),
        // wm_task_manager_destroy
        cmocka_unit_test(test_wm_task_manager_destroy),
        // wm_task_manager_init
        cmocka_unit_test(test_wm_task_manager_init_ok),
        cmocka_unit_test(test_wm_task_manager_init_bind_err),
        // wm_task_manager_init - legacy_task_polling_interval vs task_ttl warning
        cmocka_unit_test(test_wm_task_manager_init_polling_interval_safe),
        cmocka_unit_test(test_wm_task_manager_init_polling_interval_equals_task_ttl),
        cmocka_unit_test(test_wm_task_manager_init_disabled),
        // wm_task_manager_read_json
        cmocka_unit_test(test_wm_task_manager_read_json_values),
        cmocka_unit_test(test_wm_task_manager_read_json_null_section_keeps_zero_defaults),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
