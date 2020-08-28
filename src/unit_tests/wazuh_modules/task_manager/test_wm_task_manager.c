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

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/task_manager/wm_task_manager.h"
#include "../../headers/shared.h"

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

// Wrappers

void __wrap__mtinfo(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mterror(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_pthread_exit() {
    return mock();
}

int __wrap_wm_task_manager_check_db() {
    return mock();
}

int __wrap_CreateThread(void * (*function_pointer)(void *), void *data) {
    return mock();
}

int __wrap_OS_BindUnixDomain(const char *path, int type, int max_msg_size) {
    return mock();
}

int __wrap_select() {
    return mock();
}

int __wrap_close(int fd) {
    check_expected(fd);
    return 0;
}

int __wrap_accept() {
    return mock();
}

int __wrap_OS_RecvSecureTCP(int sock, char *ret, uint32_t size) {
    check_expected(sock);
    check_expected(size);

    strncpy(ret, mock_type(char*), size);

    return mock();
}

int __wrap_OS_SendSecureTCP(int sock, uint32_t size, const void * msg) {
    check_expected(sock);
    check_expected(size);
    check_expected(msg);

    return mock();
}

int __wrap_w_is_worker(void) {
    return mock();
}

cJSON* __wrap_wm_task_manager_parse_message(const char *msg) {
    check_expected(msg);

    return mock_type(cJSON*);
}

cJSON* __wrap_wm_task_manager_analyze_task(const cJSON *task_object, int *error_code) {
    check_expected(task_object);

    return mock_type(cJSON*);
}

cJSON* __wrap_wm_task_manager_parse_response(int error_code, int agent_id, int task_id, char *status) {
    check_expected(error_code);
    check_expected(agent_id);
    check_expected(task_id);
    if (status) check_expected(status);

    return mock_type(cJSON*);
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
    assert_string_equal(cJSON_GetObjectItem(conf, "enabled")->valuestring, "yes");
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
    assert_string_equal(cJSON_GetObjectItem(conf, "enabled")->valuestring, "no");
}

void test_wm_task_manager_destroy(void **state)
{
    wm_task_manager *config = NULL;
    os_calloc(1, sizeof(wm_task_manager), config);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8201): Module Task Manager finished.");

    wm_task_manager_destroy(config);
}

void test_wm_task_manager_init_ok(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;

    config->enabled = 1;

    will_return(__wrap_wm_task_manager_check_db, 0);

    will_return(__wrap_CreateThread, 1);

    will_return(__wrap_OS_BindUnixDomain, sock);

    int ret = wm_task_manager_init(config);

    assert_int_equal(ret, sock);
}

void test_wm_task_manager_init_bind_err(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 1;

    will_return(__wrap_wm_task_manager_check_db, 0);

    will_return(__wrap_CreateThread, 1);

    will_return(__wrap_OS_BindUnixDomain, OS_INVALID);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8251): Queue '/queue/tasks/task' not accesible: 'Success'. Exiting...");

    will_return(__wrap_pthread_exit, OS_INVALID);

    int ret = wm_task_manager_init(config);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_task_manager_init_db_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;

    config->enabled = 1;

    will_return(__wrap_wm_task_manager_check_db, OS_INVALID);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8250): DB integrity is invalid. Exiting...");

    will_return(__wrap_pthread_exit, OS_INVALID);

    will_return(__wrap_CreateThread, 1);

    will_return(__wrap_OS_BindUnixDomain, sock);

    int ret = wm_task_manager_init(config);

    assert_int_equal(ret, sock);
}

void test_wm_task_manager_init_disabled(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;

    config->enabled = 0;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8202): Module disabled. Exiting...");

    will_return(__wrap_pthread_exit, OS_INVALID);

    will_return(__wrap_wm_task_manager_check_db, 0);

    will_return(__wrap_CreateThread, 1);

    will_return(__wrap_OS_BindUnixDomain, sock);

    int ret = wm_task_manager_init(config);

    assert_int_equal(ret, sock);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_task_manager_dump
        cmocka_unit_test_teardown(test_wm_task_manager_dump_enabled, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_dump_disabled, teardown_json),
        // wm_task_manager_destroy
        cmocka_unit_test(test_wm_task_manager_destroy),
        // wm_task_manager_init
        cmocka_unit_test(test_wm_task_manager_init_ok),
        cmocka_unit_test(test_wm_task_manager_init_bind_err),
        cmocka_unit_test(test_wm_task_manager_init_db_err),
        cmocka_unit_test(test_wm_task_manager_init_disabled),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
