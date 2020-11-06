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

#include "../../wrappers/posix/pthread_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_agent_upgrade_wrappers.h"

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/agent_upgrade/wm_agent_upgrade.h"
#include "../../headers/shared.h"

void* wm_agent_upgrade_main(wm_agent_upgrade* upgrade_config);    
void wm_agent_upgrade_destroy(wm_agent_upgrade* upgrade_config);  
cJSON *wm_agent_upgrade_dump(const wm_agent_upgrade* upgrade_config);

// Setup / teardown

static int setup_group(void **state) {
    wm_agent_upgrade *config = NULL;
    os_calloc(1, sizeof(wm_agent_upgrade), config);
    *state = config;
    return 0;
}

static int teardown_group(void **state) {
    wm_agent_upgrade *config = *state;
    #ifdef TEST_SERVER
    os_free(config->manager_config.wpk_repository);
    #endif
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

// Tests

void test_wm_agent_upgrade_dump_enabled(void **state)
{
    wm_agent_upgrade *config = *state;

    config->enabled = 1;

    #ifdef TEST_SERVER
    os_strdup("wazuh.com/packages", config->manager_config.wpk_repository);
    config->manager_config.chunk_size = 512;
    config->manager_config.max_threads = 8;
    #endif

    cJSON *ret = wm_agent_upgrade_dump(config);

    state[1] = ret;

    assert_non_null(ret);
    cJSON *conf = cJSON_GetObjectItem(ret, "agent-upgrade");
    assert_non_null(conf);
    assert_non_null(cJSON_GetObjectItem(conf, "enabled"));
    assert_string_equal(cJSON_GetObjectItem(conf, "enabled")->valuestring, "yes");
    #ifdef TEST_SERVER
    assert_int_equal(cJSON_GetObjectItem(conf, "max_threads")->valueint, 8);
    assert_int_equal(cJSON_GetObjectItem(conf, "chunk_size")->valueint, 512);
    assert_non_null(cJSON_GetObjectItem(conf, "wpk_repository"));
    assert_string_equal(cJSON_GetObjectItem(conf, "wpk_repository")->valuestring, "wazuh.com/packages");
    #endif
}

void test_wm_agent_upgrade_dump_disabled(void **state)
{
    wm_agent_upgrade *config = *state;

    config->enabled = 0;

    #ifdef TEST_SERVER
    os_free(config->manager_config.wpk_repository);
    #endif

    cJSON *ret = wm_agent_upgrade_dump(config);

    state[1] = ret;

    assert_non_null(ret);
    cJSON *conf = cJSON_GetObjectItem(ret, "agent-upgrade");
    assert_non_null(conf);
    assert_non_null(cJSON_GetObjectItem(conf, "enabled"));
    assert_string_equal(cJSON_GetObjectItem(conf, "enabled")->valuestring, "no");
}

void test_wm_agent_upgrade_destroy(void **state)
{
    wm_agent_upgrade *config = NULL;
    os_calloc(1, sizeof(wm_agent_upgrade), config);

    #ifdef TEST_SERVER
    os_strdup("wazuh.com/packages", config->manager_config.wpk_repository);
    #endif

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtinfo, formatted_msg, "(8154): Module Agent Upgrade finished.");

    wm_agent_upgrade_destroy(config);
}

void test_wm_agent_upgrade_main_ok(void **state)
{
    wm_agent_upgrade *config = *state;

    config->enabled = 1;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtinfo, formatted_msg, "(8153): Module Agent Upgrade started.");

    #ifdef TEST_SERVER
    will_return(__wrap_wm_agent_upgrade_listen_messages, 1);
    #else
    will_return(__wrap_wm_agent_upgrade_check_status, 1);
    #endif

    wm_agent_upgrade_main(config);
}

void test_wm_agent_upgrade_main_disabled(void **state)
{
    wm_agent_upgrade *config = *state;

    config->enabled = 0;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtinfo, formatted_msg, "(8152): Module Agent Upgrade disabled. Exiting...");

    will_return(__wrap_pthread_exit, OS_INVALID);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtinfo, formatted_msg, "(8153): Module Agent Upgrade started.");

    #ifdef TEST_SERVER
    will_return(__wrap_wm_agent_upgrade_listen_messages, 1);
    #else
    will_return(__wrap_wm_agent_upgrade_check_status, 1);
    #endif

    wm_agent_upgrade_main(config);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_agent_upgrade_dump
        cmocka_unit_test_teardown(test_wm_agent_upgrade_dump_enabled, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_dump_disabled, teardown_json),
        // wm_task_manager_destroy
        cmocka_unit_test(test_wm_agent_upgrade_destroy),
        // wm_agent_upgrade_main
        cmocka_unit_test(test_wm_agent_upgrade_main_ok),
        cmocka_unit_test(test_wm_agent_upgrade_main_disabled)
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
