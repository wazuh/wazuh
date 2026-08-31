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
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_agent_upgrade_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_agent_upgrade_agent_wrappers.h"

#include "wmodules.h"
#include "wm_agent_upgrade.h"
#include "shared.h"

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
    #else
    if (wcom_ca_store) {
        for (int i=0; wcom_ca_store[i]; i++) {
            os_free(wcom_ca_store[i]);
        }
        os_free(wcom_ca_store);
    }
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
    #else
    config->agent_config.enable_ca_verification = 1;
    os_calloc(2, sizeof(char*), wcom_ca_store);
    os_strdup(DEF_CA_STORE, wcom_ca_store[0]);
    wcom_ca_store[1] = NULL;
    #endif

    cJSON *ret = wm_agent_upgrade_dump(config);

    state[1] = ret;

    assert_non_null(ret);
    cJSON *conf = cJSON_GetObjectItem(ret, "agent-upgrade");
    assert_non_null(conf);
    assert_non_null(cJSON_GetObjectItem(conf, "enabled"));
    assert_true(cJSON_IsTrue(cJSON_GetObjectItem(conf, "enabled")));
    #ifdef TEST_SERVER
    assert_non_null(cJSON_GetObjectItem(conf, "wpk_repository"));
    assert_string_equal(cJSON_GetObjectItem(conf, "wpk_repository")->valuestring, "wazuh.com/packages");
    #else
    assert_non_null(cJSON_GetObjectItem(conf, "ca_verification"));
    assert_true(cJSON_IsTrue(cJSON_GetObjectItem(conf, "ca_verification")));
    cJSON *certs = cJSON_GetObjectItem(conf, "ca_store");
    assert_non_null(certs);
    assert_int_equal(cJSON_GetArraySize(certs), 1);
    assert_string_equal(cJSON_GetArrayItem(certs, 0)->valuestring, DEF_CA_STORE);
    assert_null(cJSON_GetArrayItem(certs, 1));
    #endif
}

void test_wm_agent_upgrade_dump_disabled(void **state)
{
    wm_agent_upgrade *config = *state;

    config->enabled = 0;

    #ifdef TEST_SERVER
    os_free(config->manager_config.wpk_repository);
    #else
    config->agent_config.enable_ca_verification = 0;
    if (wcom_ca_store) {
        for (int i=0; wcom_ca_store[i]; i++) {
            os_free(wcom_ca_store[i]);
        }
        os_free(wcom_ca_store);
    }
    #endif

    cJSON *ret = wm_agent_upgrade_dump(config);

    state[1] = ret;

    assert_non_null(ret);
    cJSON *conf = cJSON_GetObjectItem(ret, "agent-upgrade");
    assert_non_null(conf);
    assert_non_null(cJSON_GetObjectItem(conf, "enabled"));
    assert_true(cJSON_IsFalse(cJSON_GetObjectItem(conf, "enabled")));
    #ifndef TEST_SERVER
    assert_non_null(cJSON_GetObjectItem(conf, "ca_verification"));
    assert_true(cJSON_IsFalse(cJSON_GetObjectItem(conf, "ca_verification")));
    cJSON *certs = cJSON_GetObjectItem(conf, "ca_store");
    assert_null(certs);
    #endif
}

void test_wm_agent_upgrade_destroy(void **state)
{
    wm_agent_upgrade *config = NULL;
    os_calloc(1, sizeof(wm_agent_upgrade), config);

    #ifdef TEST_SERVER
    os_strdup("wazuh.com/packages", config->manager_config.wpk_repository);
    #endif

    #ifdef TEST_SERVER
    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:agent-upgrade");
    #else
    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:agent-upgrade");
    #endif
    expect_string(__wrap__mtinfo, formatted_msg, "(8154): Module Agent Upgrade finished.");

    wm_agent_upgrade_destroy(config);
}

void test_wm_agent_upgrade_main_ok(void **state)
{
    wm_agent_upgrade *config = *state;

    config->enabled = 1;

    #ifdef TEST_SERVER
    expect_memory(__wrap_wm_agent_upgrade_start_manager_module, manager_configs, &config->manager_config, sizeof(&config->manager_config));
    expect_value(__wrap_wm_agent_upgrade_start_manager_module, enabled, config->enabled);
    #else
    expect_memory(__wrap_wm_agent_upgrade_start_agent_module, agent_config, &config->agent_config, sizeof(&config->agent_config));
    expect_value(__wrap_wm_agent_upgrade_start_agent_module, enabled, config->enabled);
    #endif

    wm_agent_upgrade_main(config);
}

void test_wm_agent_upgrade_main_disabled(void **state)
{
    wm_agent_upgrade *config = *state;

    config->enabled = 0;

    #ifdef TEST_SERVER
    expect_memory(__wrap_wm_agent_upgrade_start_manager_module, manager_configs, &config->manager_config, sizeof(&config->manager_config));
    expect_value(__wrap_wm_agent_upgrade_start_manager_module, enabled, config->enabled);
    #else
    expect_memory(__wrap_wm_agent_upgrade_start_agent_module, agent_config, &config->agent_config, sizeof(&config->agent_config));
    expect_value(__wrap_wm_agent_upgrade_start_agent_module, enabled, config->enabled);
    #endif

    wm_agent_upgrade_main(config);
}

#ifdef TEST_SERVER
/* wm_agent_upgrade_read_json: the effective `agent-upgrade` section of etc/wazuh-manager.yml over the module
 * default_modules[] initialised with wm_agent_upgrade_read(NULL, NULL, module). */

static void free_read_json_module(wmodule *module) {
    wm_agent_upgrade *data = module->data;
    os_free(data->manager_config.wpk_repository);
    os_free(module->data);
    os_free(module->tag);
}

void test_wm_agent_upgrade_read_json_sets_enabled_and_repository(void **state)
{
    (void) state;
    wmodule module = { 0 };
    cJSON *section = cJSON_Parse("{\"enabled\":false,\"wpk_repository\":\"repo.example/wpk/\"}");

    assert_int_equal(wm_agent_upgrade_read(NULL, NULL, &module), 0);
    assert_int_equal(wm_agent_upgrade_read_json(section, &module), 0);
    cJSON_Delete(section);

    wm_agent_upgrade *data = module.data;
    assert_false(data->enabled);
    assert_string_equal(data->manager_config.wpk_repository, "repo.example/wpk/");
    free_read_json_module(&module);
}

void test_wm_agent_upgrade_read_json_null_section_keeps_defaults(void **state)
{
    (void) state;
    wmodule module = { 0 };

    assert_int_equal(wm_agent_upgrade_read(NULL, NULL, &module), 0);
    assert_int_equal(wm_agent_upgrade_read_json(NULL, &module), 0);

    wm_agent_upgrade *data = module.data;
    assert_true(data->enabled);
    assert_null(data->manager_config.wpk_repository); // no schema default: repository chosen by target version
    free_read_json_module(&module);
}

void test_wm_agent_upgrade_read_json_replaces_repository(void **state)
{
    (void) state;
    wmodule module = { 0 };
    cJSON *first = cJSON_Parse("{\"wpk_repository\":\"first.example/wpk/\"}");
    cJSON *second = cJSON_Parse("{\"enabled\":true,\"wpk_repository\":\"second.example/wpk/\"}");

    assert_int_equal(wm_agent_upgrade_read(NULL, NULL, &module), 0);
    assert_int_equal(wm_agent_upgrade_read_json(first, &module), 0);
    assert_int_equal(wm_agent_upgrade_read_json(second, &module), 0);
    cJSON_Delete(first);
    cJSON_Delete(second);

    wm_agent_upgrade *data = module.data;
    assert_true(data->enabled);
    assert_string_equal(data->manager_config.wpk_repository, "second.example/wpk/");
    free_read_json_module(&module);
}
#endif

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_agent_upgrade_dump
        cmocka_unit_test_teardown(test_wm_agent_upgrade_dump_enabled, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_dump_disabled, teardown_json),
        // wm_task_manager_destroy
        cmocka_unit_test(test_wm_agent_upgrade_destroy),
        // wm_agent_upgrade_main
        cmocka_unit_test(test_wm_agent_upgrade_main_ok),
        cmocka_unit_test(test_wm_agent_upgrade_main_disabled),
#ifdef TEST_SERVER
        // wm_agent_upgrade_read_json
        cmocka_unit_test(test_wm_agent_upgrade_read_json_sets_enabled_and_repository),
        cmocka_unit_test(test_wm_agent_upgrade_read_json_null_section_keeps_defaults),
        cmocka_unit_test(test_wm_agent_upgrade_read_json_replaces_repository),
#endif
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
