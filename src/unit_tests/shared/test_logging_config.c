/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* os_logging_config() (manager branch) over the mconf hook: `logging.log_format` of the effective
 * document decides the plain/json outputs; without provider the format is plain. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "mconf_hook.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../external/cJSON/cJSON.h"

static const char *s_logging_json = NULL;

static cJSON *test_provider(const char *section) {
    assert_string_equal(section, "logging");
    return s_logging_json != NULL ? cJSON_Parse(s_logging_json) : NULL;
}

static int setup_provider(void **state) {
    (void) state;
    s_logging_json = NULL;
    w_mconf_hook_set(test_provider);
    return 0;
}

static int teardown_provider(void **state) {
    (void) state;
    w_mconf_hook_set(NULL);
    return 0;
}

static void assert_format(const char *plain, const char *json) {
    cJSON *root = getLoggingConfig();
    cJSON *logging = cJSON_GetObjectItem(root, "logging");

    assert_non_null(logging);
    assert_string_equal(cJSON_GetObjectItem(logging, "plain")->valuestring, plain);
    assert_string_equal(cJSON_GetObjectItem(logging, "json")->valuestring, json);
    cJSON_Delete(root);
}

static void test_os_logging_config_json_only(void **state) {
    (void) state;

    s_logging_json = "{\"log_format\":[\"json\"]}";
    os_logging_config();
    assert_format("no", "yes");
}

static void test_os_logging_config_plain_and_json(void **state) {
    (void) state;

    s_logging_json = "{\"log_format\":[\"plain\",\"json\"]}";
    os_logging_config();
    assert_format("yes", "yes");
}

static void test_os_logging_config_defaults_to_plain(void **state) {
    (void) state;

    /* No document at all */
    s_logging_json = NULL;
    os_logging_config();
    assert_format("yes", "no");

    /* No provider at all (libwazuhshared.so in the engine) */
    w_mconf_hook_set(NULL);
    os_logging_config();
    assert_format("yes", "no");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_os_logging_config_json_only, setup_provider, teardown_provider),
        cmocka_unit_test_setup_teardown(test_os_logging_config_plain_and_json, setup_provider, teardown_provider),
        cmocka_unit_test_setup_teardown(test_os_logging_config_defaults_to_plain, setup_provider, teardown_provider),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
