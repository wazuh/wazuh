/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>

#include <cJSON.h>

#include "wmodules.h"

/* --- Stub controls --- */
static cJSON* g_modules_cfg = NULL;
static cJSON* g_internal_cfg = NULL;

/* --- Stub implementations --- */
cJSON* __wrap_getModulesConfig(void)
{
    cJSON* ret = g_modules_cfg;
    g_modules_cfg = NULL;

    return ret;
}

cJSON* __wrap_getModulesInternalOptions(void)
{
    cJSON* ret = g_internal_cfg;
    g_internal_cfg = NULL;

    return ret;
}

/* --- Helpers --- */

/// @brief Build what getModulesConfig() returns: {"wmodules": [{"<name>": {...}}, ...]}.
static cJSON* dumped_wodles(const char** names, size_t count)
{
    cJSON* root = cJSON_CreateObject();
    cJSON* array = cJSON_CreateArray();
    size_t i;

    for (i = 0; i < count; i++) {
        cJSON* wodle = cJSON_CreateObject();
        cJSON* body = cJSON_CreateObject();

        cJSON_AddStringToObject(body, "disabled", "no");
        cJSON_AddItemToObject(wodle, names[i], body);
        cJSON_AddItemToArray(array, wodle);
    }

    cJSON_AddItemToObject(root, "wmodules", array);
    return root;
}

static cJSON* entry_named(cJSON* report, const char* name)
{
    cJSON* entry = NULL;

    cJSON_ArrayForEach(entry, report) {
        if (entry->string && strcmp(entry->string, name) == 0) {
            return entry;
        }
    }

    return NULL;
}

/* --- Tests --- */
static void test_getallconfig_gives_each_wodle_its_own_entry(void** state)
{
    (void)state;
    const char* names[] = {"syscollector", "sca"};
    char command[] = "getallconfig";
    char* output = NULL;

    g_modules_cfg = dumped_wodles(names, 2);

    size_t len = wmcom_dispatch(command, strlen(command), &output);

    assert_non_null(output);
    assert_true(strncmp(output, "ok ", 3) == 0);
    assert_int_equal((int)len, (int)strlen(output));

    cJSON* report = cJSON_Parse(output + 3);
    assert_non_null(report);

    /* One daemon, but the modules it hosts stay individually addressable
     * instead of being buried in a single "wmodules" blob. */
    assert_int_equal(cJSON_GetArraySize(report), 2); /* object members */
    assert_non_null(entry_named(report, "syscollector"));
    assert_non_null(entry_named(report, "sca"));
    assert_string_equal(
        cJSON_GetObjectItem(entry_named(report, "sca"),
                            "disabled")->valuestring,
        "no");

    cJSON_Delete(report);
    free(output);
}

static void test_getallconfig_reports_internal_options_separately(void** state)
{
    (void)state;
    const char* names[] = {"syscollector"};
    char command[] = "getallconfig";
    char* output = NULL;

    g_modules_cfg = dumped_wodles(names, 1);
    g_internal_cfg = cJSON_CreateObject();
    cJSON_AddNumberToObject(g_internal_cfg, "wazuh_modules.debug", 2);

    wmcom_dispatch(command, strlen(command), &output);

    cJSON* report = cJSON_Parse(output + 3);

    /* Internal options belong to modulesd itself, not to any one wodle. */
    assert_int_equal(cJSON_GetArraySize(report), 2); /* object members */
    assert_non_null(entry_named(report, "wmodules"));

    cJSON_Delete(report);
    free(output);
}

static void test_getallconfig_answers_even_with_no_wodles_loaded(void** state)
{
    (void)state;
    char command[] = "getallconfig";
    char* output = NULL;

    /* Nothing configured: both getters return NULL. The daemon still has to
     * answer, so the caller can tell it apart from an unreachable socket. */
    size_t len = wmcom_dispatch(command, strlen(command), &output);

    assert_string_equal(output, "ok {}");
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_getallconfig_gives_each_wodle_its_own_entry),
        cmocka_unit_test(test_getallconfig_reports_internal_options_separately),
        cmocka_unit_test(test_getallconfig_answers_even_with_no_wodles_loaded),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
