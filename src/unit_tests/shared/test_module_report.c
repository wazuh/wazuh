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

#include "module_report.h"

/* --- Helpers --- */
static cJSON* wrapped_section(const char* name, const char* key, const char* value)
{
    cJSON* section = cJSON_CreateObject();
    cJSON* inner = cJSON_CreateObject();

    cJSON_AddStringToObject(inner, key, value);
    cJSON_AddItemToObject(section, name, inner);

    return section;
}

/* --- module_report_merge --- */
static void test_merge_moves_every_section_under_one_body(void** state)
{
    (void)state;
    cJSON* body = cJSON_CreateObject();

    module_report_merge(body, wrapped_section("syscheck", "frequency", "43200"));
    module_report_merge(body, wrapped_section("rootcheck", "disabled", "no"));

    /* Both sections keep their own key, side by side in the same body. */
    assert_non_null(cJSON_GetObjectItem(body, "syscheck"));
    assert_non_null(cJSON_GetObjectItem(body, "rootcheck"));
    assert_string_equal(
        cJSON_GetObjectItem(cJSON_GetObjectItem(body, "syscheck"), "frequency")->valuestring,
        "43200");

    cJSON_Delete(body);
}

static void test_merge_ignores_a_getter_that_returned_nothing(void** state)
{
    (void)state;
    cJSON* body = cJSON_CreateObject();

    /* A disabled component's getter returns NULL; passing it straight in must
     * be harmless so call sites need no guard. */
    module_report_merge(body, NULL);

    assert_null(body->child);

    cJSON_Delete(body);
}

static void test_merge_consumes_the_section_even_without_a_body(void** state)
{
    (void)state;

    /* The contract is that merge always takes the section. Leak checkers in CI
     * are what actually enforce this; the call must simply not crash. */
    module_report_merge(NULL, wrapped_section("syscheck", "frequency", "43200"));
}

/* --- module_report_add_config / _add_stats --- */
static void test_add_config_names_the_module_and_nests_its_body(void** state)
{
    (void)state;
    cJSON* report = cJSON_CreateArray();
    cJSON* body = cJSON_CreateObject();

    cJSON_AddStringToObject(body, "disabled", "no");
    module_report_add_config(report, "fim", body);

    assert_int_equal(cJSON_GetArraySize(report), 1);
    cJSON* entry = cJSON_GetArrayItem(report, 0);
    assert_string_equal(cJSON_GetObjectItem(entry, "module")->valuestring, "fim");
    assert_string_equal(
        cJSON_GetObjectItem(cJSON_GetObjectItem(entry, "config"), "disabled")->valuestring, "no");

    cJSON_Delete(report);
}

static void test_add_stats_files_the_body_under_stats(void** state)
{
    (void)state;
    cJSON* report = cJSON_CreateArray();
    cJSON* body = cJSON_CreateObject();

    cJSON_AddNumberToObject(body, "events", 12);
    module_report_add_stats(report, "logcollector", body);

    cJSON* entry = cJSON_GetArrayItem(report, 0);
    assert_null(cJSON_GetObjectItem(entry, "config"));
    assert_non_null(cJSON_GetObjectItem(entry, "stats"));

    cJSON_Delete(report);
}

static void test_add_leaves_out_a_module_that_reported_nothing(void** state)
{
    (void)state;
    cJSON* report = cJSON_CreateArray();

    /* An empty body and a missing one both mean "this module said nothing", so
     * neither may appear: absent and empty must stay distinguishable. */
    module_report_add_config(report, "fim", cJSON_CreateObject());
    module_report_add_config(report, "logcollector", NULL);

    assert_int_equal(cJSON_GetArraySize(report), 0);

    cJSON_Delete(report);
}

/* --- module_report_reply --- */
static void test_reply_prefixes_the_serialized_report_with_ok(void** state)
{
    (void)state;
    cJSON* report = cJSON_CreateArray();
    cJSON* body = cJSON_CreateObject();
    char* output = NULL;

    cJSON_AddStringToObject(body, "disabled", "no");
    module_report_add_config(report, "fim", body);

    size_t length = module_report_reply(report, &output);

    assert_non_null(output);
    assert_string_equal(output, "ok [{\"module\":\"fim\",\"config\":{\"disabled\":\"no\"}}]");
    assert_int_equal((int)length, (int)strlen(output));

    free(output);
}

static void test_reply_still_answers_when_no_module_reported(void** state)
{
    (void)state;
    char* output = NULL;

    /* An empty array is a valid answer: the daemon is up and hosts nothing
     * worth reporting. The caller must not read that as a failure. */
    size_t length = module_report_reply(cJSON_CreateArray(), &output);

    assert_string_equal(output, "ok []");
    assert_int_equal((int)length, (int)strlen(output));

    free(output);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_merge_moves_every_section_under_one_body),
        cmocka_unit_test(test_merge_ignores_a_getter_that_returned_nothing),
        cmocka_unit_test(test_merge_consumes_the_section_even_without_a_body),
        cmocka_unit_test(test_add_config_names_the_module_and_nests_its_body),
        cmocka_unit_test(test_add_stats_files_the_body_under_stats),
        cmocka_unit_test(test_add_leaves_out_a_module_that_reported_nothing),
        cmocka_unit_test(test_reply_prefixes_the_serialized_report_with_ok),
        cmocka_unit_test(test_reply_still_answers_when_no_module_reported),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
