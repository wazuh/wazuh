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

/* --- module_report_add --- */
static void test_add_keys_the_body_by_module_name(void** state)
{
    (void)state;
    cJSON* report = cJSON_CreateObject();
    cJSON* body = cJSON_CreateObject();

    cJSON_AddStringToObject(body, "disabled", "no");
    module_report_add(report, "fim", body);

    /* Keyed by name, with the body directly under it: no {"module": ...}
     * wrapper for the manager to walk. */
    cJSON* stored = cJSON_GetObjectItem(report, "fim");
    assert_non_null(stored);
    assert_string_equal(cJSON_GetObjectItem(stored, "disabled")->valuestring, "no");

    cJSON_Delete(report);
}

static void test_add_keeps_each_module_separate(void** state)
{
    (void)state;
    cJSON* report = cJSON_CreateObject();
    cJSON* fim = cJSON_CreateObject();
    cJSON* lc = cJSON_CreateObject();

    cJSON_AddStringToObject(fim, "disabled", "no");
    cJSON_AddNumberToObject(lc, "events", 12);
    module_report_add(report, "fim", fim);
    module_report_add(report, "logcollector", lc);

    assert_non_null(cJSON_GetObjectItem(report, "fim"));
    assert_non_null(cJSON_GetObjectItem(report, "logcollector"));
    assert_int_equal(
        cJSON_GetObjectItem(cJSON_GetObjectItem(report, "logcollector"), "events")->valueint, 12);

    cJSON_Delete(report);
}

static void test_add_leaves_out_a_module_that_reported_nothing(void** state)
{
    (void)state;
    cJSON* report = cJSON_CreateObject();

    /* An empty body and a missing one both mean "this module said nothing", so
     * neither may appear: absent and empty must stay distinguishable. */
    module_report_add(report, "fim", cJSON_CreateObject());
    module_report_add(report, "logcollector", NULL);

    assert_null(cJSON_GetObjectItem(report, "fim"));
    assert_null(cJSON_GetObjectItem(report, "logcollector"));

    cJSON_Delete(report);
}

/* --- module_report_reply --- */
static void test_reply_prefixes_the_serialized_report_with_ok(void** state)
{
    (void)state;
    cJSON* report = cJSON_CreateObject();
    cJSON* body = cJSON_CreateObject();
    char* output = NULL;

    cJSON_AddStringToObject(body, "disabled", "no");
    module_report_add(report, "fim", body);

    size_t length = module_report_reply(report, &output);

    assert_non_null(output);
    assert_string_equal(output, "ok {\"fim\":{\"disabled\":\"no\"}}");
    assert_int_equal((int)length, (int)strlen(output));

    free(output);
}

static void test_reply_still_answers_when_no_module_reported(void** state)
{
    (void)state;
    char* output = NULL;

    /* An empty object is a valid answer: the daemon is up and hosts nothing
     * worth reporting. The caller must not read that as a failure. */
    size_t length = module_report_reply(cJSON_CreateObject(), &output);

    assert_string_equal(output, "ok {}");
    assert_int_equal((int)length, (int)strlen(output));

    free(output);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_merge_moves_every_section_under_one_body),
        cmocka_unit_test(test_merge_ignores_a_getter_that_returned_nothing),
        cmocka_unit_test(test_merge_consumes_the_section_even_without_a_body),
        cmocka_unit_test(test_add_keys_the_body_by_module_name),
        cmocka_unit_test(test_add_keeps_each_module_separate),
        cmocka_unit_test(test_add_leaves_out_a_module_that_reported_nothing),
        cmocka_unit_test(test_reply_prefixes_the_serialized_report_with_ok),
        cmocka_unit_test(test_reply_still_answers_when_no_module_reported),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
