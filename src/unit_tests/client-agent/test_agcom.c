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
#include <string.h>
#include <stdlib.h>

#include <cJSON.h>

#include "agentd.h"

/* --- Stub controls --- */
static cJSON *g_client_cfg = NULL;
static cJSON *g_internal_cfg = NULL;
#ifndef WIN32
static cJSON *g_anti_tampering_cfg = NULL;
#endif
static cJSON *g_state_body = NULL;

/* --- Stub implementations --- */
cJSON* __wrap_getAgentConfig(void)
{
    cJSON* ret = g_client_cfg;
    g_client_cfg = NULL;

    return ret;
}

cJSON* __wrap_getAgentInternalOptions(void)
{
    cJSON* ret = g_internal_cfg;
    g_internal_cfg = NULL;

    return ret;
}

#ifndef WIN32
cJSON* __wrap_getAntiTamperingConfig(void)
{
    cJSON* ret = g_anti_tampering_cfg;
    g_anti_tampering_cfg = NULL;

    return ret;
}
#endif

cJSON* __wrap_w_agentd_state_get(void)
{
    cJSON* ret = g_state_body;
    g_state_body = NULL;

    return ret;
}

/* --- Helpers --- */
static cJSON* make_simple_json(const char* key, const char* value)
{
    cJSON* root = cJSON_CreateObject();

    if (root)
    {
        cJSON_AddStringToObject(root, key, value);
    }

    return root;
}

/* --- Tests --- */
static void test_agcom_dispatch_getconfig_missing_args(void** state)
{
    (void)state;
    char command[] = "getconfig";
    char* output = NULL;

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "err AGCOM getconfig needs arguments");
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

static void test_agcom_dispatch_unknown_command(void** state)
{
    (void)state;
    char command[] = "invalidcmd";
    char* output = NULL;

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "err Unrecognized command");
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

static void test_agcom_dispatch_getstate_wraps_the_body_in_the_envelope(void** state)
{
    (void)state;
    char command[] = "getstate";
    char* output = NULL;

    g_state_body = make_simple_json("status", "connected");

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_int_equal((int)len, (int)strlen(output));

    /* "getstate" is a socket call: the envelope is its framing, added at this
     * call site rather than by w_agentd_state_get(), which the /stats push
     * sends bare. */
    cJSON* parsed = cJSON_Parse(output);
    assert_non_null(parsed);
    assert_int_equal(cJSON_GetObjectItem(parsed, "error")->valueint, 0);
    assert_string_equal(
        cJSON_GetObjectItem(cJSON_GetObjectItem(parsed, "data"), "status")->valuestring,
        "connected");

    cJSON_Delete(parsed);
    free(output);
}

static void test_agcom_getconfig_client_ok(void** state)
{
    (void)state;
    char command[] = "getconfig client";
    char* output = NULL;

    g_client_cfg = make_simple_json("agent", "ok");

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_true(strncmp(output, "ok ", 3) == 0);
    assert_true(strlen(output) > 3);
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

static void test_agcom_getconfig_internal_ok(void** state)
{
    (void)state;
    char command[] = "getconfig internal";
    char* output = NULL;

    g_internal_cfg = make_simple_json("internal", "ok");

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_true(strncmp(output, "ok ", 3) == 0);
    assert_true(strlen(output) > 3);
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

#ifndef WIN32
static void test_agcom_getconfig_anti_tampering_ok(void** state)
{
    (void)state;
    char command[] = "getconfig anti_tampering";
    char* output = NULL;

    g_anti_tampering_cfg = make_simple_json("anti_tampering", "ok");

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_true(strncmp(output, "ok ", 3) == 0);
    assert_true(strlen(output) > 3);
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}
#endif

static void test_agcom_getconfig_client_error(void** state)
{
    (void)state;
    char command[] = "getconfig client";
    char* output = NULL;

    g_client_cfg = NULL;

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "err Could not get requested section");
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

static void test_agcom_getconfig_unknown_section(void** state)
{
    (void)state;
    char command[] = "getconfig unknown";
    char* output = NULL;

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "err Could not get requested section");
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

static void test_agcom_getallconfig_reports_every_section_as_one_module(void** state)
{
    (void)state;
    char command[] = "getallconfig";
    char* output = NULL;

    g_client_cfg = make_simple_json("agent", "ok");
    g_internal_cfg = make_simple_json("internal", "ok");
#ifndef WIN32
    g_anti_tampering_cfg = make_simple_json("anti_tampering", "ok");
#endif

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_true(strncmp(output, "ok ", 3) == 0);
    assert_int_equal((int)len, (int)strlen(output));

    cJSON* report = cJSON_Parse(output + 3);
    assert_non_null(report);
    /* One entry for the whole daemon, with every section inside it: this is
     * what saves the caller a query per section. */
    /* Keyed by module name, body directly under it. */
    cJSON* config = cJSON_GetObjectItem(report, "agent");
    assert_non_null(config);
    assert_non_null(cJSON_GetObjectItem(config, "agent"));
    assert_non_null(cJSON_GetObjectItem(config, "internal"));
#ifndef WIN32
    assert_non_null(cJSON_GetObjectItem(config, "anti_tampering"));
#endif

    cJSON_Delete(report);
    free(output);
}

static void test_agcom_getallconfig_omits_sections_that_are_unset(void** state)
{
    (void)state;
    char command[] = "getallconfig";
    char* output = NULL;

    /* Only the client section is configured; the rest return NULL. */
    g_client_cfg = make_simple_json("agent", "ok");

    size_t len = agcom_dispatch(command, &output);

    assert_int_equal((int)len, (int)strlen(output));

    cJSON* report = cJSON_Parse(output + 3);
    cJSON* config = cJSON_GetObjectItem(report, "agent");
    assert_non_null(cJSON_GetObjectItem(config, "agent"));
    assert_null(cJSON_GetObjectItem(config, "internal"));

    cJSON_Delete(report);
    free(output);
}

static void test_agcom_getallstats_reports_the_grouped_message_counters(void** state)
{
    (void)state;
    char command[] = "getallstats";
    char* output = NULL;

    /* The shape the manager indexes: no {"error","data"} envelope, and the
     * message counters grouped under "messages". */
    cJSON* report = cJSON_CreateObject();
    cJSON* messages = cJSON_CreateObject();
    cJSON* sent = cJSON_CreateObject();
    cJSON_AddStringToObject(report, "status", "connected");
    cJSON_AddNumberToObject(messages, "count", 602);
    cJSON_AddNumberToObject(messages, "buffered", 0);
    cJSON_AddNumberToObject(sent, "total", 689);
    cJSON_AddItemToObject(messages, "sent", sent);
    cJSON_AddItemToObject(report, "messages", messages);
    g_state_body = report;

    size_t len = agcom_dispatch(command, &output);

    assert_int_equal((int)len, (int)strlen(output));

    cJSON* parsed = cJSON_Parse(output + 3);
    cJSON* stats = cJSON_GetObjectItem(parsed, "agent");
    assert_non_null(stats);
    assert_null(cJSON_GetObjectItem(stats, "data"));
    assert_null(cJSON_GetObjectItem(stats, "msg_count"));

    cJSON* out_messages = cJSON_GetObjectItem(stats, "messages");
    assert_non_null(out_messages);
    assert_int_equal(cJSON_GetObjectItem(out_messages, "count")->valueint, 602);
    assert_int_equal(cJSON_GetObjectItem(out_messages, "buffered")->valueint, 0);
    assert_int_equal(
        cJSON_GetObjectItem(cJSON_GetObjectItem(out_messages, "sent"), "total")->valueint, 689);

    cJSON_Delete(parsed);
    free(output);
}

static void test_agcom_getallstats_drops_an_unavailable_report(void** state)
{
    (void)state;
    char command[] = "getallstats";
    char* output = NULL;

    /* g_stats_report is NULL: the entry is left out rather than reported empty. */
    size_t len = agcom_dispatch(command, &output);

    assert_int_equal((int)len, (int)strlen(output));
    assert_string_equal(output, "ok {}");

    free(output);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_agcom_dispatch_getconfig_missing_args),
        cmocka_unit_test(test_agcom_dispatch_unknown_command),
        cmocka_unit_test(test_agcom_dispatch_getstate_wraps_the_body_in_the_envelope),
        cmocka_unit_test(test_agcom_getconfig_client_ok),
        cmocka_unit_test(test_agcom_getconfig_internal_ok),
#ifndef WIN32
        cmocka_unit_test(test_agcom_getconfig_anti_tampering_ok),
#endif
        cmocka_unit_test(test_agcom_getconfig_client_error),
        cmocka_unit_test(test_agcom_getconfig_unknown_section),
        cmocka_unit_test(test_agcom_getallconfig_reports_every_section_as_one_module),
        cmocka_unit_test(test_agcom_getallconfig_omits_sections_that_are_unset),
        cmocka_unit_test(test_agcom_getallstats_reports_the_grouped_message_counters),
        cmocka_unit_test(test_agcom_getallstats_drops_an_unavailable_report),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
