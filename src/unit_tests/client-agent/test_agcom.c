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
static cJSON *g_buffer_cfg = NULL;
static cJSON *g_labels_cfg = NULL;
static cJSON *g_internal_cfg = NULL;
#ifndef WIN32
static cJSON *g_anti_tampering_cfg = NULL;
#endif
static const char *g_state_output = "ok state";

/* --- Stub implementations --- */
cJSON *__wrap_getClientConfig(void)
{
    cJSON *ret = g_client_cfg;
    g_client_cfg = NULL;

    return ret;
}

cJSON *__wrap_getBufferConfig(void)
{
    cJSON *ret = g_buffer_cfg;
    g_buffer_cfg = NULL;

    return ret;
}

cJSON *__wrap_getLabelsConfig(void)
{
    cJSON *ret = g_labels_cfg;
    g_labels_cfg = NULL;

    return ret;
}

cJSON *__wrap_getAgentInternalOptions(void)
{
    cJSON *ret = g_internal_cfg;
    g_internal_cfg = NULL;

    return ret;
}

#ifndef WIN32
cJSON *__wrap_getAntiTamperingConfig(void)
{
    cJSON *ret = g_anti_tampering_cfg;
    g_anti_tampering_cfg = NULL;

    return ret;
}
#endif

char *__wrap_w_agentd_state_get(void)
{
    return strdup(g_state_output);
}

/* --- Helpers --- */
static cJSON *make_simple_json(const char *key, const char *value)
{
    cJSON *root = cJSON_CreateObject();

    if (root)
    {
        cJSON_AddStringToObject(root, key, value);
    }

    return root;
}

/* --- Tests --- */
static void test_agcom_dispatch_getconfig_missing_args(void **state)
{
    (void)state;
    char command[] = "getconfig";
    char *output = NULL;

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "err AGCOM getconfig needs arguments");
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

static void test_agcom_dispatch_unknown_command(void **state)
{
    (void)state;
    char command[] = "invalidcmd";
    char *output = NULL;

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "err Unrecognized command");
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

static void test_agcom_dispatch_getstate(void **state)
{
    (void)state;
    char command[] = "getstate";
    char *output = NULL;

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "ok state");
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

static void test_agcom_getconfig_client_ok(void **state)
{
    (void)state;
    char command[] = "getconfig client";
    char *output = NULL;

    g_client_cfg = make_simple_json("client", "ok");

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_true(strncmp(output, "ok ", 3) == 0);
    assert_true(strlen(output) > 3);
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

static void test_agcom_getconfig_buffer_ok(void **state)
{
    (void)state;
    char command[] = "getconfig buffer";
    char *output = NULL;

    g_buffer_cfg = make_simple_json("buffer", "ok");

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_true(strncmp(output, "ok ", 3) == 0);
    assert_true(strlen(output) > 3);
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

static void test_agcom_getconfig_labels_ok(void **state)
{
    (void)state;
    char command[] = "getconfig labels";
    char *output = NULL;

    g_labels_cfg = make_simple_json("labels", "ok");

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_true(strncmp(output, "ok ", 3) == 0);
    assert_true(strlen(output) > 3);
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

static void test_agcom_getconfig_internal_ok(void **state)
{
    (void)state;
    char command[] = "getconfig internal";
    char *output = NULL;

    g_internal_cfg = make_simple_json("internal", "ok");

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_true(strncmp(output, "ok ", 3) == 0);
    assert_true(strlen(output) > 3);
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

#ifndef WIN32
static void test_agcom_getconfig_anti_tampering_ok(void **state)
{
    (void)state;
    char command[] = "getconfig anti_tampering";
    char *output = NULL;

    g_anti_tampering_cfg = make_simple_json("anti_tampering", "ok");

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_true(strncmp(output, "ok ", 3) == 0);
    assert_true(strlen(output) > 3);
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}
#endif

static void test_agcom_getconfig_client_error(void **state)
{
    (void)state;
    char command[] = "getconfig client";
    char *output = NULL;

    g_client_cfg = NULL;

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "err Could not get requested section");
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

static void test_agcom_getconfig_unknown_section(void **state)
{
    (void)state;
    char command[] = "getconfig unknown";
    char *output = NULL;

    size_t len = agcom_dispatch(command, &output);

    assert_non_null(output);
    assert_string_equal(output, "err Could not get requested section");
    assert_int_equal((int)len, (int)strlen(output));

    free(output);
}

int main(void)
{
    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test(test_agcom_dispatch_getconfig_missing_args),
        cmocka_unit_test(test_agcom_dispatch_unknown_command),
        cmocka_unit_test(test_agcom_dispatch_getstate),
        cmocka_unit_test(test_agcom_getconfig_client_ok),
        cmocka_unit_test(test_agcom_getconfig_buffer_ok),
        cmocka_unit_test(test_agcom_getconfig_labels_ok),
        cmocka_unit_test(test_agcom_getconfig_internal_ok),
#ifndef WIN32
        cmocka_unit_test(test_agcom_getconfig_anti_tampering_ok),
#endif
        cmocka_unit_test(test_agcom_getconfig_client_error),
        cmocka_unit_test(test_agcom_getconfig_unknown_section),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}