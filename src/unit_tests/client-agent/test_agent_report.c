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

#include "agentd.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* The aggregator asks each daemon in turn. These stubs stand in for the
 * component sockets so a test can decide, per component, whether it answers,
 * refuses, or is not there at all. */

typedef struct answer_t {
    const char* target;     ///< Component the answer belongs to.
    const char* reply;      ///< Reply to hand back, NULL when unreachable.
} answer_t;

static const answer_t* g_answers = NULL;
static size_t g_answer_count = 0;
static const char* g_connected_target = NULL;
static int g_connect_calls = 0;

/* --- Stub implementations --- */
static const answer_t* answer_for(const char* target)
{
    size_t i;

    for (i = 0; i < g_answer_count; i++) {
        if (strcmp(g_answers[i].target, target) == 0) {
            return &g_answers[i];
        }
    }

    return NULL;
}

int __wrap_OS_ConnectUnixDomain(const char* path, __attribute__((unused)) int type,
                                __attribute__((unused)) int max_msg_size)
{
    /* The path is "queue/sockets/<target>"; keep the target so the recv stub
     * knows which component this socket belongs to. */
    const char* target = strrchr(path, '/');
    const answer_t* answer = answer_for(target ? target + 1 : path);

    g_connect_calls++;

    if (!answer || !answer->reply) {
        return -1;
    }

    g_connected_target = answer->target;
    return 42;
}

int __wrap_OS_SendSecureTCP(__attribute__((unused)) int sock,
                            __attribute__((unused)) uint32_t size,
                            __attribute__((unused)) const void* msg)
{
    return 0;
}

int __wrap_OS_RecvSecureTCP(__attribute__((unused)) int sock, char* ret,
                            __attribute__((unused)) uint32_t size)
{
    const answer_t* answer = g_connected_target ? answer_for(g_connected_target) : NULL;

    if (!answer || !answer->reply) {
        return -1;
    }

    strcpy(ret, answer->reply);
    return (int)strlen(answer->reply);
}

/* --- Helpers --- */
static void given(const answer_t* answers, size_t count)
{
    g_answers = answers;
    g_answer_count = count;
    g_connected_target = NULL;
    g_connect_calls = 0;
}

/// @brief Allow the debug lines a component that is down or refusing produces.
///        Only the tests that exercise those paths may declare this: cmocka
///        fails a test that leaves the expectation unused.
static void expecting_debug_logs(void)
{
    expect_any_always(__wrap__mdebug1, formatted_msg);
}

static cJSON* module_named(cJSON* document, const char* name)
{
    cJSON* modules = cJSON_GetObjectItem(document, "modules");
    cJSON* entry = NULL;

    cJSON_ArrayForEach(entry, modules) {
        cJSON* module = cJSON_GetObjectItem(entry, "module");

        if (module && strcmp(module->valuestring, name) == 0) {
            return entry;
        }
    }

    return NULL;
}

/* --- Tests --- */
static void test_collect_config_merges_every_daemon_into_one_document(void** state)
{
    (void)state;
    const answer_t answers[] = {
        {"agent", "ok [{\"module\":\"agent\",\"config\":{\"client\":{}}}]"},
        {"syscheck", "ok [{\"module\":\"fim\",\"config\":{\"syscheck\":{}}}]"},
        {"logcollector", "ok [{\"module\":\"logcollector\",\"config\":{\"localfile\":[]}}]"},
        /* One daemon, two modules: modulesd reports each wodle separately. */
        {"wmodules", "ok [{\"module\":\"syscollector\",\"config\":{}},"
                     "{\"module\":\"sca\",\"config\":{}}]"},
        {"com", "ok [{\"module\":\"execd\",\"config\":{\"active-response\":[]}}]"},
    };

    given(answers, 5);

    char* document = w_agent_collect_config();

    assert_non_null(document);

    cJSON* parsed = cJSON_Parse(document);
    assert_non_null(parsed);

    /* One query per daemon, and every module they named is present. */
    assert_int_equal(g_connect_calls, 5);
    assert_int_equal(cJSON_GetArraySize(cJSON_GetObjectItem(parsed, "modules")), 6);
    assert_non_null(module_named(parsed, "agent"));
    assert_non_null(module_named(parsed, "fim"));
    assert_non_null(module_named(parsed, "logcollector"));
    assert_non_null(module_named(parsed, "syscollector"));
    assert_non_null(module_named(parsed, "sca"));
    assert_non_null(module_named(parsed, "execd"));

    cJSON_Delete(parsed);
    free(document);
}

static void test_collect_config_reports_the_daemons_that_are_up(void** state)
{
    (void)state;
    const answer_t answers[] = {
        {"agent", "ok [{\"module\":\"agent\",\"config\":{\"client\":{}}}]"},
        {"syscheck", NULL},         /* not running */
        {"logcollector", "err Could not get requested section"},
        {"wmodules", "ok [{\"module\":\"sca\",\"config\":{}}]"},
        {"com", NULL},
    };

    given(answers, 5);
    expecting_debug_logs();

    char* document = w_agent_collect_config();

    assert_non_null(document);

    cJSON* parsed = cJSON_Parse(document);
    /* A daemon that is down or refuses is left out; the rest still report, so
     * one sick component does not cost the manager the whole document. */
    assert_int_equal(cJSON_GetArraySize(cJSON_GetObjectItem(parsed, "modules")), 2);
    assert_non_null(module_named(parsed, "agent"));
    assert_non_null(module_named(parsed, "sca"));
    assert_null(module_named(parsed, "fim"));

    cJSON_Delete(parsed);
    free(document);
}

static void test_collect_config_skips_the_cycle_when_nothing_answers(void** state)
{
    (void)state;
    const answer_t answers[] = {
        {"agent", NULL},
        {"syscheck", NULL},
        {"logcollector", NULL},
        {"wmodules", NULL},
        {"com", NULL},
    };

    given(answers, 5);
    expecting_debug_logs();

    /* Pushing {"modules":[]} here would overwrite a good document in the
     * manager's index with an empty one, so the cycle is skipped instead. */
    assert_null(w_agent_collect_config());
}

static void test_collect_config_ignores_a_reply_that_is_not_a_report(void** state)
{
    (void)state;
    const answer_t answers[] = {
        {"agent", "ok {\"module\":\"agent\"}"},   /* an object, not an array */
        {"syscheck", "ok not json at all"},
        {"logcollector", "ok [{\"module\":\"logcollector\",\"config\":{}}]"},
        {"wmodules", NULL},
        {"com", NULL},
    };

    given(answers, 5);
    expecting_debug_logs();

    char* document = w_agent_collect_config();
    cJSON* parsed = cJSON_Parse(document);

    assert_int_equal(cJSON_GetArraySize(cJSON_GetObjectItem(parsed, "modules")), 1);
    assert_non_null(module_named(parsed, "logcollector"));

    cJSON_Delete(parsed);
    free(document);
}

static void test_collect_stats_only_asks_the_daemons_that_produce_them(void** state)
{
    (void)state;
    const answer_t answers[] = {
        {"agent", "ok [{\"module\":\"agent\",\"stats\":{\"status\":\"connected\"}}]"},
        {"logcollector", "ok [{\"module\":\"logcollector\",\"stats\":{}}]"},
    };

    given(answers, 2);

    char* document = w_agent_collect_stats();

    assert_non_null(document);

    cJSON* parsed = cJSON_Parse(document);
    /* Only two daemons have a getstate handler, so only two are queried. */
    assert_int_equal(g_connect_calls, 2);
    assert_int_equal(cJSON_GetArraySize(cJSON_GetObjectItem(parsed, "modules")), 2);

    cJSON_Delete(parsed);
    free(document);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_collect_config_merges_every_daemon_into_one_document),
        cmocka_unit_test(test_collect_config_reports_the_daemons_that_are_up),
        cmocka_unit_test(test_collect_config_skips_the_cycle_when_nothing_answers),
        cmocka_unit_test(test_collect_config_ignores_a_reply_that_is_not_a_report),
        cmocka_unit_test(test_collect_stats_only_asks_the_daemons_that_produce_them),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
