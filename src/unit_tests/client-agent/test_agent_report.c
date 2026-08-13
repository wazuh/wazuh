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

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "agentd.h"
#ifndef TEST_WINAGENT
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#endif

/* The aggregator asks each daemon in turn. These stubs stand in for whatever it
 * asks THROUGH, so a test can decide, per component, whether it answers,
 * refuses, or is not there at all.
 *
 * The two platforms reach the daemons differently and both need covering: on
 * POSIX each one is a separate process behind a socket, while a Windows agent
 * runs them all in-process and calls their dispatchers directly. The stubs
 * below switch; every assertion further down is shared. */

typedef struct answer_t {
    const char* target;     ///< Component the answer belongs to.
    const char* reply;      ///< Reply to hand back, NULL when unreachable.
} answer_t;

static const answer_t* g_answers = NULL;
static size_t g_answer_count = 0;
static const char* g_connected_target = NULL;
static int g_connect_calls = 0;

/* report_query() gates every component query on this (#37843 follow-up). Wrapped
 * (not touched via extern) because agent_report.c/startup_gate.c are each compiled
 * twice for TARGET=winagent -- once into agentd_lib, once into wazuh-agentd (see
 * client-agent/CMakeLists.txt) -- so a global this test pokes directly is not
 * guaranteed to be the same one the linked report_query() actually reads (that bit
 * every test in this file that expected a component to answer, on CI's winagent
 * run, twice). --wrap redirects the *call*, so it does not matter which of the two
 * compiled copies of report_query() ends up in the final binary. */
bool __wrap_startup_gate_is_settled(__attribute__((unused)) unsigned int margin_seconds)
{
    return true;
}

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

#ifndef TEST_WINAGENT

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

#else /* TEST_WINAGENT */

/**
 * @brief Stand in for one component's dispatcher.
 *
 * A component that is "not there" answers 0 with no output, which is what a
 * dispatcher that does not recognise the command does; the aggregator has to
 * treat that the same way it treats an unreachable socket on POSIX.
 */
static size_t dispatch_as(const char* target, char** output)
{
    const answer_t* answer = answer_for(target);

    g_connect_calls++;

    if (!answer || !answer->reply) {
        return 0;
    }

    os_strdup(answer->reply, *output);
    return strlen(*output);
}

size_t __wrap_agcom_dispatch(__attribute__((unused)) char* command, char** output)
{
    return dispatch_as("agent", output);
}

size_t __wrap_syscom_dispatch(__attribute__((unused)) char* command,
                              __attribute__((unused)) size_t command_len, char** output)
{
    return dispatch_as("syscheck", output);
}

size_t __wrap_lccom_dispatch(__attribute__((unused)) char* command, char** output)
{
    return dispatch_as("logcollector", output);
}

size_t __wrap_wmcom_dispatch(__attribute__((unused)) char* command,
                             __attribute__((unused)) size_t command_len, char** output)
{
    return dispatch_as("wmodules", output);
}

size_t __wrap_wcom_dispatch(__attribute__((unused)) char* command, char** output)
{
    return dispatch_as("com", output);
}

#endif /* TEST_WINAGENT */

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
    /* "modules" is keyed by module name, so this is a direct lookup. */
    return cJSON_GetObjectItem(cJSON_GetObjectItem(document, "modules"), name);
}

/* --- Tests --- */
static void test_collect_config_merges_every_daemon_into_one_document(void** state)
{
    (void)state;
    const answer_t answers[] = {
        {"agent", "ok {\"agent\":{\"client\":{}}}"},
        {"syscheck", "ok {\"fim\":{\"syscheck\":{}}}"},
        {"logcollector", "ok {\"logcollector\":{\"localfile\":[]}}"},
        /* One daemon, two modules: modulesd reports each wodle separately. */
        {"wmodules", "ok {\"syscollector\":{},\"sca\":{}}"},
        {"com", "ok {\"execd\":{\"active-response\":[]}}"},
    };

    given(answers, 5);

    char* document = w_agent_collect_config();

    assert_non_null(document);

    cJSON* parsed = cJSON_Parse(document);
    assert_non_null(parsed);

    /* One query per daemon, and every module they named is present. */
    assert_int_equal(g_connect_calls, 5);
    assert_int_equal(cJSON_GetArraySize(cJSON_GetObjectItem(parsed, "modules")), 6); /* object members */
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
        {"agent", "ok {\"agent\":{\"client\":{}}}"},
        {"syscheck", NULL},         /* not running */
        {"logcollector", "err Could not get requested section"},
        {"wmodules", "ok {\"sca\":{}}"},
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
        {"agent", "ok [{\"module\":\"agent\"}]"},  /* the old array shape */
        {"syscheck", "ok not json at all"},
        {"logcollector", "ok {\"logcollector\":{}}"},
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
        {"agent", "ok {\"agent\":{\"status\":\"connected\"}}"},
        {"logcollector", "ok {\"logcollector\":{}}"},
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
