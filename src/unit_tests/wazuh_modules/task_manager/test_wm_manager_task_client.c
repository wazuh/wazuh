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
#include <string.h>

#include "wmodules.h"
#include "../../../wazuh_modules/src/task_manager/wm_manager_task_client.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_db/wdb_wrappers.h"

#define TEST_TIMEOUT 10

static int test_setup(void **state) {
    wm_manager_task_client *client = NULL;

    os_calloc(1, sizeof(wm_manager_task_client), client);
    client->sock = 7;
    client->timeout = TEST_TIMEOUT;

    *state = client;

    return 0;
}

static int test_teardown(void **state) {
    os_free(*state);
    return 0;
}

/**
 * @brief Queue one round trip: the exact query expected, and the response to answer with.
 */
static void expect_wdb_call(const char *query, const char *response, int retval) {
    expect_value(__wrap_wdbc_query_ex_timeout, *sock, 7);
    expect_string(__wrap_wdbc_query_ex_timeout, query, query);
    expect_value(__wrap_wdbc_query_ex_timeout, len, WDBOUTPUT_SIZE);
    expect_value(__wrap_wdbc_query_ex_timeout, timeout, TEST_TIMEOUT);
    will_return(__wrap_wdbc_query_ex_timeout, response);
    will_return(__wrap_wdbc_query_ex_timeout, retval);

    if (retval == 0) {
        expect_string(__wrap_wdbc_parse_result, result, response);
        will_return(__wrap_wdbc_parse_result, WDBC_OK);
    }
}

/* wm_manager_task_client_call */

void test_call_sends_the_command_and_returns_the_response(void **state) {
    wm_manager_task_client *client = *state;
    cJSON *response = NULL;

    expect_wdb_call("task get_manager_task {\"task_id\":\"abc\"}", "ok {\"error\":0,\"task\":{\"status\":\"pending\"}}", 0);

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "task_id", "abc");

    assert_int_equal(wm_manager_task_client_call(client, "get_manager_task", parameters, &response), 0);
    assert_non_null(response);

    // The error field is consumed here so callers read only their own fields.
    assert_null(cJSON_GetObjectItem(response, "error"));
    assert_non_null(cJSON_GetObjectItem(response, "task"));

    cJSON_Delete(response);
}

void test_call_supplies_an_empty_object_when_given_none(void **state) {
    wm_manager_task_client *client = *state;

    // Sub-commands that read nothing still take a parameters object, so the dispatch on the
    // wazuh-db side stays uniform.
    expect_wdb_call("task poll_manager_tasks {}", "ok {\"error\":0,\"types\":[]}", 0);

    assert_int_equal(wm_manager_task_client_call(client, "poll_manager_tasks", NULL, NULL), 0);
}

void test_call_drops_the_socket_on_a_transport_failure(void **state) {
    wm_manager_task_client *client = *state;

    expect_wdb_call("task poll_manager_tasks {}", "", -2);
    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "Cannot send 'poll_manager_tasks' to the tasks database.");

    assert_int_equal(wm_manager_task_client_call(client, "poll_manager_tasks", NULL, NULL), -1);

    // The connection's state is unknown after a failed or timed-out call, so it is dropped rather
    // than reused; the next call reconnects.
    assert_int_equal(client->sock, -1);
}

void test_call_treats_a_database_error_as_a_failure(void **state) {
    wm_manager_task_client *client = *state;
    cJSON *response = NULL;

    // The task actor answers "ok" even when the write failed, carrying the outcome in the error
    // field. A caller that only checked the ok prefix would read a failed write as a success.
    expect_wdb_call("task poll_manager_tasks {}", "ok {\"error\":-1}", 0);
    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "Tasks database reported an error for 'poll_manager_tasks'.");

    assert_int_equal(wm_manager_task_client_call(client, "poll_manager_tasks", NULL, &response), -1);
    assert_null(response);

    // A database error is not a broken connection, so the socket stays.
    assert_int_equal(client->sock, 7);
}

void test_call_rejects_an_unparseable_response(void **state) {
    wm_manager_task_client *client = *state;

    expect_wdb_call("task poll_manager_tasks {}", "ok not-json", 0);
    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg,
                  "Cannot parse the tasks database response to 'poll_manager_tasks'.");

    assert_int_equal(wm_manager_task_client_call(client, "poll_manager_tasks", NULL, NULL), -1);
}

/* wm_manager_task_client_claim */

void test_claim_returns_nothing_when_the_queue_is_empty(void **state) {
    wm_manager_task_client *client = *state;
    cJSON *task = NULL;

    will_return(__wrap_time, 5000);
    expect_wdb_call("task claim_manager_task {\"task_type\":\"vd_scan\",\"owner\":\"10:20:scan-0\",\"now\":5000}",
                    "ok {\"error\":0}", 0);

    // An empty queue is the common answer at every poll, not an error.
    assert_int_equal(wm_manager_task_client_claim(client, "vd_scan", "10:20:scan-0", &task), 0);
    assert_null(task);
}

void test_claim_returns_the_row(void **state) {
    wm_manager_task_client *client = *state;
    cJSON *task = NULL;

    will_return(__wrap_time, 5000);
    expect_wdb_call("task claim_manager_task {\"task_type\":\"vd_scan\",\"owner\":\"10:20:scan-0\",\"now\":5000}",
                    "ok {\"error\":0,\"task\":{\"task_id\":\"abc\",\"attempts\":2}}", 0);

    assert_int_equal(wm_manager_task_client_claim(client, "vd_scan", "10:20:scan-0", &task), 0);
    assert_non_null(task);
    assert_string_equal(cJSON_GetObjectItem(task, "task_id")->valuestring, "abc");

    cJSON_Delete(task);
}

/* wm_manager_task_client_apply */

void test_apply_writes_a_terminal_outcome(void **state) {
    wm_manager_task_client *client = *state;
    wm_manager_task_transition_t transition = {.status = "completed", .attempts = 1, .defer_count = 0};

    expect_wdb_call("task set_manager_task_result "
                    "{\"task_id\":\"abc\",\"attempts\":1,\"defer_count\":0,\"status\":\"completed\"}",
                    "ok {\"error\":0}", 0);

    assert_int_equal(
        wm_manager_task_client_apply(client, wm_manager_task_registry_get("vd_scan"), "abc", "001", &transition, NULL),
        0);
}

void test_apply_requeues_a_coalescing_type_with_its_competing_row_check(void **state) {
    wm_manager_task_client *client = *state;
    wm_manager_task_transition_t transition = {
        .status = NULL, .attempts = 2, .defer_count = 0, .next_attempt_at = 6000};

    // A coalescing type can have had its slot taken by a newer pending row while this one was
    // claimed, so the re-queue carries the agent and type the check needs.
    expect_wdb_call("task requeue_manager_task "
                    "{\"task_id\":\"abc\",\"attempts\":2,\"defer_count\":0,\"last_error\":\"timeout\","
                    "\"next_attempt_at\":6000,\"coalesce\":true,\"task_type\":\"vd_scan\",\"agent_id\":\"001\"}",
                    "ok {\"error\":0,\"result\":\"requeued\"}", 0);

    assert_int_equal(wm_manager_task_client_apply(client, wm_manager_task_registry_get("vd_scan"), "abc", "001",
                                                  &transition, "timeout"),
                     0);
}

void test_apply_omits_the_check_for_a_non_coalescing_type(void **state) {
    wm_manager_task_client *client = *state;
    wm_manager_task_transition_t transition = {
        .status = NULL, .attempts = 3, .defer_count = 0, .next_attempt_at = 6000};

    // Nothing can have taken a deletion's slot, so asking would make the row look for a
    // competitor that cannot exist.
    expect_wdb_call("task requeue_manager_task "
                    "{\"task_id\":\"abc\",\"attempts\":3,\"defer_count\":0,\"next_attempt_at\":6000}",
                    "ok {\"error\":0,\"result\":\"requeued\"}", 0);

    assert_int_equal(wm_manager_task_client_apply(client, wm_manager_task_registry_get("agent_delete_indexer"), "abc",
                                                  "001", &transition, NULL),
                     0);
}

/* wm_manager_task_client_create */

void test_create_carries_the_types_policy(void **state) {
    wm_manager_task_client *client = *state;
    char *outcome = NULL;
    char *surviving = NULL;

    will_return(__wrap_time, 1000);

    // Both policies travel with the request rather than being inferred from the type name:
    // wazuh-db has no notion of which task types exist.
    expect_wdb_call("task create_manager_task "
                    "{\"task_id\":\"abc\",\"task_type\":\"vd_scan\",\"payload\":\"{}\",\"create_time\":1000,"
                    "\"agent_id\":\"001\",\"coalesce\":true,\"max_pending\":64}",
                    "ok {\"error\":0,\"result\":\"created\",\"task_id\":\"abc\"}", 0);

    assert_int_equal(wm_manager_task_client_create(client, wm_manager_task_registry_get("vd_scan"), "abc", "001", "{}",
                                                   0, &outcome, &surviving),
                     0);
    assert_string_equal(outcome, "created");
    assert_string_equal(surviving, "abc");

    os_free(outcome);
    os_free(surviving);
}

void test_create_returns_the_surviving_id_on_a_coalesce(void **state) {
    wm_manager_task_client *client = *state;
    char *outcome = NULL;
    char *surviving = NULL;

    will_return(__wrap_time, 1000);
    expect_wdb_call("task create_manager_task "
                    "{\"task_id\":\"abc\",\"task_type\":\"vd_scan\",\"payload\":\"{}\",\"create_time\":1000,"
                    "\"agent_id\":\"001\",\"coalesce\":true,\"max_pending\":64}",
                    "ok {\"error\":0,\"result\":\"coalesced\",\"task_id\":\"older\"}", 0);

    assert_int_equal(wm_manager_task_client_create(client, wm_manager_task_registry_get("vd_scan"), "abc", "001", "{}",
                                                   0, &outcome, &surviving),
                     0);

    // Not the id that was asked for. A caller tracking its own would hold one with no row behind
    // it, and every later lookup on it would come back empty.
    assert_string_equal(outcome, "coalesced");
    assert_string_equal(surviving, "older");

    os_free(outcome);
    os_free(surviving);
}

void test_create_seeds_the_first_attempt_when_asked(void **state) {
    wm_manager_task_client *client = *state;

    will_return(__wrap_time, 1000);

    // A deletion is not due until the purge delay has elapsed, which is what keeps documents
    // written inside the index refresh interval from surviving the deletion permanently.
    expect_wdb_call("task create_manager_task "
                    "{\"task_id\":\"abc\",\"task_type\":\"agent_delete_indexer\",\"payload\":\"{}\","
                    "\"create_time\":1000,\"agent_id\":\"001\",\"next_attempt_at\":1120,\"max_pending\":20000}",
                    "ok {\"error\":0,\"result\":\"created\",\"task_id\":\"abc\"}", 0);

    assert_int_equal(wm_manager_task_client_create(client, wm_manager_task_registry_get("agent_delete_indexer"), "abc",
                                                   "001", "{}", 1120, NULL, NULL),
                     0);
}

/* wm_manager_task_client_poll and _claimed */

void test_poll_returns_the_type_list(void **state) {
    wm_manager_task_client *client = *state;
    cJSON *types = NULL;

    expect_wdb_call("task poll_manager_tasks {}",
                    "ok {\"error\":0,\"types\":[{\"task_type\":\"vd_scan\",\"next_attempt_at\":10}]}", 0);

    assert_int_equal(wm_manager_task_client_poll(client, &types), 0);
    assert_int_equal(cJSON_GetArraySize(types), 1);

    cJSON_Delete(types);
}

void test_claimed_pages_from_a_cursor(void **state) {
    wm_manager_task_client *client = *state;
    cJSON *tasks = NULL;

    expect_wdb_call("task get_claimed_manager_tasks {\"owner\":\"10:20:scan-0\",\"last_task_id\":\"abc\"}",
                    "ok {\"error\":0,\"tasks\":[]}", 0);

    assert_int_equal(wm_manager_task_client_claimed(client, "10:20:scan-0", "abc", &tasks), 0);
    assert_int_equal(cJSON_GetArraySize(tasks), 0);

    cJSON_Delete(tasks);
}

void test_claimed_without_an_owner_is_the_startup_form(void **state) {
    wm_manager_task_client *client = *state;
    cJSON *tasks = NULL;

    // Every claimed row, whoever holds it.
    expect_wdb_call("task get_claimed_manager_tasks {}", "ok {\"error\":0,\"tasks\":[]}", 0);

    assert_int_equal(wm_manager_task_client_claimed(client, NULL, NULL, &tasks), 0);

    cJSON_Delete(tasks);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_manager_task_client_call
        cmocka_unit_test_setup_teardown(test_call_sends_the_command_and_returns_the_response, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_call_supplies_an_empty_object_when_given_none, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_call_drops_the_socket_on_a_transport_failure, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_call_treats_a_database_error_as_a_failure, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_call_rejects_an_unparseable_response, test_setup, test_teardown),
        // wm_manager_task_client_claim
        cmocka_unit_test_setup_teardown(test_claim_returns_nothing_when_the_queue_is_empty, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_claim_returns_the_row, test_setup, test_teardown),
        // wm_manager_task_client_apply
        cmocka_unit_test_setup_teardown(test_apply_writes_a_terminal_outcome, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_apply_requeues_a_coalescing_type_with_its_competing_row_check, test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_apply_omits_the_check_for_a_non_coalescing_type, test_setup,
                                        test_teardown),
        // wm_manager_task_client_create
        cmocka_unit_test_setup_teardown(test_create_carries_the_types_policy, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_create_returns_the_surviving_id_on_a_coalesce, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_create_seeds_the_first_attempt_when_asked, test_setup, test_teardown),
        // wm_manager_task_client_poll and _claimed
        cmocka_unit_test_setup_teardown(test_poll_returns_the_type_list, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_claimed_pages_from_a_cursor, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_claimed_without_an_owner_is_the_startup_form, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
