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

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/http_op_wrappers.h"

#include "shared.h"
#include "manager_task_op.h"

/* The producer side of the manager task queue: the client authd and the vulnerability scanner use
 * to record work that must outlive the process that asked for it.
 *
 * Two things here are contracts rather than implementation details, and both are covered below:
 *
 *   - The THREE ID RECIPES. They are how a creator that can legitimately run twice for one logical
 *     event stays idempotent -- authd's deletion journal is replayed at every start, and a
 *     schedule's spawn loop has no transaction across "insert the row" and "advance next_run_at".
 *     A refactor that still hashed SOMETHING consistently would keep every round-trip test green
 *     and silently break both, so these are asserted against golden vectors, not round trips.
 *
 *   - The REQUEST the client puts on the wire. It is the only place the url is built, and libcurl
 *     requires an absolute one; a bare path fails the transfer with no HTTP status, which this
 *     file's own error handling then reports as an unreachable task manager. That failure mode is
 *     indistinguishable from an outage in a log, so it is asserted directly.
 */

/// A non-NULL handle for uhttp_client_new() to hand back. Never dereferenced: every uhttp_* entry
/// point is wrapped, so the value only has to be distinguishable from NULL.
static uhttp_client_t *const TEST_CLIENT = (uhttp_client_t *)0xC0FFEE;

static int setup_group(void **state) {
    (void) state;
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    (void) state;
    test_mode = 0;
    return 0;
}

/**
 * @brief Queue one whole round trip.
 *
 * @param body What the task manager answers with, or NULL for no body at all.
 * @param retval uhttp_post()'s return; 0 is success.
 * @param http_status The status to report, or 0 for "the request never got an answer".
 */
static void expect_round_trip(const char *body, int retval, long http_status) {
    will_return(__wrap_uhttp_client_new, TEST_CLIENT);
    will_return(__wrap_uhttp_post, body);
    will_return(__wrap_uhttp_post, retval);
    will_return(__wrap_uhttp_post, http_status);
}

/// @brief A minimally valid creation request, so each test varies only what it is about.
static manager_task_request_t sample_request(void) {
    manager_task_request_t request = {0};

    request.task_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    request.task_type = MANAGER_TASK_TYPE_AGENT_DELETE;
    request.agent_id = "001";
    request.payload = "{\"agent_id\":\"001\"}";
    request.create_time = 1700000000;

    return request;
}

/* ---------------------------------------------------------------------------------------------
 * Task id recipes
 * --------------------------------------------------------------------------------------------- */

/* Golden vectors, not round trips: see the file header. Each is SHA-256 of the exact string this
 * client is contracted to hash, and the digests below were computed independently of the code. */

void test_id_agent_delete_matches_its_golden_vector(void **state) {
    (void) state;

    // SHA-256("mt:del:001:42")
    char *task_id = manager_task_id_agent_delete("001", 42);

    assert_non_null(task_id);
    assert_string_equal(task_id, "ae28ee6efe3dbade0a4740642f748125f92cc5fd62827ce074d4a273df0401dd");

    os_free(task_id);
}

void test_id_agent_delete_is_keyed_on_the_sequence_not_only_the_agent(void **state) {
    (void) state;

    // Two genuine deletions of one agent are two obligations, and must not share an id -- if they
    // did, the second would be swallowed by the first's primary-key collision and never applied.
    char *first = manager_task_id_agent_delete("001", 42);
    char *second = manager_task_id_agent_delete("001", 43);

    assert_non_null(first);
    assert_non_null(second);
    assert_string_not_equal(first, second);

    os_free(first);
    os_free(second);
}

void test_id_agent_delete_repeats_for_one_journal_line(void **state) {
    (void) state;

    // The whole of the journal's replay safety: authd's writer and its startup reconciliation both
    // create the same line, and only a stable id makes the second one a no-op.
    char *first = manager_task_id_agent_delete("001", 42);
    char *second = manager_task_id_agent_delete("001", 42);

    assert_string_equal(first, second);

    os_free(first);
    os_free(second);
}

void test_id_schedule_matches_the_task_managers_own_vector(void **state) {
    (void) state;

    // SHA-256("mt:sched:agent_delete_old:1700000000").
    //
    // The SAME vector the Task Manager's own C++ suite asserts for taskId::forScheduledRun(), which
    // is the point of duplicating it here: a scheduled run is spawned by the module and can also be
    // reasoned about by this client, and the two implementations agreeing is what makes the
    // primary-key collision a no-op instead of a duplicate run.
    char *task_id = manager_task_id_schedule("agent_delete_old", 1700000000);

    assert_non_null(task_id);
    assert_string_equal(task_id, "6b74b099b261fb4d2bc2f56a578a8d0bd8b74034a27f686824403ba14c1ad623");

    os_free(task_id);
}

void test_id_schedule_is_keyed_on_the_slot(void **state) {
    (void) state;

    // Two runs of one schedule are two different slots; two attempts at one slot are one run.
    char *first = manager_task_id_schedule("agent_delete_old", 1700000000);
    char *second = manager_task_id_schedule("agent_delete_old", 1700086400);

    assert_string_not_equal(first, second);

    os_free(first);
    os_free(second);
}

void test_id_random_is_64_hex_and_never_repeats(void **state) {
    (void) state;

    char *first = manager_task_id_random("scan");
    char *second = manager_task_id_random("scan");

    assert_non_null(first);
    assert_non_null(second);

    // Same width as every other task id, whatever produced it.
    assert_int_equal(strlen(first), 64);
    assert_int_equal(strspn(first, "0123456789abcdef"), 64);

    // Random on purpose: two scan requests for one agent are two different things, and
    // deduplication is the queue's job through the type's coalesce flag, not the id's.
    assert_string_not_equal(first, second);

    os_free(first);
    os_free(second);
}

void test_id_helpers_reject_empty_and_null_arguments(void **state) {
    (void) state;

    assert_null(manager_task_id_agent_delete(NULL, 1));
    assert_null(manager_task_id_agent_delete("", 1));
    assert_null(manager_task_id_schedule(NULL, 1));
    assert_null(manager_task_id_schedule("", 1));
    assert_null(manager_task_id_random(NULL));
    assert_null(manager_task_id_random(""));
}

/* ---------------------------------------------------------------------------------------------
 * What goes on the wire
 * --------------------------------------------------------------------------------------------- */

void test_create_posts_an_absolute_url_to_the_task_socket(void **state) {
    (void) state;

    manager_task_request_t request = sample_request();

    expect_round_trip("{\"result\":\"created\"}", 0, 200);

    assert_int_equal(manager_task_create(&request, 5, NULL), MANAGER_TASK_CREATED);

    const uhttp_captured_options_t *sent = uhttp_wrappers_last_options();

    // THE regression this test exists for. libcurl parses the url before it consults
    // CURLOPT_UNIX_SOCKET_PATH and rejects a bare path with CURLE_URL_MALFORMAT and no HTTP status
    // -- which manager_task_request() reports as "did not reach the task manager", so the mistake
    // reads as an outage and every creation fails silently.
    assert_string_equal(sent->url, "http://localhost/v1/manager-tasks");
    assert_string_equal(sent->unix_socket_path, "queue/sockets/task.sock");
    assert_string_equal(sent->content_type, "application/json");

    // The caller's timeout bounds the whole round trip; the connect deadline is the client's own,
    // because reaching a socket on this host either works at once or is not going to.
    assert_int_equal(sent->timeout_ms, 5000);
    assert_int_equal(sent->connect_timeout_ms, 2000);
}

void test_count_and_agent_status_use_their_own_routes(void **state) {
    (void) state;

    expect_round_trip("{\"count\":3}", 0, 200);
    assert_int_equal(manager_task_count("agent_delete_indexer", "pending", 5), 3);
    assert_string_equal(uhttp_wrappers_last_options()->url, "http://localhost/v1/manager-tasks/count");

    expect_round_trip("{}", 0, 200);
    assert_int_equal(manager_task_agent_status("001", "agent_delete_indexer", 5),
                     MANAGER_TASK_STATUS_NONE);
    assert_string_equal(uhttp_wrappers_last_options()->url, "http://localhost/v1/manager-tasks/by-agent");
}

void test_create_omits_the_optional_fields_it_was_not_given(void **state) {
    (void) state;

    manager_task_request_t request = sample_request();
    request.agent_id = NULL;
    request.next_attempt_at = 0;
    request.max_pending = 0;

    expect_round_trip("{\"result\":\"created\"}", 0, 200);

    assert_int_equal(manager_task_create(&request, 0, NULL), MANAGER_TASK_CREATED);

    // A zero timeout is "no deadline", which libcurl also spells zero -- so it must be passed
    // through rather than turned into 0 ms, which libcurl would read the same way but which a
    // future refactor could easily convert into an instant expiry.
    assert_int_equal(uhttp_wrappers_last_options()->timeout_ms, 0);
}

/* ---------------------------------------------------------------------------------------------
 * Creation outcomes
 * --------------------------------------------------------------------------------------------- */

void test_create_maps_every_result_the_task_manager_can_answer(void **state) {
    (void) state;

    const struct {
        const char *body;
        int expected;
    } cases[] = {
        {"{\"result\":\"created\"}", MANAGER_TASK_CREATED},
        {"{\"result\":\"coalesced\"}", MANAGER_TASK_COALESCED},
        {"{\"result\":\"collided\"}", MANAGER_TASK_COLLIDED},
        {"{\"result\":\"queue_full\"}", MANAGER_TASK_QUEUE_FULL},
        // A result this client does not know is NOT success: every value except FAILED means the
        // row exists, so guessing one would tell authd to drop a journal line for a row that may
        // never have been written.
        {"{\"result\":\"something_new\"}", MANAGER_TASK_CREATE_FAILED},
        // Parseable, but says nothing about what happened.
        {"{}", MANAGER_TASK_CREATE_FAILED},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        manager_task_request_t request = sample_request();

        expect_round_trip(cases[i].body, 0, 200);

        assert_int_equal(manager_task_create(&request, 5, NULL), cases[i].expected);
    }
}

void test_create_returns_the_surviving_id_which_a_coalesce_changes(void **state) {
    (void) state;

    manager_task_request_t request = sample_request();
    char *surviving = NULL;

    expect_round_trip("{\"result\":\"coalesced\",\"task_id\":\"aaaa\"}", 0, 200);

    assert_int_equal(manager_task_create(&request, 5, &surviving), MANAGER_TASK_COALESCED);

    // The id of the row that actually exists, which on a coalesce is not the one that was asked
    // for -- a caller that kept its own id would hold one with no row behind it.
    assert_non_null(surviving);
    assert_string_equal(surviving, "aaaa");

    os_free(surviving);
}

void test_create_leaves_the_surviving_id_null_when_it_failed(void **state) {
    (void) state;

    manager_task_request_t request = sample_request();
    char *surviving = (char *)0xdeadbeef;

    expect_round_trip(NULL, -1, 0);
    expect_any(__wrap__mdebug1, formatted_msg);

    assert_int_equal(manager_task_create(&request, 5, &surviving), MANAGER_TASK_CREATE_FAILED);

    // Cleared on entry, so a caller cannot read a stale pointer from a previous call after a
    // failure -- and cannot free one either.
    assert_null(surviving);
}

void test_create_refuses_an_incomplete_request_without_touching_the_socket(void **state) {
    (void) state;

    manager_task_request_t request = sample_request();

    // No round trip is queued: reaching the client here would exhaust an empty mock queue and fail
    // the test, which is exactly the assertion.
    assert_int_equal(manager_task_create(NULL, 5, NULL), MANAGER_TASK_CREATE_FAILED);

    request = sample_request();
    request.task_id = NULL;
    assert_int_equal(manager_task_create(&request, 5, NULL), MANAGER_TASK_CREATE_FAILED);

    request = sample_request();
    request.task_type = NULL;
    assert_int_equal(manager_task_create(&request, 5, NULL), MANAGER_TASK_CREATE_FAILED);

    request = sample_request();
    request.payload = NULL;
    assert_int_equal(manager_task_create(&request, 5, NULL), MANAGER_TASK_CREATE_FAILED);
}

/* ---------------------------------------------------------------------------------------------
 * Transport failures
 * --------------------------------------------------------------------------------------------- */

void test_a_refusal_is_read_from_its_body_even_though_it_is_not_a_2xx(void **state) {
    (void) state;

    manager_task_request_t request = sample_request();

    // 503 with a body that names the cause. Discarding it here would flatten "the queue is full"
    // into "the request failed", which is the difference between backing off and giving up: authd
    // keeps the journal line on a full queue and retries it, and abandons the pass rather than
    // hammering a queue that will not empty between two rows.
    expect_round_trip("{\"result\":\"queue_full\"}", -1, 503);

    assert_int_equal(manager_task_create(&request, 5, NULL), MANAGER_TASK_QUEUE_FULL);
}

void test_an_unanswered_request_is_a_failure_not_a_refusal(void **state) {
    (void) state;

    manager_task_request_t request = sample_request();

    // No status at all: the request never reached a server.
    expect_round_trip(NULL, -1, 0);
    expect_string(__wrap__mdebug1, formatted_msg,
                  "Manager task request '/v1/manager-tasks' did not reach the task manager.");

    assert_int_equal(manager_task_create(&request, 5, NULL), MANAGER_TASK_CREATE_FAILED);
}

void test_a_body_that_is_not_json_is_a_failure(void **state) {
    (void) state;

    manager_task_request_t request = sample_request();

    expect_round_trip("not json at all", 0, 200);
    expect_string(__wrap__mdebug1, formatted_msg,
                  "Manager task request '/v1/manager-tasks' answered something that is not JSON.");

    assert_int_equal(manager_task_create(&request, 5, NULL), MANAGER_TASK_CREATE_FAILED);
}

void test_a_client_that_cannot_be_built_is_a_failure(void **state) {
    (void) state;

    manager_task_request_t request = sample_request();

    will_return(__wrap_uhttp_client_new, NULL);

    assert_int_equal(manager_task_create(&request, 5, NULL), MANAGER_TASK_CREATE_FAILED);
}

/* ---------------------------------------------------------------------------------------------
 * Counting
 * --------------------------------------------------------------------------------------------- */

void test_count_returns_what_the_task_manager_reported(void **state) {
    (void) state;

    expect_round_trip("{\"count\":17}", 0, 200);

    assert_int_equal(manager_task_count("agent_delete_indexer", "pending", 5), 17);
}

void test_count_answers_minus_one_when_it_could_not_be_measured(void **state) {
    (void) state;

    // -1 is NOT zero, and the distinction is load-bearing: a caller that uses this as a bound must
    // keep its previous value rather than concluding the queue is empty and admitting more work.
    expect_round_trip(NULL, -1, 0);
    expect_any(__wrap__mdebug1, formatted_msg);
    assert_int_equal(manager_task_count("agent_delete_indexer", "pending", 5), -1);

    // Answered, parseable, but without the field.
    expect_round_trip("{}", 0, 200);
    assert_int_equal(manager_task_count("agent_delete_indexer", "pending", 5), -1);

    // Refused outright, without ever reaching the socket.
    assert_int_equal(manager_task_count(NULL, "pending", 5), -1);
    assert_int_equal(manager_task_count("agent_delete_indexer", NULL, 5), -1);
}

/* ---------------------------------------------------------------------------------------------
 * What an agent still owes
 * --------------------------------------------------------------------------------------------- */

void test_agent_status_reads_pending_and_claimed_as_outstanding(void **state) {
    (void) state;

    expect_round_trip("{\"task\":{\"status\":\"pending\"}}", 0, 200);
    assert_int_equal(manager_task_agent_status("001", MANAGER_TASK_TYPE_AGENT_DELETE, 5),
                     MANAGER_TASK_STATUS_OUTSTANDING);

    expect_round_trip("{\"task\":{\"status\":\"claimed\"}}", 0, 200);
    assert_int_equal(manager_task_agent_status("001", MANAGER_TASK_TYPE_AGENT_DELETE, 5),
                     MANAGER_TASK_STATUS_OUTSTANDING);
}

void test_agent_status_reads_anything_else_as_terminal(void **state) {
    (void) state;

    const char *terminal[] = {"completed", "failed", "dead_letter", "superseded"};

    for (size_t i = 0; i < sizeof(terminal) / sizeof(terminal[0]); i++) {
        char body[128];
        snprintf(body, sizeof(body), "{\"task\":{\"status\":\"%s\"}}", terminal[i]);

        expect_round_trip(body, 0, 200);
        assert_int_equal(manager_task_agent_status("001", MANAGER_TASK_TYPE_AGENT_DELETE, 5),
                         MANAGER_TASK_STATUS_TERMINAL);
    }
}

void test_agent_status_answers_none_when_there_is_no_row(void **state) {
    (void) state;

    // Reachable without any failure: an id enters a caller's pending set before the row is created,
    // and the creation can legitimately never happen. It must not look like an error.
    expect_round_trip("{}", 0, 200);

    assert_int_equal(manager_task_agent_status("001", MANAGER_TASK_TYPE_AGENT_DELETE, 5),
                     MANAGER_TASK_STATUS_NONE);
}

void test_agent_status_fails_safe_on_anything_that_is_not_a_200(void **state) {
    (void) state;

    // The one place a non-2xx body is deliberately NOT trusted. A caller uses this to decide
    // whether an agent id may be reused, so concluding "nothing outstanding" from an error would
    // hand out an id whose previous owner's documents are still being deleted.
    expect_round_trip("{\"error\":\"parsing_error\"}", -1, 400);

    assert_int_equal(manager_task_agent_status("001", MANAGER_TASK_TYPE_AGENT_DELETE, 5),
                     MANAGER_TASK_STATUS_FAILED);
}

void test_agent_status_refuses_missing_arguments(void **state) {
    (void) state;

    assert_int_equal(manager_task_agent_status(NULL, MANAGER_TASK_TYPE_AGENT_DELETE, 5),
                     MANAGER_TASK_STATUS_FAILED);
    assert_int_equal(manager_task_agent_status("001", NULL, 5), MANAGER_TASK_STATUS_FAILED);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Task id recipes
        cmocka_unit_test(test_id_agent_delete_matches_its_golden_vector),
        cmocka_unit_test(test_id_agent_delete_is_keyed_on_the_sequence_not_only_the_agent),
        cmocka_unit_test(test_id_agent_delete_repeats_for_one_journal_line),
        cmocka_unit_test(test_id_schedule_matches_the_task_managers_own_vector),
        cmocka_unit_test(test_id_schedule_is_keyed_on_the_slot),
        cmocka_unit_test(test_id_random_is_64_hex_and_never_repeats),
        cmocka_unit_test(test_id_helpers_reject_empty_and_null_arguments),
        // What goes on the wire
        cmocka_unit_test(test_create_posts_an_absolute_url_to_the_task_socket),
        cmocka_unit_test(test_count_and_agent_status_use_their_own_routes),
        cmocka_unit_test(test_create_omits_the_optional_fields_it_was_not_given),
        // Creation outcomes
        cmocka_unit_test(test_create_maps_every_result_the_task_manager_can_answer),
        cmocka_unit_test(test_create_returns_the_surviving_id_which_a_coalesce_changes),
        cmocka_unit_test(test_create_leaves_the_surviving_id_null_when_it_failed),
        cmocka_unit_test(test_create_refuses_an_incomplete_request_without_touching_the_socket),
        // Transport failures
        cmocka_unit_test(test_a_refusal_is_read_from_its_body_even_though_it_is_not_a_2xx),
        cmocka_unit_test(test_an_unanswered_request_is_a_failure_not_a_refusal),
        cmocka_unit_test(test_a_body_that_is_not_json_is_a_failure),
        cmocka_unit_test(test_a_client_that_cannot_be_built_is_a_failure),
        // Counting
        cmocka_unit_test(test_count_returns_what_the_task_manager_reported),
        cmocka_unit_test(test_count_answers_minus_one_when_it_could_not_be_measured),
        // What an agent still owes
        cmocka_unit_test(test_agent_status_reads_pending_and_claimed_as_outstanding),
        cmocka_unit_test(test_agent_status_reads_anything_else_as_terminal),
        cmocka_unit_test(test_agent_status_answers_none_when_there_is_no_row),
        cmocka_unit_test(test_agent_status_fails_safe_on_anything_that_is_not_a_200),
        cmocka_unit_test(test_agent_status_refuses_missing_arguments),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
