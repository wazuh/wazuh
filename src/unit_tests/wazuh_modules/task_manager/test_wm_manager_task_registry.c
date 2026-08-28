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
#include "../../../wazuh_modules/src/task_manager/wm_manager_task_registry.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"

/// The documented defaults, restated here so a change to either side has to be deliberate.
static wm_manager_task_policy default_policy(void) {
    wm_manager_task_policy policy = {
        .backoff_base = 30,
        .backoff_cap = 900,
        .defer_base = 5,
        .max_attempts = 8,
        .max_defer = 48,
    };

    return policy;
}

/* The lane views are built by the registry init, so it runs once for the whole group. That also
 * exercises the happy path of init itself: a mis-specified descriptor fails here, loudly, rather
 * than becoming a row that is claimed and then silently dropped. */
static int group_setup(void **state) {
    // vd_scan timeout, delete timeout, connect timeout, in the order init reads them.
    will_return(__wrap_getDefine_Int_default, 300);
    will_return(__wrap_getDefine_Int_default, 600);
    will_return(__wrap_getDefine_Int_default, 2);

    assert_int_equal(wm_manager_task_registry_init("queue/sockets/inventory-sync-http.sock"), 0);

    return 0;
}

/* The registry as data */

void test_registry_lookup(void **state) {
    assert_non_null(wm_manager_task_registry_get("vd_scan"));
    assert_non_null(wm_manager_task_registry_get("agent_delete_indexer"));
    assert_null(wm_manager_task_registry_get("removed_in_a_later_release"));
    assert_null(wm_manager_task_registry_get(NULL));
}

void test_registry_is_iterable(void **state) {
    size_t count = wm_manager_task_registry_count();

    assert_true(count > 0);

    // Every entry has a name and a lane, and the walk terminates rather than running off the end.
    for (size_t i = 0; i < count; i++) {
        const wm_manager_task_descriptor *desc = wm_manager_task_registry_at(i);

        assert_non_null(desc);
        assert_non_null(desc->name);
        assert_true(desc->lane < WM_MANAGER_TASK_LANE_COUNT);
    }

    assert_null(wm_manager_task_registry_at(count));
}

void test_agent_delete_indexer_can_never_be_given_up_on(void **state) {
    const wm_manager_task_descriptor *desc = wm_manager_task_registry_get("agent_delete_indexer");

    // All three together, and all three necessary. Once client.keys is written the agent is gone
    // and nobody re-raises the obligation, so a terminal row here means orphaned documents with
    // only a log line behind them. Unbounded attempts alone would not do it: a 4xx maps to
    // terminal, which is just as final, which is what allow_terminal_failure closes.
    assert_int_equal(desc->max_attempts, WM_MANAGER_TASK_UNBOUNDED);
    assert_int_equal(desc->max_defer, WM_MANAGER_TASK_UNBOUNDED);
    assert_false(desc->allow_terminal_failure);

    // And never coalesced: two deletions of one agent are two obligations.
    assert_false(desc->coalesce);
}

void test_vd_scan_coalesces_and_is_bounded(void **state) {
    const wm_manager_task_descriptor *desc = wm_manager_task_registry_get("vd_scan");

    assert_true(desc->coalesce);
    assert_int_equal(desc->max_pending, 64);
    assert_true(desc->allow_terminal_failure);
}

void test_periodic_types_share_the_local_lane(void **state) {
    size_t count = 0;
    const wm_manager_task_descriptor **types = wm_manager_task_registry_lane(WM_MANAGER_TASK_LANE_LOCAL, &count);

    // Three types, one thread. Holding three threads alive so that a daily rotation cannot delay
    // a disconnect sweep by minutes is a poor trade at these cadences.
    assert_int_equal(count, 3);
    assert_non_null(types);
    assert_int_equal(wm_manager_task_lane_depth(WM_MANAGER_TASK_LANE_LOCAL), 1);

    for (size_t i = 0; i < count; i++) {
        assert_int_equal(types[i]->lane, WM_MANAGER_TASK_LANE_LOCAL);
    }
}

void test_lane_depths(void **state) {
    assert_int_equal(wm_manager_task_lane_depth(WM_MANAGER_TASK_LANE_DELETE), 4);
    assert_int_equal(wm_manager_task_lane_depth(WM_MANAGER_TASK_LANE_SCAN), 1);
    assert_int_equal(wm_manager_task_lane_depth(WM_MANAGER_TASK_LANE_COUNT), 0);

    assert_string_equal(wm_manager_task_lane_name(WM_MANAGER_TASK_LANE_DELETE), "delete");
    assert_string_equal(wm_manager_task_lane_name(WM_MANAGER_TASK_LANE_COUNT), "unknown");
}

void test_per_type_overrides_resolve_against_the_policy(void **state) {
    wm_manager_task_policy policy = default_policy();
    const wm_manager_task_descriptor *scan = wm_manager_task_registry_get("vd_scan");
    const wm_manager_task_descriptor *del = wm_manager_task_registry_get("agent_delete_indexer");

    assert_int_equal(wm_manager_task_max_attempts(scan, &policy), 8);
    assert_int_equal(wm_manager_task_max_defer(scan, &policy), 48);

    // The override wins, and it is not USE_DEFAULT, so a change to the configured default cannot
    // quietly give the deletion lane a finite budget.
    assert_int_equal(wm_manager_task_max_attempts(del, &policy), WM_MANAGER_TASK_UNBOUNDED);
    assert_int_equal(wm_manager_task_max_defer(del, &policy), WM_MANAGER_TASK_UNBOUNDED);
}

/* The ladders */

void test_backoff_ladder_matches_the_documented_arithmetic(void **state) {
    const int expected[] = {30, 60, 120, 240, 480, 900, 900};
    int total = 0;

    for (int attempts = 1; attempts <= 7; attempts++) {
        int delay = wm_manager_task_backoff(attempts, 30, 900);

        assert_int_equal(delay, expected[attempts - 1]);
        total += delay;
    }

    // Eight attempts span seven delays. State this when changing the budget: five attempts would
    // be 7.5 minutes, shorter than a routine indexer restart and short enough that the cap is
    // never reached at all.
    assert_int_equal(total, 2730);
}

void test_defer_ladder_starts_low(void **state) {
    // Starting at the cap would tax every modulesd restart with a fifteen minute delay to price a
    // boot race that resolves in seconds.
    assert_int_equal(wm_manager_task_defer_delay(1, 5, 900), 5);
    assert_int_equal(wm_manager_task_defer_delay(2, 5, 900), 10);
    assert_int_equal(wm_manager_task_defer_delay(3, 5, 900), 20);
    assert_int_equal(wm_manager_task_defer_delay(9, 5, 900), 900);
}

void test_ladders_do_not_overflow(void **state) {
    // A row that has deferred hundreds of times must sit at the cap, not wrap into a negative
    // delay that would make it permanently overdue.
    assert_int_equal(wm_manager_task_defer_delay(1000, 5, 900), 900);
    assert_int_equal(wm_manager_task_backoff(1000, 30, 900), 900);
    assert_true(wm_manager_task_backoff(64, 30, 900) > 0);
}

void test_ladders_handle_a_zero_attempt_count(void **state) {
    assert_int_equal(wm_manager_task_backoff(0, 30, 900), 30);
    assert_int_equal(wm_manager_task_defer_delay(0, 5, 900), 5);
}

/* The state machine */

void test_ok_completes(void **state) {
    wm_manager_task_policy policy = default_policy();
    wm_manager_task_transition_t transition = {0};

    wm_manager_task_apply_result(wm_manager_task_registry_get("vd_scan"), &policy,
                                 WM_MANAGER_TASK_OK, 2, 1, 1000, &transition);

    assert_string_equal(transition.status, "completed");
}

void test_retryable_consumes_an_attempt_and_resets_deferrals(void **state) {
    wm_manager_task_policy policy = default_policy();
    wm_manager_task_transition_t transition = {0};

    wm_manager_task_apply_result(wm_manager_task_registry_get("vd_scan"), &policy,
                                 WM_MANAGER_TASK_RETRYABLE, 1, 4, 1000, &transition);

    assert_null(transition.status);
    assert_int_equal(transition.attempts, 2);

    // Zeroed because the counter measures *consecutive* no-fault deferrals. Without this, both
    // the deferral ladder and the 3-and-20 log escalation are wrong after the first flap between
    // deferring and genuinely failing.
    assert_int_equal(transition.defer_count, 0);
    assert_int_equal(transition.next_attempt_at, 1000 + 60);
}

void test_timeout_is_a_real_attempt(void **state) {
    wm_manager_task_policy policy = default_policy();
    wm_manager_task_transition_t transition = {0};

    wm_manager_task_apply_result(wm_manager_task_registry_get("vd_scan"), &policy,
                                 WM_MANAGER_TASK_TIMEOUT, 0, 2, 1000, &transition);

    assert_null(transition.status);
    assert_int_equal(transition.attempts, 1);
    assert_int_equal(transition.defer_count, 0);
    assert_int_equal(transition.next_attempt_at, 1000 + 30);
}

void test_attempt_budget_exhausts_into_dead_letter(void **state) {
    wm_manager_task_policy policy = default_policy();
    wm_manager_task_transition_t transition = {0};

    wm_manager_task_apply_result(wm_manager_task_registry_get("vd_scan"), &policy,
                                 WM_MANAGER_TASK_RETRYABLE, 7, 0, 1000, &transition);

    assert_string_equal(transition.status, "dead_letter");
    assert_int_equal(transition.attempts, 8);
}

void test_terminal_does_not_consume_budget(void **state) {
    wm_manager_task_policy policy = default_policy();
    wm_manager_task_transition_t transition = {0};

    wm_manager_task_apply_result(wm_manager_task_registry_get("vd_scan"), &policy,
                                 WM_MANAGER_TASK_TERMINAL, 3, 0, 1000, &transition);

    // The row is not being given up on after trying; it is being declared impossible.
    assert_string_equal(transition.status, "failed");
    assert_int_equal(transition.attempts, 3);
}

void test_not_ready_defers_without_costing_an_attempt(void **state) {
    wm_manager_task_policy policy = default_policy();
    wm_manager_task_transition_t transition = {0};

    wm_manager_task_apply_result(wm_manager_task_registry_get("vd_scan"), &policy,
                                 WM_MANAGER_TASK_NOT_READY, 3, 1, 1000, &transition);

    assert_null(transition.status);
    assert_int_equal(transition.attempts, 3);
    assert_int_equal(transition.defer_count, 2);
    assert_int_equal(transition.next_attempt_at, 1000 + 10);
}

void test_busy_defers_like_not_ready(void **state) {
    wm_manager_task_policy policy = default_policy();
    wm_manager_task_transition_t transition = {0};

    wm_manager_task_apply_result(wm_manager_task_registry_get("vd_scan"), &policy,
                                 WM_MANAGER_TASK_BUSY, 3, 0, 1000, &transition);

    assert_null(transition.status);
    assert_int_equal(transition.attempts, 3);
    assert_int_equal(transition.defer_count, 1);
}

void test_deferral_terminates(void **state) {
    wm_manager_task_policy policy = default_policy();
    wm_manager_task_transition_t transition = {0};

    wm_manager_task_apply_result(wm_manager_task_registry_get("vd_scan"), &policy,
                                 WM_MANAGER_TASK_NOT_READY, 0, 47, 1000, &transition);

    // Without a deferral ceiling a consumer that never appears leaves rows deferring at the cap
    // forever, coalescing folds every new request into them, admission fills permanently and
    // nothing lands in dead_letter for anyone to find. Invisible is worse than terminal.
    assert_string_equal(transition.status, "dead_letter");
    assert_int_equal(transition.defer_count, 48);
}

void test_unbounded_type_never_dead_letters(void **state) {
    wm_manager_task_policy policy = default_policy();
    wm_manager_task_transition_t transition = {0};
    const wm_manager_task_descriptor *desc = wm_manager_task_registry_get("agent_delete_indexer");

    wm_manager_task_apply_result(desc, &policy, WM_MANAGER_TASK_RETRYABLE, 5000, 0, 1000, &transition);
    assert_null(transition.status);
    assert_int_equal(transition.attempts, 5001);

    wm_manager_task_apply_result(desc, &policy, WM_MANAGER_TASK_NOT_READY, 0, 5000, 1000, &transition);
    assert_null(transition.status);
    assert_int_equal(transition.defer_count, 5001);
}

void test_incomplete_is_neither_success_nor_failure(void **state) {
    wm_manager_task_policy policy = default_policy();
    wm_manager_task_transition_t transition = {0};

    wm_manager_task_apply_result(wm_manager_task_registry_get("agent_delete_old"), &policy,
                                 WM_MANAGER_TASK_INCOMPLETE, 7, 3, 1000, &transition);

    // Completing would end the row with the sweep half done; consuming an attempt would
    // dead-letter a fleet that needs more batches than the budget allows. It runs again at once.
    assert_null(transition.status);
    assert_int_equal(transition.attempts, 7);
    assert_int_equal(transition.defer_count, 0);
    assert_int_equal(transition.next_attempt_at, 1000);
}

void test_transition_tolerates_null_arguments(void **state) {
    wm_manager_task_policy policy = default_policy();
    wm_manager_task_transition_t transition = {.status = "untouched"};

    wm_manager_task_apply_result(NULL, &policy, WM_MANAGER_TASK_OK, 0, 0, 0, &transition);
    assert_string_equal(transition.status, "untouched");

    wm_manager_task_apply_result(wm_manager_task_registry_get("vd_scan"), NULL,
                                 WM_MANAGER_TASK_OK, 0, 0, 0, &transition);
    assert_string_equal(transition.status, "untouched");
}

/* Classifying a consumer's answer */

void test_success_is_ok(void **state) {
    uhttp_result_t result = {0};
    char error[256];

    assert_int_equal(wm_manager_task_classify_response(0, &result, NULL, 0, true, error, sizeof(error)),
                     WM_MANAGER_TASK_OK);
}

void test_connect_refused_is_not_ready(void **state) {
    uhttp_result_t result = {.curl_code = 7};
    char error[256];

    // A consumer that has not bound its socket must not burn the retry budget: this is the boot
    // race, and every modulesd restart goes through it.
    assert_int_equal(wm_manager_task_classify_response(-7, &result, NULL, 0, true, error, sizeof(error)),
                     WM_MANAGER_TASK_NOT_READY);
}

void test_curl_timeout_is_a_timeout(void **state) {
    uhttp_result_t result = {.curl_code = 28};
    char error[256];

    assert_int_equal(wm_manager_task_classify_response(-28, &result, NULL, 0, true, error, sizeof(error)),
                     WM_MANAGER_TASK_TIMEOUT);
}

void test_other_transport_errors_are_retryable(void **state) {
    uhttp_result_t result = {.curl_code = 56};
    char error[256];

    // The peer died mid-request: RECV_ERROR, SEND_ERROR or GOT_NOTHING. Nothing DNS, TLS or
    // proxy shaped is reachable over a Unix socket.
    assert_int_equal(wm_manager_task_classify_response(-56, &result, NULL, 0, true, error, sizeof(error)),
                     WM_MANAGER_TASK_RETRYABLE);
}

void test_never_sent_sentinel_is_a_dispatcher_bug(void **state) {
    uhttp_result_t result = {0};
    char error[256];

    // -1 with the result struct untouched means the request never left this process: a NULL
    // client, NULL data with a positive length, a failed setopt. It is not a consumer that is
    // down, and treating it as one would defer forever against a local bug. Telling it apart
    // from -CURLE_UNSUPPORTED_PROTOCOL is safe only because the URL and socket are constants.
    assert_int_equal(wm_manager_task_classify_response(-1, &result, NULL, 0, true, error, sizeof(error)),
                     WM_MANAGER_TASK_TERMINAL);
    assert_non_null(strstr(error, "never sent"));
}

void test_409_is_busy(void **state) {
    uhttp_result_t result = {.http_status = 409};
    const char *body = "{\"error\":\"scan_in_progress\",\"retryable\":true}";
    char error[256];

    assert_int_equal(
        wm_manager_task_classify_response(409, &result, body, strlen(body), true, error, sizeof(error)),
        WM_MANAGER_TASK_BUSY);
    assert_non_null(strstr(error, "scan_in_progress"));
}

void test_409_with_a_truncated_body_is_still_busy(void **state) {
    uhttp_result_t result = {.http_status = 409};
    const char *body = "{\"error\":\"scan_in_pr";
    char error[256];

    // The response buffer is caller-owned and truncates silently. Falling through to the 4xx rule
    // here would, for a type that must never fail, produce exactly the orphan that
    // allow_terminal_failure exists to prevent.
    assert_int_equal(
        wm_manager_task_classify_response(409, &result, body, strlen(body), true, error, sizeof(error)),
        WM_MANAGER_TASK_BUSY);
}

void test_4xx_is_terminal_when_allowed(void **state) {
    uhttp_result_t result = {.http_status = 400};
    const char *body = "{\"error\":\"bad_agent_id\"}";
    char error[256];

    assert_int_equal(
        wm_manager_task_classify_response(400, &result, body, strlen(body), true, error, sizeof(error)),
        WM_MANAGER_TASK_TERMINAL);
}

void test_4xx_requeues_when_terminal_failure_is_forbidden(void **state) {
    uhttp_result_t result = {.http_status = 400};
    const char *body = "{\"error\":\"bad_agent_id\"}";
    char error[256];

    // For a deletion, a 4xx is a dispatcher bug or a transient misconfiguration. Neither is a
    // reason to abandon an obligation nobody will raise again.
    assert_int_equal(
        wm_manager_task_classify_response(400, &result, body, strlen(body), false, error, sizeof(error)),
        WM_MANAGER_TASK_RETRYABLE);
}

void test_408_and_429_are_retryable_not_terminal(void **state) {
    uhttp_result_t result = {.http_status = 429};
    char error[256];

    assert_int_equal(wm_manager_task_classify_response(408, &result, NULL, 0, true, error, sizeof(error)),
                     WM_MANAGER_TASK_RETRYABLE);
    assert_int_equal(wm_manager_task_classify_response(429, &result, NULL, 0, true, error, sizeof(error)),
                     WM_MANAGER_TASK_RETRYABLE);
}

void test_5xx_is_retryable(void **state) {
    uhttp_result_t result = {.http_status = 503};
    char error[256];

    assert_int_equal(wm_manager_task_classify_response(503, &result, NULL, 0, true, error, sizeof(error)),
                     WM_MANAGER_TASK_RETRYABLE);
}

void test_body_can_override_a_terminal_status(void **state) {
    uhttp_result_t result = {.http_status = 400};
    const char *body = "{\"error\":\"feed_not_loaded\",\"retryable\":true}";
    char error[256];

    assert_int_equal(
        wm_manager_task_classify_response(400, &result, body, strlen(body), true, error, sizeof(error)),
        WM_MANAGER_TASK_RETRYABLE);
}

void test_routed_types_carry_resolved_timeouts_and_socket(void **state) {
    const wm_manager_task_descriptor *scan = wm_manager_task_registry_get("vd_scan");
    const wm_manager_task_descriptor *del = wm_manager_task_registry_get("agent_delete_indexer");

    assert_string_equal(scan->socket_path, "queue/sockets/inventory-sync-http.sock");
    assert_string_equal(del->socket_path, "queue/sockets/inventory-sync-http.sock");

    // Neither may be left at zero. libcurl reads a zero request timeout as "wait forever" and a
    // zero connect timeout as its own 300 second default, so the same value would mean two
    // different and equally wrong things.
    assert_int_equal(scan->request_timeout_ms, 300000);
    assert_int_equal(del->request_timeout_ms, 600000);
    assert_int_equal(scan->connect_timeout_ms, 2000);
    assert_int_equal(del->connect_timeout_ms, 2000);
}

void test_local_types_have_no_socket(void **state) {
    const wm_manager_task_descriptor *desc = wm_manager_task_registry_get("log_rotate_daily");

    assert_null(desc->path);
    assert_int_equal(desc->socket_path[0], '\0');
}

void test_registry_init_rejects_unordered_timeouts(void **state) {
    // A scan can park a deletion behind it on the consumer's per-agent queue. With equal
    // deadlines the deletion expires while parked and re-queues for the full backoff over work
    // that was never its own fault, so the ordering is asserted rather than left as a comment.
    will_return(__wrap_getDefine_Int_default, 600);
    will_return(__wrap_getDefine_Int_default, 600);
    will_return(__wrap_getDefine_Int_default, 2);

    // Literal, not WM_TASK_MANAGER_LOGTAG: the module's objects are built with
    // -DARGV0="wazuh-manager-modulesd" and this translation unit is not, so the macro would
    // expand here to the fallback in wmodules_def.h.
    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg,
                  "manager_task_delete_timeout (600) must be greater than manager_task_vd_scan_timeout (600).");

    assert_int_equal(wm_manager_task_registry_init("queue/sockets/inventory-sync-http.sock"), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // The registry as data
        cmocka_unit_test(test_registry_lookup),
        cmocka_unit_test(test_registry_is_iterable),
        cmocka_unit_test(test_agent_delete_indexer_can_never_be_given_up_on),
        cmocka_unit_test(test_vd_scan_coalesces_and_is_bounded),
        cmocka_unit_test(test_periodic_types_share_the_local_lane),
        cmocka_unit_test(test_lane_depths),
        cmocka_unit_test(test_per_type_overrides_resolve_against_the_policy),
        cmocka_unit_test(test_routed_types_carry_resolved_timeouts_and_socket),
        cmocka_unit_test(test_local_types_have_no_socket),
        // The ladders
        cmocka_unit_test(test_backoff_ladder_matches_the_documented_arithmetic),
        cmocka_unit_test(test_defer_ladder_starts_low),
        cmocka_unit_test(test_ladders_do_not_overflow),
        cmocka_unit_test(test_ladders_handle_a_zero_attempt_count),
        // The state machine
        cmocka_unit_test(test_ok_completes),
        cmocka_unit_test(test_retryable_consumes_an_attempt_and_resets_deferrals),
        cmocka_unit_test(test_timeout_is_a_real_attempt),
        cmocka_unit_test(test_attempt_budget_exhausts_into_dead_letter),
        cmocka_unit_test(test_terminal_does_not_consume_budget),
        cmocka_unit_test(test_not_ready_defers_without_costing_an_attempt),
        cmocka_unit_test(test_busy_defers_like_not_ready),
        cmocka_unit_test(test_deferral_terminates),
        cmocka_unit_test(test_unbounded_type_never_dead_letters),
        cmocka_unit_test(test_incomplete_is_neither_success_nor_failure),
        cmocka_unit_test(test_transition_tolerates_null_arguments),
        // Classifying a consumer's answer
        cmocka_unit_test(test_success_is_ok),
        cmocka_unit_test(test_connect_refused_is_not_ready),
        cmocka_unit_test(test_curl_timeout_is_a_timeout),
        cmocka_unit_test(test_other_transport_errors_are_retryable),
        cmocka_unit_test(test_never_sent_sentinel_is_a_dispatcher_bug),
        cmocka_unit_test(test_409_is_busy),
        cmocka_unit_test(test_409_with_a_truncated_body_is_still_busy),
        cmocka_unit_test(test_4xx_is_terminal_when_allowed),
        cmocka_unit_test(test_4xx_requeues_when_terminal_failure_is_forbidden),
        cmocka_unit_test(test_408_and_429_are_retryable_not_terminal),
        cmocka_unit_test(test_5xx_is_retryable),
        cmocka_unit_test(test_body_can_override_a_terminal_status),
        // Last, because it is the only test that calls init again.
        cmocka_unit_test(test_registry_init_rejects_unordered_timeouts),
    };

    return cmocka_run_group_tests(tests, group_setup, NULL);
}
