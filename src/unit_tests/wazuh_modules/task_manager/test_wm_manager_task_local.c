/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Covers the local handlers' decisions. Their bodies are sockets and the filesystem -- a wazuh-db
 * round trip per agent, an authd connection per removal, a rename and a gzip -- which is
 * integration territory; what is testable here is every rule those bodies consult.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "wmodules.h"
#include "../../../wazuh_modules/src/task_manager/wm_manager_task_local.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"

/* The retention window */

void test_a_recently_seen_agent_is_not_expired(void **state) {
    // Disconnected 900 s, retention 60 minutes: the window is 4500 s, and this agent was seen
    // 1000 s ago.
    assert_false(wm_manager_task_delete_old_expired(9000, 10000, 900, 60));
}

void test_the_window_is_the_disconnection_time_plus_the_retention(void **state) {
    // Not the retention alone. An agent becomes eligible one whole retention period AFTER it was
    // marked disconnected, which is how monitord read the same two options.
    assert_false(wm_manager_task_delete_old_expired(10000 - 4500, 10000, 900, 60));
    assert_true(wm_manager_task_delete_old_expired(10000 - 4501, 10000, 900, 60));
}

void test_the_boundary_is_exclusive(void **state) {
    // Exactly on the boundary is not yet expired, so an agent is never deleted a second early.
    assert_false(wm_manager_task_delete_old_expired(5500, 10000, 900, 60));
}

void test_a_disabled_retention_expires_nothing(void **state) {
    // The handler already returns early on this, but the predicate must agree: a zero window would
    // otherwise read as "everything disconnected is eligible", which is the whole fleet.
    assert_false(wm_manager_task_delete_old_expired(0, 10000, 900, 0));
    assert_false(wm_manager_task_delete_old_expired(0, 10000, 900, -1));
}

void test_a_very_old_keepalive_does_not_overflow(void **state) {
    // The retention bound is 9600 minutes. Multiplied in int arithmetic against a seconds-since-
    // epoch timestamp this is where a 32-bit intermediate would wrap; the calculation is done in
    // long long for that reason.
    assert_true(wm_manager_task_delete_old_expired(0, 4000000000LL, 900, 9600));
    assert_false(wm_manager_task_delete_old_expired(4000000000LL, 4000000000LL, 900, 9600));
}

/* What one removal's answer means for the sweep */

void test_a_successful_removal_is_ok(void **state) {
    char error[256] = "";

    assert_int_equal(wm_manager_task_delete_old_outcome(true, 0, error, sizeof(error)), WM_MANAGER_TASK_OK);
}

void test_an_agent_that_is_already_gone_is_ok(void **state) {
    char error[256] = "";

    // IDEMPOTENCY. The dispatcher may re-run this handler after a lost outcome write, and by then
    // the agents the abandoned attempt removed are gone. Treating that as a failure would make the
    // sweep unable to satisfy the contract every manager task handler is held to.
    assert_int_equal(wm_manager_task_delete_old_outcome(true, 9010, error, sizeof(error)), WM_MANAGER_TASK_OK);
    assert_int_equal(wm_manager_task_delete_old_outcome(true, 9011, error, sizeof(error)), WM_MANAGER_TASK_OK);
}

void test_an_already_journaled_deletion_is_ok(void **state) {
    char error[256] = "";

    // 9018: authd has already written the intent, so the removal will happen whether or not this
    // sweep waits for it. There is nothing left to do for this agent.
    assert_int_equal(wm_manager_task_delete_old_outcome(true, 9018, error, sizeof(error)), WM_MANAGER_TASK_OK);
}

void test_a_full_deletion_backlog_is_retryable(void **state) {
    char error[256] = "";

    // THE MAPPING THIS FUNCTION EXISTS FOR. 9020 means authd refused because it is already holding
    // as many journaled deletions as its bound allows -- so the agent is still there, and reporting
    // success would silently drop it until the next scheduled run.
    assert_int_equal(wm_manager_task_delete_old_outcome(true, 9020, error, sizeof(error)),
                     WM_MANAGER_TASK_RETRYABLE);

    // And the reason reaches LAST_ERROR, because a retention sweep that keeps retrying with an
    // empty reason is indistinguishable from one that is merely slow.
    assert_string_not_equal(error, "");
}

void test_a_demoted_master_fails_terminally(void **state) {
    char error[256] = "";

    // 9015: the node was demoted between the spawn and the run. No retry can help here, and the new
    // master's own schedule covers the work.
    assert_int_equal(wm_manager_task_delete_old_outcome(true, 9015, error, sizeof(error)), WM_MANAGER_TASK_TERMINAL);
    assert_string_not_equal(error, "");
}

void test_an_unknown_refusal_is_retryable_not_terminal(void **state) {
    char error[256] = "";

    // Retryable is the safe default for a code this build does not recognise: an agent that should
    // have been deleted and was not is recoverable, while giving up on it is not.
    assert_int_equal(wm_manager_task_delete_old_outcome(true, 9001, error, sizeof(error)), WM_MANAGER_TASK_RETRYABLE);
    assert_string_not_equal(error, "");
}

void test_no_answer_at_all_is_retryable(void **state) {
    char error[256] = "";

    // authd down, or the socket wedged past its deadline. The distinction from a refusal matters:
    // this one says nothing about the agent.
    assert_int_equal(wm_manager_task_delete_old_outcome(false, 0, error, sizeof(error)), WM_MANAGER_TASK_RETRYABLE);
    assert_string_not_equal(error, "");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // The retention window
        cmocka_unit_test(test_a_recently_seen_agent_is_not_expired),
        cmocka_unit_test(test_the_window_is_the_disconnection_time_plus_the_retention),
        cmocka_unit_test(test_the_boundary_is_exclusive),
        cmocka_unit_test(test_a_disabled_retention_expires_nothing),
        cmocka_unit_test(test_a_very_old_keepalive_does_not_overflow),
        // What one removal's answer means for the sweep
        cmocka_unit_test(test_a_successful_removal_is_ok),
        cmocka_unit_test(test_an_agent_that_is_already_gone_is_ok),
        cmocka_unit_test(test_an_already_journaled_deletion_is_ok),
        cmocka_unit_test(test_a_full_deletion_backlog_is_retryable),
        cmocka_unit_test(test_a_demoted_master_fails_terminally),
        cmocka_unit_test(test_an_unknown_refusal_is_retryable_not_terminal),
        cmocka_unit_test(test_no_answer_at_all_is_retryable),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
