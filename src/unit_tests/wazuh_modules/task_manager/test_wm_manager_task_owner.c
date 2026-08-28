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
#include "../../../wazuh_modules/src/task_manager/wm_manager_task_owner.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"

/* Nothing here is mocked: /proc is read for real, because the whole value of a process start time
 * is that it comes from the kernel rather than from anything this process could be wrong about. */

/// A pid far enough above the usual pid_max that it will not be a running process.
#define ABSENT_PID 4194303

static wm_manager_task_owner self_identity(void) {
    wm_manager_task_owner self = {.pid = 4242, .start_time = 99887766};
    return self;
}

/* Formatting and parsing */

void test_owner_round_trips(void **state) {
    wm_manager_task_owner self = self_identity();
    wm_manager_task_owner parsed = {0};
    char owner[WM_MANAGER_TASK_OWNER_LEN];

    assert_int_equal(wm_manager_task_owner_format(owner, sizeof(owner), &self, WM_MANAGER_TASK_LANE_DELETE, 2), 0);
    assert_string_equal(owner, "4242:99887766:delete-2");

    assert_true(wm_manager_task_owner_parse(owner, &parsed));
    assert_int_equal(parsed.pid, 4242);
    assert_int_equal(parsed.start_time, 99887766);
    assert_string_equal(parsed.lane, "delete-2");
}

void test_owner_format_refuses_to_truncate(void **state) {
    wm_manager_task_owner self = self_identity();
    char owner[8];

    // A truncated OWNER would not compare equal to itself on the next sweep, so the row would
    // look like it belonged to nobody. Better to fail loudly at startup.
    assert_int_equal(wm_manager_task_owner_format(owner, sizeof(owner), &self, WM_MANAGER_TASK_LANE_DELETE, 2), -1);
}

void test_owner_format_rejects_bad_arguments(void **state) {
    wm_manager_task_owner self = self_identity();
    char owner[WM_MANAGER_TASK_OWNER_LEN];

    assert_int_equal(wm_manager_task_owner_format(NULL, sizeof(owner), &self, WM_MANAGER_TASK_LANE_SCAN, 0), -1);
    assert_int_equal(wm_manager_task_owner_format(owner, sizeof(owner), NULL, WM_MANAGER_TASK_LANE_SCAN, 0), -1);
    assert_int_equal(wm_manager_task_owner_format(owner, sizeof(owner), &self, WM_MANAGER_TASK_LANE_COUNT, 0), -1);
    assert_int_equal(wm_manager_task_owner_format(owner, sizeof(owner), &self, WM_MANAGER_TASK_LANE_SCAN, -1), -1);
}

void test_owner_parse_rejects_malformed_values(void **state) {
    wm_manager_task_owner parsed = {0};

    assert_false(wm_manager_task_owner_parse(NULL, &parsed));
    assert_false(wm_manager_task_owner_parse("", &parsed));
    assert_false(wm_manager_task_owner_parse("4242", &parsed));
    assert_false(wm_manager_task_owner_parse("4242:99887766", &parsed));
    assert_false(wm_manager_task_owner_parse("4242:99887766:", &parsed));
    assert_false(wm_manager_task_owner_parse("notapid:99887766:scan-0", &parsed));
    assert_false(wm_manager_task_owner_parse("4242:nottime:scan-0", &parsed));

    // Trailing junk on either integer means this is not a value this build wrote.
    assert_false(wm_manager_task_owner_parse("4242x:99887766:scan-0", &parsed));
    assert_false(wm_manager_task_owner_parse("4242:998x:scan-0", &parsed));

    // A pid of zero or below is not a process.
    assert_false(wm_manager_task_owner_parse("0:99887766:scan-0", &parsed));
    assert_false(wm_manager_task_owner_parse("-1:99887766:scan-0", &parsed));
}

void test_owner_parse_rejects_an_oversized_lane(void **state) {
    wm_manager_task_owner parsed = {0};
    char owner[128];

    snprintf(owner, sizeof(owner), "4242:99887766:%s", "a-very-long-lane-name-that-will-not-fit-in-the-field");

    assert_false(wm_manager_task_owner_parse(owner, &parsed));
}

/* Reading a process start time */

void test_start_time_of_a_live_process(void **state) {
    // This process exists, so its start time must be readable and non-zero. Without it an OWNER
    // cannot tell this process from a later one that inherits its pid.
    assert_true(wm_manager_task_process_start_time(getpid()) > 0);
}

void test_start_time_of_a_missing_process(void **state) {
    assert_int_equal(wm_manager_task_process_start_time(0), 0);
    assert_int_equal(wm_manager_task_process_start_time(-1), 0);
}

void test_start_time_is_stable(void **state) {
    // Read twice: a parse that walked the wrong field would be far more likely to differ than to
    // return the same wrong number twice.
    unsigned long long first = wm_manager_task_process_start_time(getpid());
    unsigned long long second = wm_manager_task_process_start_time(getpid());

    assert_int_equal(first, second);
}

/* Classification */

void test_classify_recognises_our_own_lane(void **state) {
    wm_manager_task_owner self = {0};
    char owner[WM_MANAGER_TASK_OWNER_LEN];

    self.pid = getpid();
    self.start_time = wm_manager_task_process_start_time(self.pid);

    assert_int_equal(wm_manager_task_owner_format(owner, sizeof(owner), &self, WM_MANAGER_TASK_LANE_SCAN, 0), 0);
    assert_int_equal(wm_manager_task_owner_classify(owner, &self), WM_MANAGER_TASK_OWNER_MINE);
}

void test_classify_treats_a_recycled_pid_as_dead(void **state) {
    wm_manager_task_owner self = self_identity();
    char owner[WM_MANAGER_TASK_OWNER_LEN];

    // This pid is alive, but the start time on the row is not its own: the pid was recycled and
    // the claim belongs to a process that no longer exists. A pid check alone would call this
    // owner alive and leave the row unclaimable for as long as the new process runs.
    snprintf(owner, sizeof(owner), "%d:1:scan-0", (int)getpid());

    assert_int_equal(wm_manager_task_owner_classify(owner, &self), WM_MANAGER_TASK_OWNER_DEAD);
}

void test_classify_reports_a_missing_process_as_dead(void **state) {
    wm_manager_task_owner self = self_identity();
    char owner[WM_MANAGER_TASK_OWNER_LEN];

    snprintf(owner, sizeof(owner), "%d:12345:scan-0", ABSENT_PID);

    assert_int_equal(wm_manager_task_owner_classify(owner, &self), WM_MANAGER_TASK_OWNER_DEAD);
}

void test_classify_reports_malformed_owners(void **state) {
    wm_manager_task_owner self = self_identity();

    assert_int_equal(wm_manager_task_owner_classify("garbage", &self), WM_MANAGER_TASK_OWNER_UNPARSEABLE);
    assert_int_equal(wm_manager_task_owner_classify(NULL, &self), WM_MANAGER_TASK_OWNER_UNPARSEABLE);
    assert_int_equal(wm_manager_task_owner_classify("1:1:scan-0", NULL), WM_MANAGER_TASK_OWNER_UNPARSEABLE);
}

/* The sweep predicate */

void test_a_dead_owner_is_reclaimed_at_once(void **state) {
    wm_manager_task_owner self = self_identity();

    // No lease timer: after a crash mid-execution the row does not sit unusable for a timeout
    // that has nothing to do with the failure.
    assert_true(wm_manager_task_owner_reclaimable("1:1:scan-0", 1000, 1001, 30, &self, NULL, "abc"));
}

void test_a_foreign_live_owner_is_never_reclaimed(void **state) {
    wm_manager_task_owner self = {0};
    char owner[WM_MANAGER_TASK_OWNER_LEN];

    // Stands in for a second modulesd, or an old process still shutting down under a restart: an
    // owner whose process is demonstrably alive but is not this instance. Forced deterministically
    // by giving "self" a start time that is not the live one, so the identity cannot match.
    self.pid = getpid();
    self.start_time = 1;

    snprintf(owner, sizeof(owner), "%d:%llu:scan-0", (int)getpid(),
             wm_manager_task_process_start_time(getpid()));

    assert_int_equal(wm_manager_task_owner_classify(owner, &self), WM_MANAGER_TASK_OWNER_FOREIGN);

    // Never reclaimed, however old the claim: those lanes may still be mid-call, and inferring
    // death from "not mine" is what would cause the concurrent execution this design forbids.
    assert_false(wm_manager_task_owner_reclaimable(owner, 0, 100000, 30, &self, NULL, "abc"));
}

void test_our_lane_working_on_the_row_is_never_reclaimed(void **state) {
    wm_manager_task_owner self = {0};
    char owner[WM_MANAGER_TASK_OWNER_LEN];

    self.pid = getpid();
    self.start_time = wm_manager_task_process_start_time(self.pid);
    assert_int_equal(wm_manager_task_owner_format(owner, sizeof(owner), &self, WM_MANAGER_TASK_LANE_SCAN, 0), 0);

    // However long it has been held. This is the one race that would make the design worse than
    // what it replaces: flipping the row to pending while the handler is still running executes
    // the work twice and leaves the lane with nothing to show for it. The per-call timeout is
    // what bounds a long-running handler, not the sweep.
    assert_false(wm_manager_task_owner_reclaimable(owner, 0, 999999, 30, &self, "abc", "abc"));
}

void test_our_lane_on_a_different_row_is_reclaimed_after_the_grace(void **state) {
    wm_manager_task_owner self = {0};
    char owner[WM_MANAGER_TASK_OWNER_LEN];

    self.pid = getpid();
    self.start_time = wm_manager_task_process_start_time(self.pid);
    assert_int_equal(wm_manager_task_owner_format(owner, sizeof(owner), &self, WM_MANAGER_TASK_LANE_SCAN, 0), 0);

    assert_true(wm_manager_task_owner_reclaimable(owner, 1000, 1031, 30, &self, "other", "abc"));
}

void test_a_freshly_claimed_row_is_left_alone(void **state) {
    wm_manager_task_owner self = {0};
    char owner[WM_MANAGER_TASK_OWNER_LEN];

    self.pid = getpid();
    self.start_time = wm_manager_task_process_start_time(self.pid);
    assert_int_equal(wm_manager_task_owner_format(owner, sizeof(owner), &self, WM_MANAGER_TASK_LANE_SCAN, 0), 0);

    // The window this grace exists for: the claim has landed but the lane has not published the
    // id yet, because it cannot until the claim returns it. Without the grace the sweep reads
    // "not the row this lane is running" and reclaims a row that is about to execute -- double
    // execution, caused by the mechanism meant to prevent it.
    assert_false(wm_manager_task_owner_reclaimable(owner, 1000, 1000, 30, &self, NULL, "abc"));
    assert_false(wm_manager_task_owner_reclaimable(owner, 1000, 1030, 30, &self, NULL, "abc"));

    // One second past the grace, it is fair game.
    assert_true(wm_manager_task_owner_reclaimable(owner, 1000, 1031, 30, &self, NULL, "abc"));
}

void test_an_unreadable_owner_is_reclaimed(void **state) {
    wm_manager_task_owner self = self_identity();

    // No other rule would ever touch it, so it would stay claimed forever while counting against
    // the row ceiling.
    assert_true(wm_manager_task_owner_reclaimable("garbage", 1000, 1001, 30, &self, NULL, "abc"));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Formatting and parsing
        cmocka_unit_test(test_owner_round_trips),
        cmocka_unit_test(test_owner_format_refuses_to_truncate),
        cmocka_unit_test(test_owner_format_rejects_bad_arguments),
        cmocka_unit_test(test_owner_parse_rejects_malformed_values),
        cmocka_unit_test(test_owner_parse_rejects_an_oversized_lane),
        // Reading a process start time
        cmocka_unit_test(test_start_time_of_a_live_process),
        cmocka_unit_test(test_start_time_of_a_missing_process),
        cmocka_unit_test(test_start_time_is_stable),
        // Classification
        cmocka_unit_test(test_classify_recognises_our_own_lane),
        cmocka_unit_test(test_classify_treats_a_recycled_pid_as_dead),
        cmocka_unit_test(test_classify_reports_a_missing_process_as_dead),
        cmocka_unit_test(test_classify_reports_malformed_owners),
        // The sweep predicate
        cmocka_unit_test(test_a_dead_owner_is_reclaimed_at_once),
        cmocka_unit_test(test_a_foreign_live_owner_is_never_reclaimed),
        cmocka_unit_test(test_our_lane_working_on_the_row_is_never_reclaimed),
        cmocka_unit_test(test_our_lane_on_a_different_row_is_reclaimed_after_the_grace),
        cmocka_unit_test(test_a_freshly_claimed_row_is_left_alone),
        cmocka_unit_test(test_an_unreadable_owner_is_reclaimed),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
