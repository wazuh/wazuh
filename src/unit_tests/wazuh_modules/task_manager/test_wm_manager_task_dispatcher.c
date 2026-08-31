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
#include "../../../wazuh_modules/src/task_manager/wm_manager_task_dispatcher.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"

/* The dispatcher's decisions are pure functions so they can be exercised without threads, a
 * socket or a database. The threads themselves are covered by the integration cases. */

static int group_setup(void **state) {
    // vd_scan timeout, delete timeout, then the two admission bounds, in the order init reads them.
    // The connect timeout is not among them: it is a constant, not an operator knob.
    will_return(__wrap_getDefine_Int_default, 300);
    will_return(__wrap_getDefine_Int_default, 600);
    will_return(__wrap_getDefine_Int_default, 20000);
    will_return(__wrap_getDefine_Int_default, 64);

    assert_int_equal(wm_manager_task_registry_init("queue/sockets/inventory-sync-http.sock"), 0);

    return 0;
}

/* Lane rotation */

void test_a_single_type_lane_always_returns_its_type(void **state) {
    size_t rotation = 0;

    const wm_manager_task_descriptor *desc = wm_manager_task_rotate(WM_MANAGER_TASK_LANE_SCAN, &rotation, 0);

    assert_non_null(desc);
    assert_string_equal(desc->name, "vd_scan");

    // A lane with one type has nothing to rotate through, so a second offset is past the end.
    assert_null(wm_manager_task_rotate(WM_MANAGER_TASK_LANE_SCAN, &rotation, 1));
}

void test_a_pass_covers_every_type_on_the_lane(void **state) {
    size_t rotation = 0;
    size_t count = 0;

    wm_manager_task_registry_lane(WM_MANAGER_TASK_LANE_LOCAL, &count);
    assert_int_equal(count, 3);

    for (size_t offset = 0; offset < count; offset++) {
        const wm_manager_task_descriptor *desc = wm_manager_task_rotate(WM_MANAGER_TASK_LANE_LOCAL, &rotation, offset);

        assert_non_null(desc);

        // No type appears twice in one pass, so a pass genuinely covers the lane.
        for (size_t i = 0; i < count; i++) {
            const wm_manager_task_descriptor *other =
                wm_manager_task_rotate(WM_MANAGER_TASK_LANE_LOCAL, &rotation, i);

            if (i != offset) {
                assert_ptr_not_equal(desc, other);
            }
        }
    }

    assert_null(wm_manager_task_rotate(WM_MANAGER_TASK_LANE_LOCAL, &rotation, count));
}

void test_rotation_moves_the_starting_point(void **state) {
    size_t rotation = 0;
    const wm_manager_task_descriptor *first = wm_manager_task_rotate(WM_MANAGER_TASK_LANE_LOCAL, &rotation, 0);

    // Advancing past the type that yielded a row is what stops a busy type starving its siblings:
    // the next pass begins at the following one rather than at the same one every time.
    rotation = (rotation + 1) % 3;

    assert_ptr_not_equal(first, wm_manager_task_rotate(WM_MANAGER_TASK_LANE_LOCAL, &rotation, 0));

    rotation = (rotation + 1) % 3;
    assert_ptr_not_equal(first, wm_manager_task_rotate(WM_MANAGER_TASK_LANE_LOCAL, &rotation, 0));

    // Three steps returns to the start: the walk is a rotation, not a drift.
    rotation = (rotation + 1) % 3;
    assert_ptr_equal(first, wm_manager_task_rotate(WM_MANAGER_TASK_LANE_LOCAL, &rotation, 0));
}

void test_rotate_rejects_bad_arguments(void **state) {
    size_t rotation = 0;

    assert_null(wm_manager_task_rotate(WM_MANAGER_TASK_LANE_COUNT, &rotation, 0));
    assert_null(wm_manager_task_rotate(WM_MANAGER_TASK_LANE_LOCAL, NULL, 0));
}

/* The watchdog predicate */

void test_an_idle_lane_is_not_stalled(void **state) {
    assert_false(wm_manager_task_worker_stalled(false, 0, 300000, 100000));
    assert_false(wm_manager_task_worker_stalled(true, 0, 300000, 100000));
}

void test_a_call_within_its_deadline_is_not_stalled(void **state) {
    // 300 second deadline plus the margin. A call that is merely close to its own deadline is a
    // slow call, and reporting it would make the warning meaningless on a lane whose work
    // legitimately runs for minutes.
    assert_false(wm_manager_task_worker_stalled(true, 1000, 300000, 1000 + 300));
    assert_false(wm_manager_task_worker_stalled(true, 1000, 300000, 1000 + 330));
}

void test_a_call_past_its_deadline_and_margin_is_stalled(void **state) {
    assert_true(wm_manager_task_worker_stalled(true, 1000, 300000, 1000 + 331));
}

void test_a_local_handler_gets_the_margin_alone(void **state) {
    // A local handler has no request timeout, so the margin is the whole of its allowance.
    assert_false(wm_manager_task_worker_stalled(true, 1000, 0, 1030));
    assert_true(wm_manager_task_worker_stalled(true, 1000, 0, 1031));
}

/* Looking up what a lane is executing */

void test_inflight_lookup_finds_a_busy_worker(void **state) {
    wm_manager_task_dispatcher dispatcher = {0};
    wm_manager_task_worker workers[2] = {0};
    char task_id[WM_MANAGER_TASK_ID_LEN] = "";

    strcpy(workers[0].owner, "10:20:scan-0");
    strcpy(workers[1].owner, "10:20:delete-0");
    strcpy(workers[1].inflight_task_id, "abc");
    workers[1].inflight = true;

    w_mutex_init(&workers[0].published_mutex, NULL);
    w_mutex_init(&workers[1].published_mutex, NULL);

    dispatcher.workers = workers;
    dispatcher.worker_count = 2;

    assert_true(wm_manager_task_worker_inflight(&dispatcher, "10:20:delete-0", task_id, sizeof(task_id)));
    assert_string_equal(task_id, "abc");
}

void test_inflight_lookup_reports_an_idle_worker_as_empty(void **state) {
    wm_manager_task_dispatcher dispatcher = {0};
    wm_manager_task_worker workers[1] = {0};
    char task_id[WM_MANAGER_TASK_ID_LEN] = "";

    strcpy(workers[0].owner, "10:20:scan-0");

    // Left over from an earlier task and not cleared: the flag, not the string, says whether the
    // lane holds anything. Reading the string alone would make an idle lane look busy and stop
    // the sweep from ever reclaiming its rows.
    strcpy(workers[0].inflight_task_id, "stale");
    workers[0].inflight = false;

    w_mutex_init(&workers[0].published_mutex, NULL);

    dispatcher.workers = workers;
    dispatcher.worker_count = 1;

    assert_true(wm_manager_task_worker_inflight(&dispatcher, "10:20:scan-0", task_id, sizeof(task_id)));
    assert_string_equal(task_id, "");
}

void test_inflight_lookup_rejects_an_unknown_owner(void **state) {
    wm_manager_task_dispatcher dispatcher = {0};
    wm_manager_task_worker workers[1] = {0};
    char task_id[WM_MANAGER_TASK_ID_LEN] = "unchanged";

    strcpy(workers[0].owner, "10:20:scan-0");
    w_mutex_init(&workers[0].published_mutex, NULL);

    dispatcher.workers = workers;
    dispatcher.worker_count = 1;

    // An owner from another process instance. Reporting it as ours would let the sweep decide it
    // was idle and reclaim a row a live foreign lane is still running.
    assert_false(wm_manager_task_worker_inflight(&dispatcher, "999:1:scan-0", task_id, sizeof(task_id)));
    assert_string_equal(task_id, "");

    assert_false(wm_manager_task_worker_inflight(NULL, "10:20:scan-0", task_id, sizeof(task_id)));
    assert_false(wm_manager_task_worker_inflight(&dispatcher, NULL, task_id, sizeof(task_id)));
    assert_false(wm_manager_task_worker_inflight(&dispatcher, "10:20:scan-0", NULL, 0));
}

/* The spawn decision */

void test_a_due_schedule_with_a_free_slot_spawns(void **state) {
    assert_int_equal(wm_manager_task_spawn_decide(true, true, true, false), WM_MANAGER_TASK_SPAWN);
}

void test_an_unknown_schedule_is_skipped_not_held(void **state) {
    // Holding would re-read a row this build cannot act on at every poll, forever. Skipping
    // advances the slot, so a stranded schedule costs one query a day instead of one every five
    // seconds -- and the node scope and overlap answers are irrelevant once nothing can run it.
    assert_int_equal(wm_manager_task_spawn_decide(false, true, true, false), WM_MANAGER_TASK_SPAWN_SKIP);
    assert_int_equal(wm_manager_task_spawn_decide(false, false, false, true), WM_MANAGER_TASK_SPAWN_SKIP);
}

void test_a_node_that_may_not_run_it_skips_the_slot(void **state) {
    // Skipping rather than holding is what keeps w_is_worker() off the poll path: it re-parses
    // ossec.conf from disk on every call, so a worker that held its master-scoped schedules would
    // re-read the file every five seconds for the life of the process.
    assert_int_equal(wm_manager_task_spawn_decide(true, false, true, false), WM_MANAGER_TASK_SPAWN_SKIP);
}

void test_an_unanswered_overlap_check_holds(void **state) {
    // Asymmetric on purpose. Advancing on an unanswered question would skip a legitimate run
    // outright; holding costs one query on the next poll and self-heals when wazuh-db answers.
    assert_int_equal(wm_manager_task_spawn_decide(true, true, false, false), WM_MANAGER_TASK_SPAWN_HOLD);
    assert_int_equal(wm_manager_task_spawn_decide(true, true, false, true), WM_MANAGER_TASK_SPAWN_HOLD);
}

void test_an_instance_still_in_flight_suppresses_the_next_run(void **state) {
    // Overlap-skip, and the interaction with `incomplete` that comes with it: a multi-batch
    // agent_delete_old holds a non-terminal instance for the whole sweep, which suppresses its own
    // next scheduled run until it finishes. Correct -- a retention sweep should not start again
    // while the previous one is still walking -- and it means the effective interval under a large
    // backlog is however long the sweep takes, not the configured one.
    assert_int_equal(wm_manager_task_spawn_decide(true, true, true, true), WM_MANAGER_TASK_SPAWN_SKIP);
}

/* Direct actions */

void test_every_direct_action_is_addressable(void **state) {
    size_t count = wm_manager_task_direct_count();

    assert_true(count > 0);

    for (size_t i = 0; i < count; i++) {
        const wm_manager_task_direct_def *action = wm_manager_task_direct_at(i);

        assert_non_null(action);
        assert_non_null(action->name);
        // No entry may be a null function pointer or a zero interval: the first would be called,
        // and the second would signal its lane every single pass of the scheduler loop.
        assert_non_null(action->run);
        assert_true(action->interval > 0);
        assert_true(action->lane < WM_MANAGER_TASK_LANE_COUNT);
    }

    assert_null(wm_manager_task_direct_at(count));
}

void test_size_rotation_is_a_direct_action_and_not_a_task(void **state) {
    bool found = false;

    for (size_t i = 0; i < wm_manager_task_direct_count(); i++) {
        if (strcmp(wm_manager_task_direct_at(i)->name, "log_rotate_size") == 0) {
            found = true;
            // On the local lane, which is where the daily rotation runs too, so the two can never
            // rotate the same file concurrently.
            assert_int_equal(wm_manager_task_direct_at(i)->lane, WM_MANAGER_TASK_LANE_LOCAL);
        }
    }

    assert_true(found);

    // And deliberately NOT a task type: routing two w_stat() calls through the queue would cost
    // about 1440 rows a day to do work that is harmless to miss.
    assert_null(wm_manager_task_registry_get("log_rotate_size"));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Lane rotation
        cmocka_unit_test(test_a_single_type_lane_always_returns_its_type),
        cmocka_unit_test(test_a_pass_covers_every_type_on_the_lane),
        cmocka_unit_test(test_rotation_moves_the_starting_point),
        cmocka_unit_test(test_rotate_rejects_bad_arguments),
        // The watchdog predicate
        cmocka_unit_test(test_an_idle_lane_is_not_stalled),
        cmocka_unit_test(test_a_call_within_its_deadline_is_not_stalled),
        cmocka_unit_test(test_a_call_past_its_deadline_and_margin_is_stalled),
        cmocka_unit_test(test_a_local_handler_gets_the_margin_alone),
        // Looking up what a lane is executing
        cmocka_unit_test(test_inflight_lookup_finds_a_busy_worker),
        cmocka_unit_test(test_inflight_lookup_reports_an_idle_worker_as_empty),
        cmocka_unit_test(test_inflight_lookup_rejects_an_unknown_owner),
        // The spawn decision
        cmocka_unit_test(test_a_due_schedule_with_a_free_slot_spawns),
        cmocka_unit_test(test_an_unknown_schedule_is_skipped_not_held),
        cmocka_unit_test(test_a_node_that_may_not_run_it_skips_the_slot),
        cmocka_unit_test(test_an_unanswered_overlap_check_holds),
        cmocka_unit_test(test_an_instance_still_in_flight_suppresses_the_next_run),
        // Direct actions
        cmocka_unit_test(test_every_direct_action_is_addressable),
        cmocka_unit_test(test_size_rotation_is_a_direct_action_and_not_a_task),
    };

    return cmocka_run_group_tests(tests, group_setup, NULL);
}
