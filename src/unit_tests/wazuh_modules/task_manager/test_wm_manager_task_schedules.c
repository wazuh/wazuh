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
#include <time.h>

#include "wmodules.h"
#include "../../../wazuh_modules/src/task_manager/wm_manager_task_schedules.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"

/* The daily arithmetic is local-time arithmetic, so the timezone is pinned rather than inherited:
 * mktime() over a zeroed clock is exactly what makes the offset survive a DST shift, and a machine
 * whose zone has no midnight on some day would otherwise fail one assertion twice a year. */
static int group_setup(void **state) {
    setenv("TZ", "UTC", 1);
    tzset();

    return 0;
}

cJSON *__wrap_w_mconf_section(__attribute__((unused)) const char *section) {
    long value = mock_type(long);

    // A negative queued value stands for "the effective document could not be read", which is the
    // case the loader has to survive without exiting.
    if (value < 0) {
        return NULL;
    }

    cJSON *global = cJSON_CreateObject();

    if (value > 0) {
        // The real Read_Global_JSON parses this section, so the schedule loader is exercised
        // against the reader it ships with rather than against a hand-written struct.
        cJSON_AddNumberToObject(global, "agents_disconnection_time", (double)value);
    }

    return global;
}

/* The built-in table */

void test_every_schedule_is_addressable(void **state) {
    size_t count = wm_manager_task_schedules_count();

    assert_true(count > 0);

    for (size_t i = 0; i < count; i++) {
        const wm_manager_task_schedule_def *def = wm_manager_task_schedules_at(i);

        assert_non_null(def);
        assert_non_null(def->schedule_id);
        assert_non_null(def->task_type);

        // The id is the primary key, so a lookup by it must reach the same entry the walk did.
        assert_ptr_equal(wm_manager_task_schedules_get(def->schedule_id), def);
    }

    assert_null(wm_manager_task_schedules_at(count));
    assert_null(wm_manager_task_schedules_get("never_existed"));
    assert_null(wm_manager_task_schedules_get(NULL));
}

void test_schedule_ids_are_unique(void **state) {
    size_t count = wm_manager_task_schedules_count();

    // Two entries sharing an id would share a row: the second's upsert would overwrite the first's
    // next run, and one of the two would never fire again.
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            assert_string_not_equal(wm_manager_task_schedules_at(i)->schedule_id,
                                    wm_manager_task_schedules_at(j)->schedule_id);
        }
    }
}

void test_the_three_recurring_schedules_are_present(void **state) {
    const wm_manager_task_schedule_def *sweep = wm_manager_task_schedules_get("agent_disconnect_sweep");
    const wm_manager_task_schedule_def *retention = wm_manager_task_schedules_get("agent_delete_old");
    const wm_manager_task_schedule_def *rotation = wm_manager_task_schedules_get("log_rotate_daily");

    assert_non_null(sweep);
    assert_non_null(retention);
    assert_non_null(rotation);

    // Both agent-facing schedules are master-scoped: they read and write rows for the whole
    // cluster's agents, so two nodes running them would collide.
    assert_int_equal(sweep->scope, WM_MANAGER_TASK_SCOPE_MASTER);
    assert_int_equal(retention->scope, WM_MANAGER_TASK_SCOPE_MASTER);

    // Rotation is local work: every node writes its own logs.
    assert_int_equal(rotation->scope, WM_MANAGER_TASK_SCOPE_ANY);

    assert_int_equal(rotation->cadence, WM_MANAGER_TASK_CADENCE_DAILY);
    assert_int_equal(sweep->cadence, WM_MANAGER_TASK_CADENCE_INTERVAL);
}

/* Loading the configuration */

void test_load_reads_each_schedules_own_source(void **state) {
    wm_manager_task_schedule schedules[8] = {0};

    will_return(__wrap_w_mconf_section, 1800); // global agents_disconnection_time
    will_return(__wrap_getDefine_Int_default, 120); // manager_task_delete_old_agents, minutes
    will_return(__wrap_getDefine_Int_default, 1);   // manager_task_monitor_agents
    will_return(__wrap_getDefine_Int_default, 1);   // manager_task_log_rotate
    will_return(__wrap_getDefine_Int_default, 30);  // manager_task_log_day_wait

    assert_int_equal(wm_manager_task_schedules_load(schedules), wm_manager_task_schedules_count());

    for (size_t i = 0; i < wm_manager_task_schedules_count(); i++) {
        const char *id = schedules[i].def->schedule_id;

        if (strcmp(id, "agent_disconnect_sweep") == 0) {
            assert_int_equal(schedules[i].interval, 1800);
            assert_true(schedules[i].enabled);
        } else if (strcmp(id, "agent_delete_old") == 0) {
            // Minutes on the way in, seconds out. Getting this wrong by 60 is a two month interval.
            assert_int_equal(schedules[i].interval, 7200);
            assert_true(schedules[i].enabled);
        } else if (strcmp(id, "log_rotate_daily") == 0) {
            assert_int_equal(schedules[i].day_wait, 30);
            assert_true(schedules[i].enabled);
        }
    }
}

void test_retention_is_disabled_when_its_interval_is_zero(void **state) {
    wm_manager_task_schedule schedules[8] = {0};

    will_return(__wrap_w_mconf_section, 900);
    will_return(__wrap_getDefine_Int_default, 0);   // delete_old_agents, the shipping default
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 10);

    wm_manager_task_schedules_load(schedules);

    // Off by default, and off in a way that cannot become a zero-interval spin: a disabled schedule
    // is never listed as due.
    assert_false(wm_manager_task_schedules_get("agent_delete_old") == NULL);
    for (size_t i = 0; i < wm_manager_task_schedules_count(); i++) {
        if (strcmp(schedules[i].def->schedule_id, "agent_delete_old") == 0) {
            assert_false(schedules[i].enabled);
        }
    }
}

void test_monitor_agents_zero_disables_retention_only(void **state) {
    wm_manager_task_schedule schedules[8] = {0};

    will_return(__wrap_w_mconf_section, 900);
    will_return(__wrap_getDefine_Int_default, 60);  // delete_old_agents set...
    will_return(__wrap_getDefine_Int_default, 0);   // ...but monitor_agents off
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 10);

    wm_manager_task_schedules_load(schedules);

    for (size_t i = 0; i < wm_manager_task_schedules_count(); i++) {
        const char *id = schedules[i].def->schedule_id;

        if (strcmp(id, "agent_delete_old") == 0) {
            // Both gates apply: a retention window AND the agent-monitoring flag.
            assert_false(schedules[i].enabled);
        } else if (strcmp(id, "agent_disconnect_sweep") == 0) {
            // NOT disabled. The flag gates the log line and the retention deletion; carrying it
            // onto the sweep would stop agents ever being marked disconnected on a manager that
            // set it.
            assert_true(schedules[i].enabled);
        }
    }
}

void test_rotate_log_zero_disables_the_daily_rotation(void **state) {
    wm_manager_task_schedule schedules[8] = {0};

    will_return(__wrap_w_mconf_section, 900);
    will_return(__wrap_getDefine_Int_default, 0);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 0);   // rotate_log off
    will_return(__wrap_getDefine_Int_default, 10);

    wm_manager_task_schedules_load(schedules);

    for (size_t i = 0; i < wm_manager_task_schedules_count(); i++) {
        if (strcmp(schedules[i].def->schedule_id, "log_rotate_daily") == 0) {
            assert_false(schedules[i].enabled);
        }
    }
}

void test_load_survives_an_unreadable_global_section(void **state) {
    wm_manager_task_schedule schedules[8] = {0};

    will_return(__wrap_w_mconf_section, -1);   // the effective document is unavailable
    expect_any(__wrap__mtwarn, tag);
    expect_any(__wrap__mtwarn, formatted_msg);
    will_return(__wrap_getDefine_Int_default, 0);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 10);

    // Warns and carries on with the documented default: exiting here would take every other module
    // down over a <global> typo.
    assert_int_equal(wm_manager_task_schedules_load(schedules), wm_manager_task_schedules_count());

    for (size_t i = 0; i < wm_manager_task_schedules_count(); i++) {
        if (strcmp(schedules[i].def->schedule_id, "agent_disconnect_sweep") == 0) {
            assert_int_equal(schedules[i].interval, 900);
        }
    }
}

void test_load_rejects_a_null_destination(void **state) {
    assert_int_equal(wm_manager_task_schedules_load(NULL), 0);
}

/* Interval arithmetic */

void test_a_schedule_that_has_never_run_starts_one_interval_out(void **state) {
    // Not `now`. Starting at now would make every restart fire every schedule, so a restart loop
    // would become a sweep loop.
    assert_int_equal(wm_manager_task_schedule_next_interval(0, 1000, 900), 1900);
}

void test_a_future_slot_is_left_alone(void **state) {
    assert_int_equal(wm_manager_task_schedule_next_interval(2000, 1000, 900), 2000);
}

void test_the_next_slot_is_one_interval_on(void **state) {
    // Punctual case: the slot has just come due.
    assert_int_equal(wm_manager_task_schedule_next_interval(1000, 1000, 900), 1900);
    assert_int_equal(wm_manager_task_schedule_next_interval(1000, 1100, 900), 1900);
}

void test_missed_runs_coalesce_into_one(void **state) {
    // A week of downtime at a fifteen minute cadence is 672 missed slots. The answer is the next
    // FUTURE slot, reached in one step: walking them would be a visible pause in the scheduler.
    long long previous = 1000;
    long long now = previous + (672 * 900) + 5;
    long long next = wm_manager_task_schedule_next_interval(previous, now, 900);

    assert_true(next > now);
    assert_true(next - now <= 900);

    // Still on the original grid, so the cadence survives the outage rather than being re-anchored
    // to whenever the manager happened to come back.
    assert_int_equal((next - previous) % 900, 0);
}

void test_a_slot_exactly_at_now_still_advances(void **state) {
    // Strictly after `now`, or the schedule would be listed as due again on the very next poll and
    // the spawn loop would spin.
    assert_true(wm_manager_task_schedule_next_interval(1000, 1900, 900) > 1900);
}

void test_a_non_positive_interval_has_no_next_slot(void **state) {
    assert_int_equal(wm_manager_task_schedule_next_interval(1000, 2000, 0), 0);
    assert_int_equal(wm_manager_task_schedule_next_interval(1000, 2000, -60), 0);
}

/* Daily arithmetic */

void test_the_daily_slot_is_local_midnight_plus_the_offset(void **state) {
    time_t now = 1700000000; // Some fixed instant; the assertion is about structure, not a date.
    long long slot = wm_manager_task_schedule_next_daily((long long)now, 600);
    time_t as_time = (time_t)slot;
    struct tm broken = {0};

    assert_true(slot > (long long)now);

    localtime_r(&as_time, &broken);

    // 600 seconds past midnight is 00:10:00 local.
    assert_int_equal(broken.tm_hour, 0);
    assert_int_equal(broken.tm_min, 10);
    assert_int_equal(broken.tm_sec, 0);
}

void test_the_daily_slot_is_always_in_the_future(void **state) {
    // Whatever the offset and whatever the time of day, including the boundary cases where today's
    // slot has just passed.
    for (int offset = 0; offset <= 600; offset += 120) {
        for (long long now = 1700000000; now < 1700000000 + 86400; now += 3600) {
            assert_true(wm_manager_task_schedule_next_daily(now, offset) > now);
        }
    }
}

void test_a_daily_offset_beyond_a_day_is_clamped(void **state) {
    long long slot = wm_manager_task_schedule_next_daily(1700000000, 200000);

    // Clamped rather than wrapped: wrapping would put the slot before midnight, i.e. on the
    // previous day, and a slot in the past fires on every poll.
    assert_true(slot > 1700000000);
    assert_true(slot - 1700000000 <= 2 * 86400);
}

void test_the_cadence_selects_the_arithmetic(void **state) {
    const wm_manager_task_schedule_def interval_def = {
        .schedule_id = "x", .task_type = "t", .cadence = WM_MANAGER_TASK_CADENCE_INTERVAL};
    const wm_manager_task_schedule_def daily_def = {
        .schedule_id = "y", .task_type = "t", .cadence = WM_MANAGER_TASK_CADENCE_DAILY};
    wm_manager_task_schedule interval = {.def = &interval_def, .interval = 900};
    wm_manager_task_schedule daily = {.def = &daily_def, .day_wait = 0};

    assert_int_equal(wm_manager_task_schedule_next(&interval, 1000, 1000), 1900);

    // A daily schedule ignores `previous` entirely: several missed days collapse into the next
    // midnight by construction, so there is nothing to coalesce.
    assert_int_equal(wm_manager_task_schedule_next(&daily, 0, 1700000000),
                     wm_manager_task_schedule_next(&daily, 1, 1700000000));

    assert_int_equal(wm_manager_task_schedule_next(NULL, 0, 1000), 0);
}

/* Node scope */

void test_an_unscoped_schedule_runs_anywhere(void **state) {
    assert_true(wm_manager_task_schedule_node_allows(WM_MANAGER_TASK_SCOPE_ANY, 0));
    assert_true(wm_manager_task_schedule_node_allows(WM_MANAGER_TASK_SCOPE_ANY, 1));
    assert_true(wm_manager_task_schedule_node_allows(WM_MANAGER_TASK_SCOPE_ANY, OS_INVALID));
}

void test_a_master_scoped_schedule_runs_only_on_the_master(void **state) {
    assert_true(wm_manager_task_schedule_node_allows(WM_MANAGER_TASK_SCOPE_MASTER, 0));
    assert_false(wm_manager_task_schedule_node_allows(WM_MANAGER_TASK_SCOPE_MASTER, 1));
}

void test_an_unreadable_cluster_stanza_is_not_the_master(void **state) {
    // w_is_worker() returns OS_INVALID when ossec.conf will not parse. Letting that fall through to
    // "master" would run one sweep on two nodes whenever a worker's cluster stanza is broken.
    assert_false(wm_manager_task_schedule_node_allows(WM_MANAGER_TASK_SCOPE_MASTER, OS_INVALID));
    assert_false(wm_manager_task_schedule_node_allows(WM_MANAGER_TASK_SCOPE_MASTER, 42));
}

/* Startup and re-enablement */

static wm_manager_task_schedule interval_schedule(bool enabled, int interval) {
    static const wm_manager_task_schedule_def def = {
        .schedule_id = "s", .task_type = "t", .cadence = WM_MANAGER_TASK_CADENCE_INTERVAL};
    wm_manager_task_schedule schedule = {.def = &def, .interval = interval, .enabled = enabled};

    return schedule;
}

void test_a_new_schedule_starts_one_interval_out(void **state) {
    wm_manager_task_schedule schedule = interval_schedule(true, 900);

    assert_int_equal(wm_manager_task_schedule_startup_next_run(&schedule, false, 0, 0, 1000), 1900);
}

void test_an_enabled_schedule_keeps_its_stored_slot_across_a_restart(void **state) {
    wm_manager_task_schedule schedule = interval_schedule(true, 900);

    // Otherwise a restart would become a way to skip a slot, and a manager restarted every ten
    // minutes would never reach a fifteen minute one.
    assert_int_equal(wm_manager_task_schedule_startup_next_run(&schedule, true, 1500, 1, 1000), 1500);
}

void test_an_overdue_stored_slot_is_kept_so_the_missed_run_still_fires(void **state) {
    wm_manager_task_schedule schedule = interval_schedule(true, 900);

    // The slot is in the past because the manager was down through it. Keeping it is what makes the
    // spawn loop see it as due and coalescing turn it into exactly one catch-up run.
    assert_int_equal(wm_manager_task_schedule_startup_next_run(&schedule, true, 500, 1, 10000), 500);
}

void test_re_enabling_does_not_fire_an_immediate_catch_up(void **state) {
    wm_manager_task_schedule schedule = interval_schedule(true, 900);

    // DISABLED TIME IS NOT DOWNTIME. A week-old stored slot carried across a re-enablement would
    // look overdue and fire at once -- and for agent_delete_old, destructive and off by default, an
    // operator flipping the switch and getting an instant sweep is the surprise being avoided.
    assert_int_equal(wm_manager_task_schedule_startup_next_run(&schedule, true, 500, 0, 10000), 10900);
}

void test_a_shrunk_interval_is_recomputed(void **state) {
    wm_manager_task_schedule schedule = interval_schedule(true, 900);

    // The stored slot is further out than one whole interval from now, so it cannot have been
    // produced by the interval configured today. Without this, an operator who lowers
    // agents_disconnection_time still waits out the old, longer one.
    assert_int_equal(wm_manager_task_schedule_startup_next_run(&schedule, true, 100000, 1, 1000), 1900);
}

void test_a_grown_interval_needs_no_correction(void **state) {
    wm_manager_task_schedule schedule = interval_schedule(true, 3600);

    // The stored slot merely falls sooner than the new interval would place it: it fires once early
    // and re-anchors on the next advance, which is not worth a special case.
    assert_int_equal(wm_manager_task_schedule_startup_next_run(&schedule, true, 1500, 1, 1000), 1500);
}

void test_a_stored_slot_of_zero_is_recomputed(void **state) {
    wm_manager_task_schedule schedule = interval_schedule(true, 900);

    // A row written by something that did not know the column's meaning. Zero is permanently
    // overdue, so it must not be kept.
    assert_int_equal(wm_manager_task_schedule_startup_next_run(&schedule, true, 0, 1, 1000), 1900);
}

void test_a_disabled_schedule_still_gets_a_coherent_slot(void **state) {
    wm_manager_task_schedule schedule = interval_schedule(false, 900);

    // It will not be listed as due while disabled, but the column is NOT NULL and a nonsense value
    // would fire the moment it was switched on.
    assert_true(wm_manager_task_schedule_startup_next_run(&schedule, false, 0, 0, 1000) > 1000);
}

void test_startup_next_run_rejects_a_null_schedule(void **state) {
    assert_int_equal(wm_manager_task_schedule_startup_next_run(NULL, true, 1500, 1, 1000), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // The built-in table
        cmocka_unit_test(test_every_schedule_is_addressable),
        cmocka_unit_test(test_schedule_ids_are_unique),
        cmocka_unit_test(test_the_three_recurring_schedules_are_present),
        // Loading the configuration
        cmocka_unit_test(test_load_reads_each_schedules_own_source),
        cmocka_unit_test(test_retention_is_disabled_when_its_interval_is_zero),
        cmocka_unit_test(test_monitor_agents_zero_disables_retention_only),
        cmocka_unit_test(test_rotate_log_zero_disables_the_daily_rotation),
        cmocka_unit_test(test_load_survives_an_unreadable_global_section),
        cmocka_unit_test(test_load_rejects_a_null_destination),
        // Interval arithmetic
        cmocka_unit_test(test_a_schedule_that_has_never_run_starts_one_interval_out),
        cmocka_unit_test(test_a_future_slot_is_left_alone),
        cmocka_unit_test(test_the_next_slot_is_one_interval_on),
        cmocka_unit_test(test_missed_runs_coalesce_into_one),
        cmocka_unit_test(test_a_slot_exactly_at_now_still_advances),
        cmocka_unit_test(test_a_non_positive_interval_has_no_next_slot),
        // Daily arithmetic
        cmocka_unit_test(test_the_daily_slot_is_local_midnight_plus_the_offset),
        cmocka_unit_test(test_the_daily_slot_is_always_in_the_future),
        cmocka_unit_test(test_a_daily_offset_beyond_a_day_is_clamped),
        cmocka_unit_test(test_the_cadence_selects_the_arithmetic),
        // Node scope
        cmocka_unit_test(test_an_unscoped_schedule_runs_anywhere),
        cmocka_unit_test(test_a_master_scoped_schedule_runs_only_on_the_master),
        cmocka_unit_test(test_an_unreadable_cluster_stanza_is_not_the_master),
        // Startup and re-enablement
        cmocka_unit_test(test_a_new_schedule_starts_one_interval_out),
        cmocka_unit_test(test_an_enabled_schedule_keeps_its_stored_slot_across_a_restart),
        cmocka_unit_test(test_an_overdue_stored_slot_is_kept_so_the_missed_run_still_fires),
        cmocka_unit_test(test_re_enabling_does_not_fire_an_immediate_catch_up),
        cmocka_unit_test(test_a_shrunk_interval_is_recomputed),
        cmocka_unit_test(test_a_grown_interval_needs_no_correction),
        cmocka_unit_test(test_a_stored_slot_of_zero_is_recomputed),
        cmocka_unit_test(test_a_disabled_schedule_still_gets_a_coherent_slot),
        cmocka_unit_test(test_startup_next_run_rejects_a_null_schedule),
    };

    return cmocka_run_group_tests(tests, group_setup, NULL);
}
