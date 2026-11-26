/*
 * Copyright (C) Wazuh Inc.
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
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "../../remoted/src/agent_metadata_db.h"

/* The real cache, end to end: the group membership of a legacy (4.x) agent reaches the snapshot
 * the event header is built from, and survives the refresh every keepalive performs. */

static int setup(void **state) {
    (void) state;
    agent_metadata_init();
    return 0;
}

static int teardown(void **state) {
    (void) state;
    agent_metadata_teardown();
    return 0;
}

/* A keepalive refresh as secure.c performs it: a fresh entry with no groups. */
static void upsert_keepalive(const char *id, const char *name) {
    agent_meta_t *fresh = NULL;
    os_calloc(1, sizeof(agent_meta_t), fresh);
    fresh->agent_id = atoi(id);
    os_strdup(name, fresh->agent_name);
    assert_int_equal(agent_meta_upsert_locked(id, fresh), 0);
}

static void assert_groups(const char *id, size_t count, const char *const *expected) {
    agent_meta_t snap = {0};
    assert_int_equal(agent_meta_snapshot_str(id, &snap), 0);
    assert_int_equal(snap.groups_count, count);
    for (size_t i = 0; i < count; i++) {
        assert_non_null(snap.groups[i]);
        assert_string_equal(snap.groups[i], expected[i]);
    }
    agent_meta_clear(&snap);
}

static void test_set_groups_unknown_agent(void **state) {
    (void) state;
    assert_int_equal(agent_meta_set_groups("001", "web,linux"), -1);
    agent_meta_t snap = {0};
    assert_int_equal(agent_meta_snapshot_str("001", &snap), -1);
}

static void test_set_groups_splits_csv(void **state) {
    (void) state;
    const char *expected[] = {"web", "linux"};

    upsert_keepalive("001", "agent-1");
    assert_int_equal(agent_meta_set_groups("001", "web,linux"), 0);
    assert_groups("001", 2, expected);
}

static void test_keepalive_refresh_keeps_groups(void **state) {
    (void) state;
    const char *expected[] = {"web", "linux"};

    upsert_keepalive("001", "agent-1");
    assert_int_equal(agent_meta_set_groups("001", "web,linux"), 0);

    upsert_keepalive("001", "agent-1");
    upsert_keepalive("001", "agent-1");
    assert_groups("001", 2, expected);
}

static void test_fresh_groups_win_over_cached(void **state) {
    (void) state;
    const char *expected[] = {"db"};

    upsert_keepalive("001", "agent-1");
    assert_int_equal(agent_meta_set_groups("001", "web"), 0);

    agent_meta_t *fresh = NULL;
    os_calloc(1, sizeof(agent_meta_t), fresh);
    os_calloc(1, sizeof(char *), fresh->groups);
    os_strdup("db", fresh->groups[0]);
    fresh->groups_count = 1;
    assert_int_equal(agent_meta_upsert_locked("001", fresh), 0);

    assert_groups("001", 1, expected);
}

static void test_set_groups_replaces_and_clears(void **state) {
    (void) state;
    const char *first[] = {"web", "linux"};
    const char *second[] = {"db"};

    upsert_keepalive("002", "agent-2");
    assert_int_equal(agent_meta_set_groups("002", "web,linux"), 0);
    assert_groups("002", 2, first);

    assert_int_equal(agent_meta_set_groups("002", "db"), 0);
    assert_groups("002", 1, second);

    assert_int_equal(agent_meta_set_groups("002", NULL), 0);
    assert_groups("002", 0, NULL);

    assert_int_equal(agent_meta_set_groups("002", "db"), 0);
    assert_int_equal(agent_meta_set_groups("002", ""), 0);
    assert_groups("002", 0, NULL);
}

static void test_set_groups_skips_empty_items(void **state) {
    (void) state;
    const char *expected[] = {"a", "b"};

    upsert_keepalive("003", "agent-3");
    assert_int_equal(agent_meta_set_groups("003", ",a,,b,"), 0);
    assert_groups("003", 2, expected);
}

static void test_groups_are_per_agent(void **state) {
    (void) state;
    const char *web[] = {"web"};
    const char *db[] = {"db"};

    upsert_keepalive("001", "agent-1");
    upsert_keepalive("002", "agent-2");
    assert_int_equal(agent_meta_set_groups("001", "web"), 0);
    assert_int_equal(agent_meta_set_groups("002", "db"), 0);

    assert_groups("001", 1, web);
    assert_groups("002", 1, db);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_set_groups_unknown_agent, setup, teardown),
        cmocka_unit_test_setup_teardown(test_set_groups_splits_csv, setup, teardown),
        cmocka_unit_test_setup_teardown(test_keepalive_refresh_keeps_groups, setup, teardown),
        cmocka_unit_test_setup_teardown(test_fresh_groups_win_over_cached, setup, teardown),
        cmocka_unit_test_setup_teardown(test_set_groups_replaces_and_clears, setup, teardown),
        cmocka_unit_test_setup_teardown(test_set_groups_skips_empty_items, setup, teardown),
        cmocka_unit_test_setup_teardown(test_groups_are_per_agent, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
