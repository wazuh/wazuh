/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* The agent's single manager entry, as <agent><manager> and the legacy <client> set it. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

#include "shared.h"
#include "client-config.h"
#include "agent-manager-entry.h"

static void test_set_manager_stores_one_entry(void **state) {
    agent cfg = { .server = NULL };

    w_agent_set_manager(&cfg, "10.0.0.1", 8443, "gateway", 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.1");
    assert_int_equal(cfg.server[0].port, 8443);
    assert_string_equal(cfg.server[0].endpoint, "gateway");
    assert_int_equal(cfg.server[0].scope_id, 0);
    assert_null(cfg.server[1].rip);

    Free_Agent(&cfg);
}

static void test_set_manager_replaces_the_earlier_entry(void **state) {
    agent cfg = { .server = NULL };

    w_agent_set_manager(&cfg, "10.0.0.1", 8443, "gateway", 0);
    w_agent_set_manager(&cfg, "10.0.0.2", 1517, "wazuh-manager", 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.2");
    assert_int_equal(cfg.server[0].port, 1517);
    assert_string_equal(cfg.server[0].endpoint, "wazuh-manager");
    assert_null(cfg.server[1].rip);

    Free_Agent(&cfg);
}

/* The new entry may be built from the strings of the one it replaces. */
static void test_set_manager_accepts_the_strings_of_the_earlier_entry(void **state) {
    agent cfg = { .server = NULL };

    w_agent_set_manager(&cfg, "10.0.0.1", 8443, "gateway", 0);
    w_agent_set_manager(&cfg, cfg.server[0].rip, 1517, cfg.server[0].endpoint, 0);

    assert_string_equal(cfg.server[0].rip, "10.0.0.1");
    assert_int_equal(cfg.server[0].port, 1517);
    assert_string_equal(cfg.server[0].endpoint, "gateway");

    Free_Agent(&cfg);
}

/* An <endpoint> that normalizes to nothing is the opt-out of any prefix. */
static void test_set_manager_stores_no_empty_endpoint(void **state) {
    agent cfg = { .server = NULL };

    w_agent_set_manager(&cfg, "10.0.0.1", 1517, "", 0);

    assert_null(cfg.server[0].endpoint);

    Free_Agent(&cfg);
}

static void test_set_manager_expands_an_ipv6_host(void **state) {
    agent cfg = { .server = NULL };

    w_agent_set_manager(&cfg, "fe80::1", 1517, "wazuh-manager", 3);

    assert_string_equal(cfg.server[0].rip, "FE80:0000:0000:0000:0000:0000:0000:0001");
    assert_int_equal(cfg.server[0].scope_id, 3);

    Free_Agent(&cfg);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_set_manager_stores_one_entry),
        cmocka_unit_test(test_set_manager_replaces_the_earlier_entry),
        cmocka_unit_test(test_set_manager_accepts_the_strings_of_the_earlier_entry),
        cmocka_unit_test(test_set_manager_stores_no_empty_endpoint),
        cmocka_unit_test(test_set_manager_expands_an_ipv6_host),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
