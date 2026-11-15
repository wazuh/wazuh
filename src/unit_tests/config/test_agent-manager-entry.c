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

/* Longer than an IPv6 address, so it can't be one: it used to be cut to that size and left
 * without its terminator, and everything that printed it read past the buffer. */
static void test_set_manager_keeps_a_long_host_with_a_colon_whole(void **state) {
    agent cfg = { .server = NULL };
    const char *host = "long-manager-hostname.example.internal.corp:1517";

    w_agent_set_manager(&cfg, host, 1517, "wazuh-manager", 0);

    assert_string_equal(cfg.server[0].rip, host);

    Free_Agent(&cfg);
}

static void test_set_manager_keeps_a_host_that_does_not_expand(void **state) {
    agent cfg = { .server = NULL };

    w_agent_set_manager(&cfg, "wazuh-server:1517", 1517, "wazuh-manager", 0);

    assert_string_equal(cfg.server[0].rip, "wazuh-server:1517");

    Free_Agent(&cfg);
}

static void test_manager_name_is_host_port_and_prefix(void **state) {
    agent_server server = { .rip = "wazuh-server", .port = 1517, .endpoint = "wazuh-manager" };
    char *name = w_agent_manager_name(&server);

    assert_string_equal(name, "wazuh-server:1517/wazuh-manager");

    os_free(name);
}

static void test_manager_name_brackets_an_ipv6_host(void **state) {
    agent_server server = { .rip = "2001:0DB8:0000:0000:0000:0000:0000:0001", .port = 8443,
                            .endpoint = "gw" };
    char *name = w_agent_manager_name(&server);

    assert_string_equal(name, "[2001:0DB8:0000:0000:0000:0000:0000:0001]:8443/gw");

    os_free(name);
}

/* <server-hostname> has always stored its host with a trailing '/'. */
static void test_manager_name_drops_the_slash_of_a_server_hostname(void **state) {
    agent_server server = { .rip = "manager.example/", .port = 1517, .endpoint = "wazuh-manager" };
    char *name = w_agent_manager_name(&server);

    assert_string_equal(name, "manager.example:1517/wazuh-manager");

    os_free(name);
}

/* No prefix is the "host:port/" opt-out, which is how an <endpoint> spells it. */
static void test_manager_name_keeps_the_slash_without_a_prefix(void **state) {
    agent_server server = { .rip = "10.0.0.1", .port = 1517, .endpoint = NULL };
    char *name = w_agent_manager_name(&server);

    assert_string_equal(name, "10.0.0.1:1517/");

    os_free(name);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_set_manager_stores_one_entry),
        cmocka_unit_test(test_set_manager_replaces_the_earlier_entry),
        cmocka_unit_test(test_set_manager_accepts_the_strings_of_the_earlier_entry),
        cmocka_unit_test(test_set_manager_stores_no_empty_endpoint),
        cmocka_unit_test(test_set_manager_expands_an_ipv6_host),
        cmocka_unit_test(test_set_manager_keeps_a_long_host_with_a_colon_whole),
        cmocka_unit_test(test_set_manager_keeps_a_host_that_does_not_expand),
        cmocka_unit_test(test_manager_name_is_host_port_and_prefix),
        cmocka_unit_test(test_manager_name_brackets_an_ipv6_host),
        cmocka_unit_test(test_manager_name_drops_the_slash_of_a_server_hostname),
        cmocka_unit_test(test_manager_name_keeps_the_slash_without_a_prefix),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
