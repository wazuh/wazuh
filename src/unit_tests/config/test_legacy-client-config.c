/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Which manager a whole agent configuration file leaves when it still carries a legacy
 * 4.x <client> block. Read through ReadConfig(), which settles the legacy
 * targets once every block of the file is read. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

#include "shared.h"
#include "client-config.h"
#include "config.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#define TEST_CONF "/tmp/test_legacy-client-config.conf"

/* What the agent dials for a bare <address>: the 5.x port and the default prefix. */
#define ADDRESS_FALLBACK_INFO(ip)                                                                \
    "<agent><manager><endpoint> is not configured. Using <client><server><address> '" ip "' "  \
    "with the default port 1517 and the default endpoint prefix 'wazuh-manager'. Replace the " \
    "<client><server> block with a single <endpoint>" ip ":1517/wazuh-manager</endpoint>"

#define DROPPED_WARNING(used, ignored)                                                     \
    "The legacy <client> block names more than one manager, and only one is supported. " \
    "Using '" used "', ignoring " ignored "."

#define SKIPPED_WARNING(used, ignored)                                                  \
    "<server> inside the legacy <client> block is ignored: the manager is already set " \
    "to '" used "'. Ignoring " ignored "."

/* The library is built for the agent, so the root is <ossec_config>. */
static int read_conf(const char *body, agent *cfg) {
    FILE *fp = fopen(TEST_CONF, "w");

    assert_non_null(fp);
    fputs(body, fp);
    fclose(fp);

    memset(cfg, 0, sizeof(*cfg));
    return ReadConfig(CCLIENT, TEST_CONF, cfg, NULL);
}

static void assert_manager(const agent *cfg, const char *rip, int port, const char *endpoint) {
    assert_int_equal(cfg->server_count, 1);
    assert_string_equal(cfg->server[0].rip, rip);
    assert_int_equal(cfg->server[0].port, port);
    assert_string_equal(cfg->server[0].endpoint, endpoint);
    assert_null(cfg->server[1].rip);
}

static void test_legacy_client_alone_sets_the_manager(void **state) {
    agent cfg;

    expect_string(__wrap__minfo, formatted_msg, ADDRESS_FALLBACK_INFO("10.0.0.1"));

    assert_int_equal(read_conf("<ossec_config><client>"
                               "<server><address>10.0.0.1</address></server>"
                               "</client></ossec_config>", &cfg), 0);

    assert_manager(&cfg, "10.0.0.1", 1517, "wazuh-manager");
    assert_null(cfg.legacy_targets);

    Free_Agent(&cfg);
}

/* No INFO line naming the legacy address, and no warning about a second <manager>. */
static void test_agent_manager_below_a_legacy_client_wins(void **state) {
    agent cfg;

    expect_string(__wrap__mwarn, formatted_msg, SKIPPED_WARNING("10.9.9.9:8443/m", "'10.0.0.1'"));

    assert_int_equal(read_conf("<ossec_config>"
                               "<client><server><address>10.0.0.1</address></server></client>"
                               "<agent><manager><endpoint>10.9.9.9:8443/m</endpoint></manager></agent>"
                               "</ossec_config>", &cfg), 0);

    assert_manager(&cfg, "10.9.9.9", 8443, "m");

    Free_Agent(&cfg);
}

static void test_agent_manager_in_a_later_root_wins(void **state) {
    agent cfg;

    expect_string(__wrap__mwarn, formatted_msg, SKIPPED_WARNING("10.9.9.9:8443/m", "'10.0.0.1'"));

    assert_int_equal(read_conf("<ossec_config>"
                               "<client><server><address>10.0.0.1</address></server></client>"
                               "</ossec_config><ossec_config>"
                               "<agent><manager><endpoint>10.9.9.9:8443/m</endpoint></manager></agent>"
                               "</ossec_config>", &cfg), 0);

    assert_manager(&cfg, "10.9.9.9", 8443, "m");

    Free_Agent(&cfg);
}

static void test_deprecated_server_hostname_below_a_legacy_client_wins(void **state) {
    agent cfg;

    expect_string(__wrap__mwarn, formatted_msg,
                  "The <server-hostname> tag is deprecated, please use <manager><endpoint> instead.");
    expect_string(__wrap__mwarn, formatted_msg,
                  SKIPPED_WARNING("manager.example:1517/wazuh-manager", "'10.0.0.1'"));

    assert_int_equal(read_conf("<ossec_config>"
                               "<client><server><address>10.0.0.1</address></server></client>"
                               "<agent><server-hostname>manager.example</server-hostname></agent>"
                               "</ossec_config>", &cfg), 0);

    /* <server-hostname> has always stored its host with a trailing '/'. */
    assert_manager(&cfg, "manager.example/", 1517, "wazuh-manager");

    Free_Agent(&cfg);
}

/* The first <client> block that names a manager decides it, as in 5.0.0. */
static void test_first_legacy_client_wins_over_a_later_one(void **state) {
    agent cfg;

    expect_string(__wrap__minfo, formatted_msg, ADDRESS_FALLBACK_INFO("10.0.0.1"));
    expect_string(__wrap__mwarn, formatted_msg,
                  DROPPED_WARNING("10.0.0.1:1517/wazuh-manager", "'10.0.0.2'"));

    assert_int_equal(read_conf("<ossec_config>"
                               "<client><server><address>10.0.0.1</address></server></client>"
                               "<client><server><address>10.0.0.2</address></server></client>"
                               "</ossec_config>", &cfg), 0);

    assert_manager(&cfg, "10.0.0.1", 1517, "wazuh-manager");

    Free_Agent(&cfg);
}

/* An <endpoint> only wins over the <address> entries of its own block. */
static void test_legacy_endpoint_in_a_later_client_is_dropped(void **state) {
    agent cfg;

    expect_string(__wrap__minfo, formatted_msg, ADDRESS_FALLBACK_INFO("10.0.0.1"));
    expect_string(__wrap__mwarn, formatted_msg,
                  DROPPED_WARNING("10.0.0.1:1517/wazuh-manager", "'10.0.0.5:8443/gw'"));

    assert_int_equal(read_conf("<ossec_config>"
                               "<client><server><address>10.0.0.1</address></server></client>"
                               "<client><server><endpoint>10.0.0.5:8443/gw</endpoint></server></client>"
                               "</ossec_config>", &cfg), 0);

    assert_manager(&cfg, "10.0.0.1", 1517, "wazuh-manager");

    Free_Agent(&cfg);
}

/* A <client> that only carries <enrollment> doesn't count as the first one. */
static void test_legacy_client_without_server_leaves_the_choice_to_the_next(void **state) {
    agent cfg;

    expect_string(__wrap__minfo, formatted_msg, ADDRESS_FALLBACK_INFO("10.0.0.2"));

    assert_int_equal(read_conf("<ossec_config>"
                               "<client><enrollment><agent_name>a</agent_name></enrollment></client>"
                               "<client><server><address>10.0.0.2</address></server></client>"
                               "</ossec_config>", &cfg), 0);

    assert_manager(&cfg, "10.0.0.2", 1517, "wazuh-manager");

    Free_Agent(&cfg);
}

/* Only the target the agent uses is parsed. */
static void test_broken_legacy_endpoint_above_an_agent_manager_is_never_parsed(void **state) {
    agent cfg;

    expect_string(__wrap__mwarn, formatted_msg,
                  SKIPPED_WARNING("10.9.9.9:8443/m", "'https://h/a//b'"));

    assert_int_equal(read_conf("<ossec_config>"
                               "<client><server><endpoint>https://h/a//b</endpoint></server></client>"
                               "<agent><manager><endpoint>10.9.9.9:8443/m</endpoint></manager></agent>"
                               "</ossec_config>", &cfg), 0);

    assert_manager(&cfg, "10.9.9.9", 8443, "m");

    Free_Agent(&cfg);
}

static void test_broken_legacy_endpoint_in_use_fails_the_read(void **state) {
    agent cfg;

    expect_string(__wrap__merror, formatted_msg,
                  "Invalid endpoint 'a//b': empty path segment (repeated '/').");
    expect_string(__wrap__merror, formatted_msg, "(1202): Configuration error at '" TEST_CONF "'.");

    assert_int_equal(read_conf("<ossec_config><client>"
                               "<server><endpoint>https://h/a//b</endpoint></server>"
                               "</client></ossec_config>", &cfg), OS_INVALID);

    assert_null(cfg.server);
    assert_null(cfg.legacy_targets);

    Free_Agent(&cfg);
}

/* A read that fails before the end of the file leaves the targets to Free_Agent(). */
static void test_targets_left_by_a_failed_read_are_freed(void **state) {
    agent cfg;

    expect_string(__wrap__merror, formatted_msg,
                  "Invalid endpoint 'a//b': empty path segment (repeated '/').");
    expect_string(__wrap__merror, formatted_msg, "(1202): Configuration error at '" TEST_CONF "'.");

    assert_int_equal(read_conf("<ossec_config>"
                               "<client><server><address>10.0.0.1</address></server></client>"
                               "<agent><manager><endpoint>https://h/a//b</endpoint></manager></agent>"
                               "</ossec_config>", &cfg), OS_INVALID);

    assert_non_null(cfg.legacy_targets);

    Free_Agent(&cfg);
    assert_null(cfg.legacy_targets);
}

/* The UX report's case: a 4.x failover list, the reachable manager listed last. */
static void test_dropped_managers_are_named_as_written(void **state) {
    agent cfg;

    expect_string(__wrap__minfo, formatted_msg, ADDRESS_FALLBACK_INFO("wazuh-server"));
    expect_string(__wrap__mwarn, formatted_msg,
                  DROPPED_WARNING("wazuh-server:1517/wazuh-manager", "'192.0.2.10'"));

    assert_int_equal(read_conf("<ossec_config><client>"
                               "<server><address>192.0.2.10</address></server>"
                               "<server><address>wazuh-server</address></server>"
                               "</client></ossec_config>", &cfg), 0);

    assert_manager(&cfg, "wazuh-server", 1517, "wazuh-manager");

    Free_Agent(&cfg);
}

static void test_one_manager_written_twice_is_not_a_drop(void **state) {
    agent cfg;

    expect_string(__wrap__minfo, formatted_msg, ADDRESS_FALLBACK_INFO("10.0.0.1"));

    assert_int_equal(read_conf("<ossec_config><client>"
                               "<server><address>10.0.0.1</address></server>"
                               "<server><address>10.0.0.1</address></server>"
                               "</client></ossec_config>", &cfg), 0);

    assert_manager(&cfg, "10.0.0.1", 1517, "wazuh-manager");

    Free_Agent(&cfg);
}

static void test_legacy_client_below_an_agent_manager_is_named(void **state) {
    agent cfg;

    expect_string(__wrap__mwarn, formatted_msg, SKIPPED_WARNING("10.9.9.9:8443/m", "'10.0.0.1'"));

    assert_int_equal(read_conf("<ossec_config>"
                               "<agent><manager><endpoint>10.9.9.9:8443/m</endpoint></manager></agent>"
                               "<client><server><address>10.0.0.1</address></server></client>"
                               "</ossec_config>", &cfg), 0);

    assert_manager(&cfg, "10.9.9.9", 8443, "m");

    Free_Agent(&cfg);
}

/* One warning for the whole file, each target named once. */
static void test_every_skipped_client_is_named_in_one_warning(void **state) {
    agent cfg;

    expect_string(__wrap__mwarn, formatted_msg,
                  SKIPPED_WARNING("10.9.9.9:8443/m", "'10.0.0.1', '10.0.0.2'"));

    assert_int_equal(read_conf("<ossec_config>"
                               "<client><server><address>10.0.0.1</address></server></client>"
                               "<agent><manager><endpoint>10.9.9.9:8443/m</endpoint></manager></agent>"
                               "<client><server><address>10.0.0.2</address></server>"
                               "<server><address>10.0.0.1</address></server></client>"
                               "</ossec_config>", &cfg), 0);

    assert_manager(&cfg, "10.9.9.9", 8443, "m");

    Free_Agent(&cfg);
}

static void test_legacy_client_without_server_beside_an_agent_says_nothing(void **state) {
    agent cfg;

    assert_int_equal(read_conf("<ossec_config>"
                               "<client><enrollment><agent_name>vm1</agent_name></enrollment></client>"
                               "<agent><manager><endpoint>10.9.9.9:8443/m</endpoint></manager></agent>"
                               "</ossec_config>", &cfg), 0);

    assert_manager(&cfg, "10.9.9.9", 8443, "m");
    assert_string_equal(cfg.enrollment.agent_name, "vm1");

    Free_Agent(&cfg);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_legacy_client_alone_sets_the_manager),
        cmocka_unit_test(test_agent_manager_below_a_legacy_client_wins),
        cmocka_unit_test(test_agent_manager_in_a_later_root_wins),
        cmocka_unit_test(test_deprecated_server_hostname_below_a_legacy_client_wins),
        cmocka_unit_test(test_first_legacy_client_wins_over_a_later_one),
        cmocka_unit_test(test_legacy_endpoint_in_a_later_client_is_dropped),
        cmocka_unit_test(test_legacy_client_without_server_leaves_the_choice_to_the_next),
        cmocka_unit_test(test_broken_legacy_endpoint_above_an_agent_manager_is_never_parsed),
        cmocka_unit_test(test_broken_legacy_endpoint_in_use_fails_the_read),
        cmocka_unit_test(test_targets_left_by_a_failed_read_are_freed),
        cmocka_unit_test(test_dropped_managers_are_named_as_written),
        cmocka_unit_test(test_one_manager_written_twice_is_not_a_drop),
        cmocka_unit_test(test_legacy_client_below_an_agent_manager_is_named),
        cmocka_unit_test(test_every_skipped_client_is_named_in_one_warning),
        cmocka_unit_test(test_legacy_client_without_server_beside_an_agent_says_nothing),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
