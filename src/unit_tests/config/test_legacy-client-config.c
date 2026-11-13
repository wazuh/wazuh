/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Which manager an upgraded agent uses when its legacy 4.x <client> block names more
 * than one, and the warning that names the ones it drops (#41415). */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

#include "shared.h"
#include "os_xml.h"
#include "client-config.h"
#include "config.h"
#include "legacy-server-targets.h"
#include "client_config_test_helpers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* What the agent dials for a bare <address>: the 5.x port and the default prefix. */
#define DIALED(ip) ip ":1517/wazuh-manager"

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

/* The list buffer in legacy-server-targets.c, and what DIALED() adds to an address. */
#define LIST_SIZE 1024
#define DIALED_SUFFIX (sizeof(":1517/wazuh-manager") - 1)

/* Reads one root's <client> and <agent> blocks in file order, as ReadConfig() does. */
static int read_root(OS_XML *xml, xml_node *root, agent *cfg) {
    xml_node **blocks = OS_GetElementsbyNode(xml, root);
    int ret = 0;

    for (int i = 0; blocks && blocks[i] && ret == 0; i++) {
        xml_node **children = OS_GetElementsbyNode(xml, blocks[i]);

        if (strcmp(blocks[i]->element, "client") == 0) {
            ret = Read_Legacy_Client(xml, children, cfg, NULL);
        } else if (strcmp(blocks[i]->element, "agent") == 0) {
            ret = Read_Agent(xml, children, cfg, NULL);
        }

        OS_ClearNode(children);
    }

    OS_ClearNode(blocks);
    return ret;
}

/* Reads a whole document, every <ossec_config> root in turn, into the same struct. The
 * library is built for the agent, so its root is "ossec_config" whatever this file's
 * WAZUHCONFIG says. */
static int read_document(const char *xml_str, OS_XML *xml, agent *cfg) {
    xml_node **roots = NULL;
    int ret = parse_xml_block(xml_str, xml, &roots);

    for (int i = 0; ret == 0 && roots[i]; i++) {
        ret = read_root(xml, roots[i], cfg);
    }

    OS_ClearNode(roots);
    return ret;
}

static void add_values(w_legacy_targets_t *targets, int count, size_t length, char first) {
    char value[LIST_SIZE + 128];

    for (int i = 0; i < count; i++) {
        memset(value, first + (i % 26), length);
        value[length] = '\0';
        w_legacy_targets_add(targets, value, false);
    }
}

/* w_legacy_targets_t */

static void test_targets_chosen_is_false_when_empty(void **state) {
    w_legacy_targets_t targets = {0};
    size_t index = 99;

    assert_false(w_legacy_targets_chosen(&targets, &index));
    assert_int_equal(index, 99);
}

static void test_targets_chosen_is_the_last_address(void **state) {
    w_legacy_targets_t targets = {0};
    size_t index = 0;

    w_legacy_targets_add(&targets, "10.0.0.1", false);
    w_legacy_targets_add(&targets, "10.0.0.2", false);

    assert_true(w_legacy_targets_chosen(&targets, &index));
    assert_string_equal(targets.items[index].value, "10.0.0.2");

    w_legacy_targets_free(&targets);
}

static void test_targets_chosen_prefers_the_last_endpoint_wherever_it_is(void **state) {
    w_legacy_targets_t targets = {0};
    size_t index = 0;

    w_legacy_targets_add(&targets, "10.0.0.5:8443", true);
    w_legacy_targets_add(&targets, "10.0.0.6:8443", true);
    w_legacy_targets_add(&targets, "10.0.0.1", false);

    assert_true(w_legacy_targets_chosen(&targets, &index));
    assert_int_equal(index, 1);

    w_legacy_targets_free(&targets);
}

/* Each target is named as the agent dials it; an endpoint that doesn't parse keeps its
 * raw text, and parsing it logs nothing. */
static void test_targets_add_fills_what_the_agent_dials(void **state) {
    w_legacy_targets_t targets = {0};

    w_legacy_targets_add(&targets, "10.0.0.1", false);
    w_legacy_targets_add(&targets, "10.0.0.5:8443/gateway", true);
    w_legacy_targets_add(&targets, "10.0.0.6", true);
    w_legacy_targets_add(&targets, "ftp://10.0.0.9", true);
    w_legacy_targets_add(&targets, "::1", false);

    assert_string_equal(targets.items[0].dialed, DIALED("10.0.0.1"));
    assert_string_equal(targets.items[1].dialed, "10.0.0.5:8443/gateway");
    assert_string_equal(targets.items[2].dialed, DIALED("10.0.0.6"));
    assert_string_equal(targets.items[3].dialed, "ftp://10.0.0.9");
    assert_string_equal(targets.items[4].dialed, "[0000:0000:0000:0000:0000:0000:0000:0001]:1517/wazuh-manager");

    w_legacy_targets_free(&targets);
}

static void test_targets_warn_ignored_names_every_other_target(void **state) {
    w_legacy_targets_t targets = {0};

    w_legacy_targets_add(&targets, "10.0.0.1", false);
    w_legacy_targets_add(&targets, "10.0.0.2", false);
    w_legacy_targets_add(&targets, "10.0.0.3", false);

    expect_string(__wrap__mwarn, formatted_msg,
                  DROPPED_WARNING(DIALED("10.0.0.3"), "'" DIALED("10.0.0.1") "', '" DIALED("10.0.0.2") "'"));

    w_legacy_targets_warn_ignored(&targets, 2);

    w_legacy_targets_free(&targets);
}

/* The same manager written twice, or as an <address> and the <endpoint> it stands for,
 * or as a short and an expanded IPv6 address: one manager, nothing to warn about. */
static void test_targets_warn_ignored_skips_repeats_of_the_chosen_one(void **state) {
    w_legacy_targets_t targets = {0};

    w_legacy_targets_add(&targets, "10.0.0.1", false);
    w_legacy_targets_add(&targets, "10.0.0.1", false);
    w_legacy_targets_add(&targets, DIALED("10.0.0.1"), true);
    w_legacy_targets_warn_ignored(&targets, 2);
    w_legacy_targets_free(&targets);

    w_legacy_targets_add(&targets, "::1", false);
    w_legacy_targets_add(&targets, "0:0:0:0:0:0:0:1", false);
    w_legacy_targets_warn_ignored(&targets, 1);
    w_legacy_targets_free(&targets);
}

/* The same dropped manager written twice is named once. */
static void test_targets_warn_ignored_names_a_repeated_value_once(void **state) {
    w_legacy_targets_t targets = {0};

    w_legacy_targets_add(&targets, "10.0.0.1", false);
    w_legacy_targets_add(&targets, DIALED("10.0.0.1"), true);
    w_legacy_targets_add(&targets, "10.0.0.2", false);

    expect_string(__wrap__mwarn, formatted_msg,
                  DROPPED_WARNING(DIALED("10.0.0.2"), "'" DIALED("10.0.0.1") "'"));
    w_legacy_targets_warn_ignored(&targets, 2);
    w_legacy_targets_free(&targets);
}

/* An empty value is still a target the agent drops, and is named as such. */
static void test_targets_warn_ignored_names_an_empty_value(void **state) {
    w_legacy_targets_t targets = {0};

    w_legacy_targets_add(&targets, "", true);
    w_legacy_targets_add(&targets, "10.0.0.1", false);

    expect_string(__wrap__mwarn, formatted_msg, DROPPED_WARNING(DIALED("10.0.0.1"), "''"));
    w_legacy_targets_warn_ignored(&targets, 1);
    w_legacy_targets_free(&targets);
}

/* The list after "ignoring " is bounded by the 1024-byte buffer, and when values were left
 * out it ends in the whole cut mark ", ...", followed by the sentence's ".". */
static int check_cut_list(const LargestIntegralType value, const LargestIntegralType check_data) {
    const char *msg = (const char *)value;
    const char *list = strstr(msg, "ignoring ");
    const size_t len = list ? strlen(list += strlen("ignoring ")) : 0;

    (void)check_data;
    return list && len > 6 && len - 1 < LIST_SIZE && strcmp(list + len - 6, ", ....") == 0;
}

/* Whatever the value length, a cut list ends in the whole ", ..." and fits its buffer. */
static void test_targets_warn_ignored_cut_mark_is_always_whole(void **state) {
    for (size_t length = 1; length <= 80; length++) {
        w_legacy_targets_t targets = {0};
        const size_t dialed = length + DIALED_SUFFIX;

        add_values(&targets, 10, length, 'a');
        w_legacy_targets_add(&targets, "10.0.0.9", false);
        add_values(&targets, 10, length + 1, 'a');

        /* Every value but the first carries ", ", and the list keeps 6 bytes free. */
        if (10 * (dialed + 4) + 10 * (dialed + 5) - 2 > LIST_SIZE - 6) {
            expect_check(__wrap__mwarn, formatted_msg, check_cut_list, NULL);
        } else {
            expect_any(__wrap__mwarn, formatted_msg);
        }

        w_legacy_targets_warn_ignored(&targets, 10);
        w_legacy_targets_free(&targets);
    }
}

/* Twenty short targets fit, and are all named in order. */
static void test_targets_warn_ignored_lists_everything_that_fits(void **state) {
    char expected[LIST_SIZE * 2] = "The legacy <client> block names more than one manager, and only one "
                                   "is supported. Using '" DIALED("10.0.1.1") "', ignoring ";
    char address[16];
    w_legacy_targets_t targets = {0};

    for (int i = 1; i <= 20; i++) {
        snprintf(address, sizeof(address), "10.0.0.%d", i);
        w_legacy_targets_add(&targets, address, false);
        snprintf(expected + strlen(expected), sizeof(expected) - strlen(expected),
                 "%s'%s'", (i > 1) ? ", " : "", targets.items[i - 1].dialed);
    }

    w_legacy_targets_add(&targets, "10.0.1.1", false);
    strcat(expected, ".");

    expect_string(__wrap__mwarn, formatted_msg, expected);
    w_legacy_targets_warn_ignored(&targets, 20);
    w_legacy_targets_free(&targets);
}

/* The longest value that fits is listed whole; one byte more and it is left out. */
static void test_targets_warn_ignored_fills_the_list_exactly(void **state) {
    char expected[LIST_SIZE + 256];
    w_legacy_targets_t targets = {0};

    add_values(&targets, 1, LIST_SIZE - 8 - DIALED_SUFFIX, 'x');
    w_legacy_targets_add(&targets, "10.0.0.1", false);

    snprintf(expected, sizeof(expected), DROPPED_WARNING(DIALED("10.0.0.1"), "'%s'"), targets.items[0].dialed);
    expect_string(__wrap__mwarn, formatted_msg, expected);
    w_legacy_targets_warn_ignored(&targets, 1);
    w_legacy_targets_free(&targets);

    add_values(&targets, 1, LIST_SIZE - 7 - DIALED_SUFFIX, 'x');
    w_legacy_targets_add(&targets, "10.0.0.1", false);

    expect_string(__wrap__mwarn, formatted_msg, DROPPED_WARNING(DIALED("10.0.0.1"), "..."));
    w_legacy_targets_warn_ignored(&targets, 1);
    w_legacy_targets_free(&targets);
}

/* Two values that fill the list exactly, separator included; one byte more and the
 * second is left out. */
static void test_targets_warn_ignored_fills_the_list_exactly_with_two(void **state) {
    char expected[LIST_SIZE + 256];
    const size_t first = 480;
    /* '<first>', '<second>' must take the 1018 bytes the cut mark leaves. */
    const size_t second = LIST_SIZE - 6 - 6 - 2 * DIALED_SUFFIX - first;
    w_legacy_targets_t targets = {0};

    add_values(&targets, 1, first, 'x');
    add_values(&targets, 1, second, 'y');
    w_legacy_targets_add(&targets, "10.0.0.1", false);

    snprintf(expected, sizeof(expected), DROPPED_WARNING(DIALED("10.0.0.1"), "'%s', '%s'"),
             targets.items[0].dialed, targets.items[1].dialed);
    expect_string(__wrap__mwarn, formatted_msg, expected);
    w_legacy_targets_warn_ignored(&targets, 2);
    w_legacy_targets_free(&targets);

    add_values(&targets, 1, first, 'x');
    add_values(&targets, 1, second + 1, 'y');
    w_legacy_targets_add(&targets, "10.0.0.1", false);

    snprintf(expected, sizeof(expected), DROPPED_WARNING(DIALED("10.0.0.1"), "'%s', ..."), targets.items[0].dialed);
    expect_string(__wrap__mwarn, formatted_msg, expected);
    w_legacy_targets_warn_ignored(&targets, 2);
    w_legacy_targets_free(&targets);
}

/* A value too long to list does not hide the ones after it. */
static void test_targets_warn_ignored_keeps_listing_after_a_long_value(void **state) {
    w_legacy_targets_t targets = {0};

    add_values(&targets, 1, 1100, 'a');
    w_legacy_targets_add(&targets, "10.0.0.2", false);
    w_legacy_targets_add(&targets, "10.0.0.3", false);

    expect_string(__wrap__mwarn, formatted_msg,
                  DROPPED_WARNING(DIALED("10.0.0.3"), "'" DIALED("10.0.0.2") "', ..."));
    w_legacy_targets_warn_ignored(&targets, 2);
    w_legacy_targets_free(&targets);
}

/* The manager in use, written the way a skipped block spells it, is not named as ignored. */
static void test_targets_warn_skipped_is_silent_for_the_manager_in_use(void **state) {
    w_legacy_targets_t targets = {0};
    w_legacy_targets_t empty = {0};
    char rip[IPSIZE + 1] = "fd00::1";
    agent_server address = {.rip = "10.0.0.5", .port = 1517, .endpoint = "wazuh-manager"};
    agent_server endpoint = {.rip = "10.0.0.5", .port = 8443, .endpoint = "gateway"};
    agent_server ipv6 = {.rip = rip, .port = 1517, .endpoint = "wazuh-manager"};

    OS_ExpandIPv6(rip, IPSIZE);

    w_legacy_targets_add(&targets, "10.0.0.5", false);
    w_legacy_targets_warn_skipped(&targets, &address);
    w_legacy_targets_warn_skipped(&empty, &address);
    w_legacy_targets_free(&targets);

    w_legacy_targets_add(&targets, "10.0.0.5:8443/gateway", true);
    w_legacy_targets_warn_skipped(&targets, &endpoint);
    w_legacy_targets_free(&targets);

    w_legacy_targets_add(&targets, "fd00::1", false);
    w_legacy_targets_add(&targets, "[fd00::1]:1517/wazuh-manager", true);
    w_legacy_targets_warn_skipped(&targets, &ipv6);
    w_legacy_targets_free(&targets);
}

/* Hostname case, and short forms the URL parser rewrites, don't make two managers. */
static void test_targets_warn_ignored_folds_what_does_not_change_the_peer(void **state) {
    w_legacy_targets_t targets = {0};

    w_legacy_targets_add(&targets, "Manager.Example", false);
    w_legacy_targets_add(&targets, "manager.example", true);
    w_legacy_targets_warn_ignored(&targets, 1);
    w_legacy_targets_free(&targets);

    w_legacy_targets_add(&targets, "127.1", false);
    w_legacy_targets_add(&targets, "127.0.0.1", true);
    w_legacy_targets_warn_ignored(&targets, 1);
    w_legacy_targets_free(&targets);

    /* The prefix is a path: its case does make a different target. */
    w_legacy_targets_add(&targets, "10.0.0.1:1517/Wazuh-Manager", true);
    w_legacy_targets_add(&targets, "10.0.0.1", false);
    expect_string(__wrap__mwarn, formatted_msg,
                  DROPPED_WARNING("10.0.0.1:1517/Wazuh-Manager", "'" DIALED("10.0.0.1") "'"));
    w_legacy_targets_warn_ignored(&targets, 0);
    w_legacy_targets_free(&targets);
}

/* The same link-local address on two interfaces is two managers, and is named with its zone. */
static void test_targets_warn_ignored_keeps_the_ipv6_zone(void **state) {
    w_legacy_targets_t targets = {0};

    w_legacy_targets_add(&targets, "[fe80::1%251]:1517", true);
    w_legacy_targets_add(&targets, "[fe80::1%252]:1517", true);

    expect_string(__wrap__mwarn, formatted_msg,
                  DROPPED_WARNING("[FE80:0000:0000:0000:0000:0000:0000:0001%2]:1517/wazuh-manager",
                                  "'[FE80:0000:0000:0000:0000:0000:0000:0001%1]:1517/wazuh-manager'"));
    w_legacy_targets_warn_ignored(&targets, 1);
    w_legacy_targets_free(&targets);
}

/* Naming a dropped <endpoint> never logs why it is invalid, whichever check refuses it:
 * the prefix, the zone, or the URL itself. An unexpected merror() fails the test. */
static void test_targets_add_never_logs_a_refused_endpoint(void **state) {
    w_legacy_targets_t targets = {0};

    w_legacy_targets_add(&targets, "10.0.0.1/a//b", true);
    w_legacy_targets_add(&targets, "[fe80::1%25nosuchif0]:1517", true);
    w_legacy_targets_add(&targets, "ftp://10.0.0.9", true);

    assert_string_equal(targets.items[0].dialed, "10.0.0.1/a//b");
    assert_string_equal(targets.items[1].dialed, "[fe80::1%25nosuchif0]:1517");

    w_legacy_targets_free(&targets);
}

/* An <endpoint> with the "/" opt-out is unprefixed; the in-use entry stores that as no
 * endpoint, and the two must still match. A default-prefix target is a different one. */
static void test_targets_warn_skipped_matches_an_unprefixed_manager(void **state) {
    w_legacy_targets_t targets = {0};
    agent_server in_use = {.rip = "10.0.0.5", .port = 1517, .endpoint = NULL};

    w_legacy_targets_add(&targets, "10.0.0.5:1517/", true);
    w_legacy_targets_warn_skipped(&targets, &in_use);
    w_legacy_targets_free(&targets);

    w_legacy_targets_add(&targets, "10.0.0.5", false);
    expect_string(__wrap__mwarn, formatted_msg, SKIPPED_WARNING("10.0.0.5:1517/", "'" DIALED("10.0.0.5") "'"));
    w_legacy_targets_warn_skipped(&targets, &in_use);
    w_legacy_targets_free(&targets);
}

/* Read_Legacy_Client() */

/* What the MSI leaves when it is given a token: it rewrites the first <server> only. */
static void test_legacy_client_endpoint_wins_over_a_later_address(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg = {0};

    expect_string(__wrap__mwarn, formatted_msg,
                  DROPPED_WARNING("10.0.0.5:8443/gateway", "'" DIALED("10.0.0.1") "'"));

    assert_int_equal(parse_legacy_client("<server><endpoint>10.0.0.5:8443/gateway</endpoint></server>"
                                         "<server><address>10.0.0.1</address></server>",
                                         &xml, &nodes, &cfg), 0);

    assert_string_equal(cfg.server[0].rip, "10.0.0.5");
    assert_int_equal(cfg.server[0].port, 8443);
    assert_string_equal(cfg.server[0].endpoint, "gateway");

    Free_Agent(&cfg);
    clear_xml_block(&xml, nodes);
}

static void test_legacy_client_endpoint_wins_inside_one_server(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg = {0};

    expect_string(__wrap__mwarn, formatted_msg, DROPPED_WARNING(DIALED("10.0.0.5"), "'" DIALED("10.0.0.1") "'"));

    assert_int_equal(parse_legacy_client("<server><address>10.0.0.1</address>"
                                         "<endpoint>10.0.0.5</endpoint></server>",
                                         &xml, &nodes, &cfg), 0);

    assert_string_equal(cfg.server[0].rip, "10.0.0.5");

    Free_Agent(&cfg);
    clear_xml_block(&xml, nodes);
}

/* Only the target in use is parsed, so a broken one that is dropped cannot stop the agent. */
static void test_legacy_client_dropped_endpoint_is_not_parsed(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg = {0};

    expect_string(__wrap__mwarn, formatted_msg,
                  DROPPED_WARNING(DIALED("10.0.0.5"), "'ftp://10.0.0.9'"));

    assert_int_equal(parse_legacy_client("<server><endpoint>ftp://10.0.0.9</endpoint></server>"
                                         "<server><endpoint>10.0.0.5</endpoint></server>",
                                         &xml, &nodes, &cfg), 0);

    assert_string_equal(cfg.server[0].rip, "10.0.0.5");

    Free_Agent(&cfg);
    clear_xml_block(&xml, nodes);
}


/* A second <client> block reads the same way as a second <agent><manager>: it does not
 * replace the first one, and now says so. */
static void test_second_legacy_client_server_is_ignored_with_warning(void **state) {
    OS_XML first_xml = {0};
    OS_XML second_xml = {0};
    xml_node **first_nodes;
    xml_node **second_nodes;
    agent cfg = {0};

    expect_string(__wrap__minfo, formatted_msg, ADDRESS_FALLBACK_INFO("10.0.0.1"));
    expect_string(__wrap__mwarn, formatted_msg,
                  SKIPPED_WARNING(DIALED("10.0.0.1"), "'" DIALED("10.0.0.2") "'"));

    assert_int_equal(parse_legacy_client("<server><address>10.0.0.1</address></server>",
                                         &first_xml, &first_nodes, &cfg), 0);
    assert_int_equal(parse_legacy_client("<server><address>10.0.0.2</address></server>",
                                         &second_xml, &second_nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.1");

    Free_Agent(&cfg);
    clear_xml_block(&first_xml, first_nodes);
    clear_xml_block(&second_xml, second_nodes);
}


/* No <server> in the later block, nothing dropped: no warning. */
static void test_legacy_client_without_server_after_agent_does_not_warn(void **state) {
    OS_XML agent_xml = {0};
    OS_XML legacy_xml = {0};
    xml_node **agent_nodes;
    xml_node **legacy_nodes;
    agent cfg = {0};

    assert_int_equal(parse_agent_into("<manager><endpoint>10.0.0.5:1600</endpoint></manager>",
                                 &agent_xml, &agent_nodes, &cfg), 0);
    assert_int_equal(parse_legacy_client("<enrollment><agent_name>vm</agent_name></enrollment>",
                                         &legacy_xml, &legacy_nodes, &cfg), 0);

    assert_string_equal(cfg.enrollment.agent_name, "vm");

    Free_Agent(&cfg);
    clear_xml_block(&agent_xml, agent_nodes);
    clear_xml_block(&legacy_xml, legacy_nodes);
}

/* <client> before <agent><manager> in the same file: <agent> sets the manager, so the
 * legacy block waits for it and then says it is ignored, naming the manager <agent> set. */
static void test_legacy_client_before_agent_is_ignored_with_warning(void **state) {
    OS_XML xml = {0};
    agent cfg = {0};

    expect_string(__wrap__mwarn, formatted_msg,
                  SKIPPED_WARNING("10.0.0.5:1600/wazuh-manager",
                                  "'" DIALED("10.0.0.1") "', '" DIALED("10.0.0.2") "'"));

    assert_int_equal(read_document("<ossec_config>"
                                   "<client><server><address>10.0.0.1</address></server>"
                                   "<server><address>10.0.0.2</address></server></client>"
                                   "<agent><manager><endpoint>10.0.0.5:1600</endpoint></manager></agent>"
                                   "</ossec_config>", &xml, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.5");
    assert_int_equal(cfg.server[0].port, 1600);

    Free_Agent(&cfg);
    OS_ClearXML(&xml);
}

/* Without an <agent><manager>, a whole document reads the legacy block as before. */
static void test_legacy_client_alone_in_a_document_is_used(void **state) {
    OS_XML xml = {0};
    agent cfg = {0};

    expect_string(__wrap__minfo, formatted_msg, ADDRESS_FALLBACK_INFO("10.0.0.2"));
    expect_string(__wrap__mwarn, formatted_msg,
                  DROPPED_WARNING(DIALED("10.0.0.2"), "'" DIALED("10.0.0.1") "'"));

    assert_int_equal(read_document("<ossec_config>"
                                   "<client><server><address>10.0.0.1</address></server>"
                                   "<server><address>10.0.0.2</address></server></client>"
                                   "<agent><notify_time>10</notify_time></agent>"
                                   "</ossec_config>", &xml, &cfg), 0);

    assert_string_equal(cfg.server[0].rip, "10.0.0.2");

    Free_Agent(&cfg);
    OS_ClearXML(&xml);
}


/* The manager <agent> sets is one of the legacy targets: it is named as the one in use, not
 * among the ignored ones. */
static void test_legacy_client_before_agent_names_the_shared_manager_once(void **state) {
    OS_XML xml = {0};
    agent cfg = {0};

    expect_string(__wrap__mwarn, formatted_msg,
                  SKIPPED_WARNING(DIALED("10.0.0.2"), "'" DIALED("10.0.0.1") "'"));

    assert_int_equal(read_document("<ossec_config>"
                                   "<client><server><address>10.0.0.1</address></server>"
                                   "<server><address>10.0.0.2</address></server></client>"
                                   "<agent><manager><endpoint>10.0.0.2:1517</endpoint></manager></agent>"
                                   "</ossec_config>", &xml, &cfg), 0);

    assert_string_equal(cfg.server[0].rip, "10.0.0.2");

    Free_Agent(&cfg);
    OS_ClearXML(&xml);
}

/* Every Linux package writes a second root for <localfile>; an <agent><manager> added
 * there still sets the manager, and the legacy block above it says so. */
static void test_legacy_client_sees_an_agent_manager_in_a_second_root(void **state) {
    OS_XML xml = {0};
    agent cfg = {0};

    expect_string(__wrap__mwarn, formatted_msg,
                  SKIPPED_WARNING("10.9.9.9:1517/wazuh-manager",
                                  "'" DIALED("10.0.0.1") "', '" DIALED("10.0.0.2") "'"));

    assert_int_equal(read_document("<ossec_config>"
                                   "<client><server><address>10.0.0.1</address></server>"
                                   "<server><address>10.0.0.2</address></server></client>"
                                   "</ossec_config>"
                                   "<ossec_config>"
                                   "<agent><manager><endpoint>10.9.9.9:1517</endpoint></manager></agent>"
                                   "</ossec_config>", &xml, &cfg), 0);

    assert_string_equal(cfg.server[0].rip, "10.9.9.9");

    Free_Agent(&cfg);
    OS_ClearXML(&xml);
}

/* An <agent> without <manager> before the one that has it doesn't hide it. */
static void test_legacy_client_sees_an_agent_manager_after_another_agent(void **state) {
    OS_XML xml = {0};
    agent cfg = {0};

    expect_string(__wrap__mwarn, formatted_msg,
                  SKIPPED_WARNING("10.9.9.9:1517/wazuh-manager", "'" DIALED("10.0.0.1") "'"));

    assert_int_equal(read_document("<ossec_config>"
                                   "<client><server><address>10.0.0.1</address></server></client>"
                                   "<agent><notify_time>10</notify_time></agent>"
                                   "<agent><manager><endpoint>10.9.9.9:1517</endpoint></manager></agent>"
                                   "</ossec_config>", &xml, &cfg), 0);

    assert_string_equal(cfg.server[0].rip, "10.9.9.9");

    Free_Agent(&cfg);
    OS_ClearXML(&xml);
}

/* With two <agent><manager> blocks after the legacy one, the warning waits for the last,
 * which is the one the agent keeps. */
static void test_legacy_client_waits_for_the_last_agent_manager(void **state) {
    OS_XML xml = {0};
    agent cfg = {0};

    expect_string(__wrap__mwarn, formatted_msg, "Only one <manager> block is supported; the last one prevails.");
    expect_string(__wrap__mwarn, formatted_msg,
                  SKIPPED_WARNING("10.9.9.2:1517/wazuh-manager", "'" DIALED("10.0.0.1") "'"));

    assert_int_equal(read_document("<ossec_config>"
                                   "<client><server><address>10.0.0.1</address></server></client>"
                                   "<agent><manager><endpoint>10.9.9.1:1517</endpoint></manager></agent>"
                                   "<agent><manager><endpoint>10.9.9.2:1517</endpoint></manager></agent>"
                                   "</ossec_config>", &xml, &cfg), 0);

    assert_string_equal(cfg.server[0].rip, "10.9.9.2");

    Free_Agent(&cfg);
    OS_ClearXML(&xml);
}

/* A read that fails before the <agent><manager> releases the waiting targets. */
static void test_legacy_client_deferred_targets_are_freed_on_a_failed_read(void **state) {
    OS_XML xml = {0};
    agent cfg = {0};

    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(read_document("<ossec_config>"
                                   "<client><server><address>10.0.0.1</address></server></client>"
                                   "<agent><manager><endpoint>ftp://10.9.9.9</endpoint></manager></agent>"
                                   "</ossec_config>", &xml, &cfg), OS_INVALID);

    assert_non_null(cfg.legacy_deferred);
    Free_Agent(&cfg);
    assert_null(cfg.legacy_deferred);
    OS_ClearXML(&xml);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_targets_chosen_is_false_when_empty),
        cmocka_unit_test(test_targets_chosen_is_the_last_address),
        cmocka_unit_test(test_targets_chosen_prefers_the_last_endpoint_wherever_it_is),
        cmocka_unit_test(test_targets_add_fills_what_the_agent_dials),
        cmocka_unit_test(test_targets_warn_ignored_names_every_other_target),
        cmocka_unit_test(test_targets_warn_ignored_skips_repeats_of_the_chosen_one),
        cmocka_unit_test(test_targets_warn_ignored_names_a_repeated_value_once),
        cmocka_unit_test(test_targets_warn_ignored_names_an_empty_value),
        cmocka_unit_test(test_targets_warn_ignored_cut_mark_is_always_whole),
        cmocka_unit_test(test_targets_warn_ignored_lists_everything_that_fits),
        cmocka_unit_test(test_targets_warn_ignored_fills_the_list_exactly),
        cmocka_unit_test(test_targets_warn_ignored_fills_the_list_exactly_with_two),
        cmocka_unit_test(test_targets_warn_ignored_keeps_listing_after_a_long_value),
        cmocka_unit_test(test_targets_warn_skipped_is_silent_for_the_manager_in_use),
        cmocka_unit_test(test_legacy_client_endpoint_wins_over_a_later_address),
        cmocka_unit_test(test_legacy_client_endpoint_wins_inside_one_server),
        cmocka_unit_test(test_legacy_client_dropped_endpoint_is_not_parsed),
        cmocka_unit_test(test_second_legacy_client_server_is_ignored_with_warning),
        cmocka_unit_test(test_legacy_client_without_server_after_agent_does_not_warn),
        cmocka_unit_test(test_legacy_client_before_agent_is_ignored_with_warning),
        cmocka_unit_test(test_legacy_client_alone_in_a_document_is_used),
        cmocka_unit_test(test_targets_warn_ignored_folds_what_does_not_change_the_peer),
        cmocka_unit_test(test_targets_warn_ignored_keeps_the_ipv6_zone),
        cmocka_unit_test(test_targets_add_never_logs_a_refused_endpoint),
        cmocka_unit_test(test_targets_warn_skipped_matches_an_unprefixed_manager),
        cmocka_unit_test(test_legacy_client_before_agent_names_the_shared_manager_once),
        cmocka_unit_test(test_legacy_client_sees_an_agent_manager_in_a_second_root),
        cmocka_unit_test(test_legacy_client_sees_an_agent_manager_after_another_agent),
        cmocka_unit_test(test_legacy_client_waits_for_the_last_agent_manager),
        cmocka_unit_test(test_legacy_client_deferred_targets_are_freed_on_a_failed_read),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
