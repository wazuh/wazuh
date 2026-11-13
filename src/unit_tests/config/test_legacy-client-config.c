/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Which manager an upgraded agent uses when its legacy 4.x <client> block names more
 * than one (#41415). */

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
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#define ADDRESS_FALLBACK_INFO(ip)                                                                \
    "<agent><manager><endpoint> is not configured. Using <client><server><address> '" ip "' "  \
    "with the default port 1517 and the default endpoint prefix 'wazuh-manager'. Replace the " \
    "<client><server> block with a single <endpoint>" ip ":1517/wazuh-manager</endpoint>"

static int parse_block(const char *xml_str, OS_XML *xml, xml_node ***nodes) {
    if (OS_ReadXMLString(xml_str, xml) != 0) {
        return OS_INVALID;
    }

    return (*nodes = OS_GetElementsbyNode(xml, NULL)) ? 0 : OS_INVALID;
}

/* Parses `xml_str` as the body of a legacy <client>...</client> into cfg, which is not
 * reset, so it can run after another block was read into the same struct. */
static int parse_legacy_client(const char *xml_str, OS_XML *xml, xml_node ***nodes, agent *cfg) {
    if (parse_block(xml_str, xml, nodes) != 0) {
        return OS_INVALID;
    }

    return Read_Legacy_Client(xml, *nodes, cfg, NULL);
}

static void clear_block(OS_XML *xml, xml_node **nodes) {
    OS_ClearNode(nodes);
    OS_ClearXML(xml);
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

/* Read_Legacy_Client() */

static void test_legacy_client_single_address_does_not_warn(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg = {0};

    expect_string(__wrap__minfo, formatted_msg, ADDRESS_FALLBACK_INFO("10.0.0.1"));

    assert_int_equal(parse_legacy_client("<server><address>10.0.0.1</address></server>",
                                         &xml, &nodes, &cfg), 0);

    Free_Agent(&cfg);
    clear_block(&xml, nodes);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_targets_chosen_is_false_when_empty),
        cmocka_unit_test(test_targets_chosen_is_the_last_address),
        cmocka_unit_test(test_targets_chosen_prefers_the_last_endpoint_wherever_it_is),
        cmocka_unit_test(test_legacy_client_single_address_does_not_warn),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
