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
#include <stdlib.h>

#include "../../remoted/remoted.h"
#include "../../headers/shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

int w_remoted_get_net_protocol(const char * content);

void w_remoted_parse_agents(XML_NODE node, remoted * logr);


/* setup/teardown */


/* wraps */


/* tests */

// Test w_remoted_get_net_protocol

void test_w_remoted_get_net_protocol_content_NULL(void **state)
{
    const char * content = NULL;

    expect_string(__wrap__mwarn, formatted_msg, "(9000): Error getting protocol. Default value (TCP) will be used.");

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, REMOTED_NET_PROTOCOL_DEFAULT);

}

void test_w_remoted_get_net_protocol_content_empty(void **state)
{
    const char * content = "";

    expect_string(__wrap__mwarn, formatted_msg, "(9001): Ignored invalid value '' for 'protocol'.");

    expect_string(__wrap__mwarn, formatted_msg, "(9000): Error getting protocol. Default value (TCP) will be used.");

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, REMOTED_NET_PROTOCOL_DEFAULT);

}

void test_w_remoted_get_net_protocol_content_ignore_values(void **state)
{
    const char * content = "hello, world";

    expect_string(__wrap__mwarn, formatted_msg, "(9001): Ignored invalid value 'hello' for 'protocol'.");

    expect_string(__wrap__mwarn, formatted_msg, "(9001): Ignored invalid value 'world' for 'protocol'.");

    expect_string(__wrap__mwarn, formatted_msg, "(9000): Error getting protocol. Default value (TCP) will be used.");

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, REMOTED_NET_PROTOCOL_DEFAULT);

}

void test_w_remoted_get_net_protocol_content_tcp(void **state)
{
    const char * content = "tcp";

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, 1);

}

void test_w_remoted_get_net_protocol_content_udp(void **state)
{
    const char * content = "udp";

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, 2);

}

void test_w_remoted_get_net_protocol_content_tcp_udp(void **state)
{
    const char * content = "tcp,udp";

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, 3);

}

void test_w_remoted_get_net_protocol_content_udp_tcp(void **state)
{
    const char * content = "udp, tcp";

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, 3);

}

void test_w_remoted_get_net_protocol_content_mix(void **state)
{
    const char * content = "hello, tcp, , world, udp";

    expect_string(__wrap__mwarn, formatted_msg, "(9001): Ignored invalid value 'hello' for 'protocol'.");

    expect_string(__wrap__mwarn, formatted_msg, "(9001): Ignored invalid value '' for 'protocol'.");

    expect_string(__wrap__mwarn, formatted_msg, "(9001): Ignored invalid value 'world' for 'protocol'.");

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, 3);

}

// Test w_remoted_parse_agents

remoted logr = {0};

static void test_w_remoted_parse_agents_no(void **state) {
    logr.allow_higher_versions = REMOTED_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT;
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("allow_higher_versions", node[0]->element);
    os_strdup("no", node[0]->content);
    node[1] = NULL;

    w_remoted_parse_agents(node, &logr);
    assert_false(logr.allow_higher_versions);

    os_free(node[0]->element);
    os_free(node[0]->content);
    os_free(node[0]);
    os_free(node);
}

static void test_w_remoted_parse_agents_yes(void **state) {
    logr.allow_higher_versions = REMOTED_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT;
    XML_NODE node;

    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("allow_higher_versions", node[0]->element);
    os_strdup("yes", node[0]->content);
    node[1] = NULL;

    w_remoted_parse_agents(node, &logr);
    assert_true(logr.allow_higher_versions);

    os_free(node[0]->element);
    os_free(node[0]->content);
    os_free(node[0]);
    os_free(node);
}

static void test_w_remoted_parse_agents_invalid_value(void **state) {
    logr.allow_higher_versions = REMOTED_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT;
    XML_NODE node;

    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("allow_higher_versions", node[0]->element);
    os_strdup("invalid_value", node[0]->content);
    node[1] = NULL;

    expect_string(__wrap__mwarn, formatted_msg,
                  "(9001): Ignored invalid value 'invalid_value' for 'allow_higher_versions'.");
    w_remoted_parse_agents(node, &logr);
    assert_int_equal(logr.allow_higher_versions, REMOTED_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT);

    os_free(node[0]->element);
    os_free(node[0]->content);
    os_free(node[0]);
    os_free(node);
}

static void test_w_remoted_parse_agents_invalid_element(void **state) {
    logr.allow_higher_versions = REMOTED_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT;

    XML_NODE node;

    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("invalid_element", node[0]->element); // Use an invalid element name
    os_strdup("no", node[0]->content);
    node[1] = NULL;

    expect_string(__wrap__mwarn, formatted_msg,
                  "(1230): Invalid element in the configuration: 'invalid_element'.");
    w_remoted_parse_agents(node, &logr);
    assert_int_equal(logr.allow_higher_versions, REMOTED_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT);

    os_free(node[0]->element);
    os_free(node[0]->content);
    os_free(node[0]);
    os_free(node);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_NULL),
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_empty),
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_ignore_values),
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_tcp),
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_udp),
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_tcp_udp),
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_udp_tcp),
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_mix),
        cmocka_unit_test(test_w_remoted_parse_agents_no),
        cmocka_unit_test(test_w_remoted_parse_agents_yes),
        cmocka_unit_test(test_w_remoted_parse_agents_invalid_value),
        cmocka_unit_test(test_w_remoted_parse_agents_invalid_element),

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
