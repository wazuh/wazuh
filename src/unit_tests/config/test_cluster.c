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
#include <memory.h>

#include "../../config/config.h"
#include "../../headers/shared.h"
#include "../../config/global-config.h"

typedef struct {
    OS_XML xml;
    XML_NODE nodes;
    _Config config;
} test_structure;

static const XML_NODE string_to_xml_node(const char * string, OS_XML *_lxml){
    XML_NODE nodes;
    OS_ReadXMLString(string, _lxml);
    nodes = OS_GetElementsbyNode(_lxml, NULL);
    return nodes;
}

static int setup_test_read(void **state) {
    test_structure *test;
    os_calloc(1, sizeof(test_structure), test);
    *state = test;
    return 0;
}

static int teardown_test_read(void **state) {
    test_structure *test = *state;
    OS_ClearNode(test->nodes);
    OS_ClearXML(&(test->xml));
    os_free(test->config.cluster_name);
    os_free(test->config.node_name);
    os_free(test->config.node_type);
    os_free(test);
    return 0;
}

/* Cluster config tests */
void test_read_empty_cluster_name(void **state) {
    const char * configuration =
        "<name></name>"
        "<node_name>node01</node_name>"
        "<node_type>master</node_type>"
        "<key>fd3350b86d239654e34866ab3c4988a8</key>"
        "<port>1516</port>"
        "<bind_addr>127.0.0.1</bind_addr>"
        "<nodes>"
            "<node>127.0.0.1</node>"
        "</nodes>"
        "<haproxy_helper>"
            "<haproxy_disabled>no</haproxy_disabled>"
            "<haproxy_address>wazuh-proxy</haproxy_address>"
            "<haproxy_user>haproxy</haproxy_user>"
            "<haproxy_password>haproxy</haproxy_password>"
        "</haproxy_helper>"
        "<hidden>no</hidden>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    expect_string(__wrap__merror, formatted_msg, "Cluster name is empty in configuration");
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), OS_INVALID);
}

void test_read_invalid_characters_in_cluster_name(void **state) {
    const char * configuration =
        "<name>wazuh 01</name>"
        "<node_name>node01</node_name>"
        "<node_type>master</node_type>"
        "<key>fd3350b86d239654e34866ab3c4988a8</key>"
        "<port>1516</port>"
        "<bind_addr>127.0.0.1</bind_addr>"
        "<nodes>"
            "<node>127.0.0.1</node>"
        "</nodes>"
        "<haproxy_helper>"
            "<haproxy_disabled>no</haproxy_disabled>"
            "<haproxy_address>wazuh-proxy</haproxy_address>"
            "<haproxy_user>haproxy</haproxy_user>"
            "<haproxy_password>haproxy</haproxy_password>"
        "</haproxy_helper>"
        "<hidden>no</hidden>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    expect_string(__wrap__merror, formatted_msg, "Detected a not allowed character in cluster name: \"wazuh 01\". Characters allowed: \"!\"#$%&'-.0123456789:<=>?ABCDEFGHIJKLMNOPQRESTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}~\".");
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), OS_INVALID);
}

void test_read_empty_node_name(void **state) {
    const char * configuration =
        "<name>wazuh</name>"
        "<node_name></node_name>"
        "<node_type>master</node_type>"
        "<key>fd3350b86d239654e34866ab3c4988a8</key>"
        "<port>1516</port>"
        "<bind_addr>127.0.0.1</bind_addr>"
        "<nodes>"
            "<node>127.0.0.1</node>"
        "</nodes>"
        "<haproxy_helper>"
            "<haproxy_disabled>no</haproxy_disabled>"
            "<haproxy_address>wazuh-proxy</haproxy_address>"
            "<haproxy_user>haproxy</haproxy_user>"
            "<haproxy_password>haproxy</haproxy_password>"
        "</haproxy_helper>"
        "<hidden>no</hidden>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    expect_string(__wrap__merror, formatted_msg, "Node name is empty in configuration");
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), OS_INVALID);
}

void test_read_invalid_characters_in_node_name(void **state) {
    const char * configuration =
        "<name>wazuh</name>"
        "<node_name>node 01</node_name>"
        "<node_type>master</node_type>"
        "<key>fd3350b86d239654e34866ab3c4988a8</key>"
        "<port>1516</port>"
        "<bind_addr>127.0.0.1</bind_addr>"
        "<nodes>"
            "<node>127.0.0.1</node>"
        "</nodes>"
        "<haproxy_helper>"
            "<haproxy_disabled>no</haproxy_disabled>"
            "<haproxy_address>wazuh-proxy</haproxy_address>"
            "<haproxy_user>haproxy</haproxy_user>"
            "<haproxy_password>haproxy</haproxy_password>"
        "</haproxy_helper>"
        "<hidden>no</hidden>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    expect_string(__wrap__merror, formatted_msg, "Detected a not allowed character in node name: \"node 01\". Characters allowed: \"!\"#$%&'-.0123456789:<=>?ABCDEFGHIJKLMNOPQRESTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}~\".");
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), OS_INVALID);
}

void test_read_empty_node_type(void **state) {
    const char * configuration =
        "<name>wazuh</name>"
        "<node_name>node01</node_name>"
        "<node_type></node_type>"
        "<key>fd3350b86d239654e34866ab3c4988a8</key>"
        "<port>1516</port>"
        "<bind_addr>127.0.0.1</bind_addr>"
        "<nodes>"
            "<node>127.0.0.1</node>"
        "</nodes>"
        "<haproxy_helper>"
            "<haproxy_disabled>no</haproxy_disabled>"
            "<haproxy_address>wazuh-proxy</haproxy_address>"
            "<haproxy_user>haproxy</haproxy_user>"
            "<haproxy_password>haproxy</haproxy_password>"
        "</haproxy_helper>"
        "<hidden>no</hidden>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    expect_string(__wrap__merror, formatted_msg, "Node type is empty in configuration");
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), OS_INVALID);
}

void test_read_invalid_node_type(void **state) {
    const char * configuration =
        "<name>wazuh</name>"
        "<node_name>node01</node_name>"
        "<node_type>invalid</node_type>"
        "<key>fd3350b86d239654e34866ab3c4988a8</key>"
        "<port>1516</port>"
        "<bind_addr>127.0.0.1</bind_addr>"
        "<nodes>"
            "<node>127.0.0.1</node>"
        "</nodes>"
        "<haproxy_helper>"
            "<haproxy_disabled>no</haproxy_disabled>"
            "<haproxy_address>wazuh-proxy</haproxy_address>"
            "<haproxy_user>haproxy</haproxy_user>"
            "<haproxy_password>haproxy</haproxy_password>"
        "</haproxy_helper>"
        "<hidden>no</hidden>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    expect_string(__wrap__merror, formatted_msg, "Detected a not allowed node type 'invalid'. Valid types are 'master' and 'worker'.");
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), OS_INVALID);
}

void test_read_deprecated_client_value(void **state) {
    const char * configuration =
        "<name>wazuh</name>"
        "<node_name>node01</node_name>"
        "<node_type>client</node_type>"
        "<key>fd3350b86d239654e34866ab3c4988a8</key>"
        "<port>1516</port>"
        "<bind_addr>127.0.0.1</bind_addr>"
        "<nodes>"
            "<node>127.0.0.1</node>"
        "</nodes>"
        "<haproxy_helper>"
            "<haproxy_disabled>no</haproxy_disabled>"
            "<haproxy_address>wazuh-proxy</haproxy_address>"
            "<haproxy_user>haproxy</haproxy_user>"
            "<haproxy_password>haproxy</haproxy_password>"
        "</haproxy_helper>"
        "<hidden>no</hidden>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    expect_string(__wrap__mwarn, formatted_msg, "Deprecated node type 'client'. Using 'worker' instead.");
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), OS_SUCCESS);
    assert_string_equal(test_data->config.node_type, "worker");
}

void test_read_deprecated_disabled_option(void **state) {
    const char * configuration =
        "<disabled>yes</disabled>"
        "<name>wazuh</name>"
        "<node_name>node01</node_name>"
        "<node_type>master</node_type>"
        "<key>fd3350b86d239654e34866ab3c4988a8</key>"
        "<port>1516</port>"
        "<bind_addr>127.0.0.1</bind_addr>"
        "<nodes>"
            "<node>127.0.0.1</node>"
        "</nodes>"
        "<haproxy_helper>"
            "<haproxy_disabled>no</haproxy_disabled>"
            "<haproxy_address>wazuh-proxy</haproxy_address>"
            "<haproxy_user>haproxy</haproxy_user>"
            "<haproxy_password>haproxy</haproxy_password>"
        "</haproxy_helper>"
        "<hidden>no</hidden>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    expect_string(__wrap__mwarn, formatted_msg, "Detected a deprecated configuration for cluster. The 'disabled' option is not longer available.");
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), 0);
}

void test_read_deprecated_interval_option(void **state) {
    const char * configuration =
    "<name>wazuh</name>"
    "<node_name>node01</node_name>"
    "<node_type>master</node_type>"
    "<key>fd3350b86d239654e34866ab3c4988a8</key>"
    "<port>1516</port>"
    "<bind_addr>127.0.0.1</bind_addr>"
    "<nodes>"
        "<node>127.0.0.1</node>"
    "</nodes>"
    "<haproxy_helper>"
        "<haproxy_disabled>no</haproxy_disabled>"
        "<haproxy_address>wazuh-proxy</haproxy_address>"
        "<haproxy_user>haproxy</haproxy_user>"
        "<haproxy_password>haproxy</haproxy_password>"
    "</haproxy_helper>"
    "<hidden>no</hidden>"
    "<interval>2m</interval>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    expect_string(__wrap__mwarn, formatted_msg, "Detected a deprecated configuration for cluster. The 'interval' option is not longer available.");
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), 0);
}

void test_read_valid_configuration(void **state) {
    const char * configuration =
    "<name>wazuh</name>"
    "<node_name>node01</node_name>"
    "<node_type>master</node_type>"
    "<key>fd3350b86d239654e34866ab3c4988a8</key>"
    "<port>1516</port>"
    "<bind_addr>127.0.0.1</bind_addr>"
    "<nodes>"
        "<node>127.0.0.1</node>"
    "</nodes>"
    "<haproxy_helper>"
        "<haproxy_disabled>no</haproxy_disabled>"
        "<haproxy_address>wazuh-proxy</haproxy_address>"
        "<haproxy_user>haproxy</haproxy_user>"
        "<haproxy_password>haproxy</haproxy_password>"
    "</haproxy_helper>"
    "<hidden>no</hidden>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), OS_SUCCESS);
}

void test_read_valid_configuration_no_haproxy(void **state) {
    const char * configuration =
    "<name>wazuh</name>"
    "<node_name>node01</node_name>"
    "<node_type>master</node_type>"
    "<key>fd3350b86d239654e34866ab3c4988a8</key>"
    "<port>1516</port>"
    "<bind_addr>127.0.0.1</bind_addr>"
    "<nodes>"
        "<node>127.0.0.1</node>"
    "</nodes>"
    "<hidden>no</hidden>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), OS_SUCCESS);
}

void test_read_invalid_haproxy_disable_option(void **state) {
    const char * configuration =
    "<name>wazuh</name>"
    "<node_name>node01</node_name>"
    "<node_type>master</node_type>"
    "<key>fd3350b86d239654e34866ab3c4988a8</key>"
    "<port>1516</port>"
    "<bind_addr>127.0.0.1</bind_addr>"
    "<nodes>"
        "<node>127.0.0.1</node>"
    "</nodes>"
    "<haproxy_helper>"
        "<haproxy_disabled>invalid</haproxy_disabled>"
        "<haproxy_address>wazuh-proxy</haproxy_address>"
        "<haproxy_user>haproxy</haproxy_user>"
        "<haproxy_password>haproxy</haproxy_password>"
    "</haproxy_helper>"
    "<hidden>no</hidden>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    expect_string(__wrap__merror, formatted_msg, "Detected an invalid value for the disabled tag 'haproxy_disabled'. Valid values are 'yes' and 'no'.");
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), OS_INVALID);
}

void test_read_invalid_haproxy_protocol_option(void **state) {
    const char * configuration =
    "<name>wazuh</name>"
    "<node_name>node01</node_name>"
    "<node_type>master</node_type>"
    "<key>fd3350b86d239654e34866ab3c4988a8</key>"
    "<port>1516</port>"
    "<bind_addr>127.0.0.1</bind_addr>"
    "<nodes>"
        "<node>127.0.0.1</node>"
    "</nodes>"
    "<haproxy_helper>"
        "<haproxy_disabled>no</haproxy_disabled>"
        "<haproxy_address>wazuh-proxy</haproxy_address>"
        "<haproxy_user>haproxy</haproxy_user>"
        "<haproxy_password>haproxy</haproxy_password>"
        "<haproxy_protocol>invalid</haproxy_protocol>"
    "</haproxy_helper>"
    "<hidden>no</hidden>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    expect_string(__wrap__merror, formatted_msg, "Detected an invalid value for the haproxy_protocol tag 'haproxy_protocol'. Valid values are 'http' and 'https'.");
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), OS_INVALID);
}

void test_read_valid_configuration_haproxy_empty_address(void **state) {
    const char * configuration =
    "<name>wazuh</name>"
    "<node_name>node01</node_name>"
    "<node_type>master</node_type>"
    "<key>fd3350b86d239654e34866ab3c4988a8</key>"
    "<port>1516</port>"
    "<bind_addr>127.0.0.1</bind_addr>"
    "<nodes>"
        "<node>127.0.0.1</node>"
    "</nodes>"
    "<haproxy_helper>"
        "<haproxy_disabled>no</haproxy_disabled>"
        "<haproxy_address></haproxy_address>"
        "<haproxy_user>haproxy</haproxy_user>"
        "<haproxy_password>haproxy</haproxy_password>"
    "</haproxy_helper>"
    "<hidden>no</hidden>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    expect_string(__wrap__merror, formatted_msg, "HAProxy address is missing in the configuration");
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), OS_INVALID);
}

void test_read_valid_configuration_haproxy_empty_user(void **state) {
    const char * configuration =
    "<name>wazuh</name>"
    "<node_name>node01</node_name>"
    "<node_type>master</node_type>"
    "<key>fd3350b86d239654e34866ab3c4988a8</key>"
    "<port>1516</port>"
    "<bind_addr>127.0.0.1</bind_addr>"
    "<nodes>"
        "<node>127.0.0.1</node>"
    "</nodes>"
    "<haproxy_helper>"
        "<haproxy_disabled>no</haproxy_disabled>"
        "<haproxy_address>wazuh-proxy</haproxy_address>"
        "<haproxy_user></haproxy_user>"
        "<haproxy_password>haproxy</haproxy_password>"
    "</haproxy_helper>"
    "<hidden>no</hidden>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    expect_string(__wrap__merror, formatted_msg, "HAProxy user is missing in the configuration");
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), OS_INVALID);
}

void test_read_valid_configuration_haproxy_empty_password(void **state) {
    const char * configuration =
    "<name>wazuh</name>"
    "<node_name>node01</node_name>"
    "<node_type>master</node_type>"
    "<key>fd3350b86d239654e34866ab3c4988a8</key>"
    "<port>1516</port>"
    "<bind_addr>127.0.0.1</bind_addr>"
    "<nodes>"
        "<node>127.0.0.1</node>"
    "</nodes>"
    "<haproxy_helper>"
        "<haproxy_disabled>no</haproxy_disabled>"
        "<haproxy_address>wazuh-proxy</haproxy_address>"
        "<haproxy_user>haproxy</haproxy_user>"
        "<haproxy_password></haproxy_password>"
    "</haproxy_helper>"
    "<hidden>no</hidden>";

    test_structure *test_data = *state;
    test_data->nodes = string_to_xml_node(configuration, &(test_data->xml));
    expect_string(__wrap__merror, formatted_msg, "HAProxy password is missing in the configuration");
    assert_int_equal(Read_Cluster(&test_data->xml, test_data->nodes, &test_data->config, NULL), OS_INVALID);
}

int main(void) {
    const struct CMUnitTest tests_config[] = {
        // Cluster config tests
        cmocka_unit_test_setup_teardown(test_read_empty_cluster_name, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_invalid_characters_in_cluster_name, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_empty_node_name, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_invalid_characters_in_node_name, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_empty_node_type, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_invalid_node_type, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_deprecated_client_value, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_deprecated_disabled_option, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_deprecated_interval_option, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_valid_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_valid_configuration_no_haproxy, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_invalid_haproxy_disable_option, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_invalid_haproxy_protocol_option, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_valid_configuration_haproxy_empty_address, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_valid_configuration_haproxy_empty_user, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_valid_configuration_haproxy_empty_password, setup_test_read, teardown_test_read),
    };
    return cmocka_run_group_tests(tests_config, NULL, NULL);
}
