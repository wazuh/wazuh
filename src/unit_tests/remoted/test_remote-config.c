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
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"
#include "../wrappers/wazuh/shared/cluster_utils_wrappers.h"
#include "../../external/cJSON/cJSON.h"

int w_remoted_get_net_protocol(const char * content);

void w_remoted_parse_agents(XML_NODE node, remoted * logr);

int __wrap_ReadConfig(int modules, const char *cfgfile, void *d1, void *d2) {
    check_expected(modules);
    check_expected(cfgfile);
    return mock();
}

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

static void test_remoted_internal_options_config(void **state) {
    (void) state;

    // Set internal options with prime numbers using mocked getDefine_Int
    will_return(__wrap_getDefine_Int, 2);      // receive_chunk
    will_return(__wrap_getDefine_Int, 3);      // send_chunk
    will_return(__wrap_getDefine_Int, 5);      // buffer_relax
    will_return(__wrap_getDefine_Int, 7);      // send_buffer_size
    will_return(__wrap_getDefine_Int, 11);     // send_timeout_to_retry
    will_return(__wrap_getDefine_Int, 13);     // recv_timeout
    will_return(__wrap_getDefine_Int, 17);     // tcp_keepidle
    will_return(__wrap_getDefine_Int, 19);     // tcp_keepintvl
    will_return(__wrap_getDefine_Int, 23);     // tcp_keepcnt
    will_return(__wrap_getDefine_Int, 29);     // worker_pool
    will_return(__wrap_getDefine_Int, 31);     // merge_shared
    will_return(__wrap_getDefine_Int, 37);     // pass_empty_keyfile
    will_return(__wrap_getDefine_Int, 41);     // ctrl_msg_queue_size
    will_return(__wrap_getDefine_Int, 43);     // keyupdate_interval
    will_return(__wrap_getDefine_Int, 47);     // router_forwarding_disabled
    will_return(__wrap_getDefine_Int, 53);     // state_interval
    will_return(__wrap_getDefine_Int, 59);     // nofile
    will_return(__wrap_getDefine_Int, 61);     // sender_pool
    will_return(__wrap_getDefine_Int, 67);     // request_pool
    will_return(__wrap_getDefine_Int, 71);     // request_timeout
    will_return(__wrap_getDefine_Int, 73);     // response_timeout
    will_return(__wrap_getDefine_Int, 79);     // rto_sec
    will_return(__wrap_getDefine_Int, 83);     // rto_msec
    will_return(__wrap_getDefine_Int, 89);     // max_attempts
    will_return(__wrap_getDefine_Int, 97);     // guess_agent_group
    will_return(__wrap_getDefine_Int, 101);    // shared_reload_interval
    will_return(__wrap_getDefine_Int, 103);    // disk_storage
    will_return(__wrap_getDefine_Int, 107);    // _s_verify_counter

    // Mock ReadConfig calls
    expect_value(__wrap_ReadConfig, modules, CREMOTE);
    expect_string(__wrap_ReadConfig, cfgfile, "test_ossec.conf");
    will_return(__wrap_ReadConfig, 0);

    expect_value(__wrap_ReadConfig, modules, CGLOBAL);
    expect_string(__wrap_ReadConfig, cfgfile, "test_ossec.conf");
    will_return(__wrap_ReadConfig, 0);

    // Mock get_node_name call
    will_return(__wrap_get_node_name, NULL);

    // Call RemotedConfig to load all internal options
    int ret = RemotedConfig("test_ossec.conf", &logr);
    assert_int_equal(ret, 1);

    // Now validate getRemoteInternalConfig returns the correct values
    cJSON *json = getRemoteInternalConfig();
    assert_non_null(json);

    cJSON *internal = cJSON_GetObjectItem(json, "internal");
    assert_non_null(internal);

    cJSON *remoted_obj = cJSON_GetObjectItem(internal, "remoted");
    assert_non_null(remoted_obj);

    // Validate prime number values
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "receive_chunk")->valueint, 2);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "send_chunk")->valueint, 3);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "buffer_relax")->valueint, 5);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "send_buffer_size")->valueint, 7);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "send_timeout_to_retry")->valueint, 11);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "recv_timeout")->valueint, 13);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "tcp_keepidle")->valueint, 17);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "tcp_keepintvl")->valueint, 19);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "tcp_keepcnt")->valueint, 23);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "worker_pool")->valueint, 29);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "merge_shared")->valueint, 31);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "pass_empty_keyfile")->valueint, 37);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "control_msg_queue_size")->valueint, 41);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "keyupdate_interval")->valueint, 43);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "router_forwarding_disabled")->valueint, 47);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "state_interval")->valueint, 53);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "rlimit_nofile")->valueint, 59);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "sender_pool")->valueint, 61);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "request_pool")->valueint, 67);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "request_timeout")->valueint, 71);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "response_timeout")->valueint, 73);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "request_rto_sec")->valueint, 79);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "request_rto_msec")->valueint, 83);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "max_attempts")->valueint, 89);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "guess_agent_group")->valueint, 97);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "shared_reload")->valueint, 101);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "disk_storage")->valueint, 103);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "verify_msg_id")->valueint, 107);

    cJSON_Delete(json);
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
        cmocka_unit_test(test_remoted_internal_options_config),

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
