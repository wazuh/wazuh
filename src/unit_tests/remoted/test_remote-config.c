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

#include "remoted.h"
#include "shared.h"
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

typedef struct test_state {
    OS_XML xml;
    remoted *logr;
} test_state;

/* setup/teardown */

static xml_node *create_xml_node(const char *element, const char *content) {
    xml_node *node = calloc(1, sizeof(xml_node));
    if (element) node->element = strdup(element);
    if (content) node->content = strdup(content);
    return node;
}

static xml_node **create_node_array(int count, ...) {
    va_list args;
    xml_node **nodes = calloc(count + 1, sizeof(xml_node *));

    va_start(args, count);
    for (int i = 0; i < count; i++) {
        nodes[i] = va_arg(args, xml_node *);
    }
    va_end(args);

    nodes[count] = NULL;
    return nodes;
}

static void free_node_array(xml_node **nodes) {
    if (!nodes) return;
    for (int i = 0; nodes[i]; i++) {
        free(nodes[i]->element);
        free(nodes[i]->content);
        free(nodes[i]);
    }
    free(nodes);
}
static remoted *create_remoted() {
    remoted *logr = calloc(1, sizeof(remoted));
    logr->port = 0;
    logr->proto = 0;
    logr->queue_size = 0;
    logr->rids_closing_time = 0;
    logr->connection_overtake_time = 60;
    logr->lip = NULL;
    return logr;
}

static int setup(void **state) {
    test_state *ts = calloc(1, sizeof(test_state));
    if (!ts) return 1;
    ts->logr = create_remoted();
    if (!ts->logr) { free(ts); return 1; }
    *state = ts;
    return 0;
}

static int teardown(void **state) {
    test_state *ts = *state;
    if (ts->logr->lip) free(ts->logr->lip);
    free(ts->logr);
    free(ts);
    return 0;
}


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

    // FIM limits
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);

    // Syscollector limits
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);
    will_return(__wrap_getDefine_Int_default, 1);

    // SCA limits
    will_return(__wrap_getDefine_Int_default, 1);

    will_return(__wrap_getDefine_Int_default, 2);      // receive_chunk
    will_return(__wrap_getDefine_Int_default, 3);      // send_chunk
    will_return(__wrap_getDefine_Int_default, 5);      // buffer_relax
    will_return(__wrap_getDefine_Int_default, 7);      // send_buffer_size
    will_return(__wrap_getDefine_Int_default, 11);     // send_timeout_to_retry
    will_return(__wrap_getDefine_Int_default, 13);     // recv_timeout
    will_return(__wrap_getDefine_Int_default, 17);     // tcp_keepidle
    will_return(__wrap_getDefine_Int_default, 19);     // tcp_keepintvl
    will_return(__wrap_getDefine_Int_default, 23);     // tcp_keepcnt
    will_return(__wrap_getDefine_Int_default, 29);     // worker_pool
    will_return(__wrap_getDefine_Int_default, 31);     // merge_shared
    will_return(__wrap_getDefine_Int_default, 37);     // pass_empty_keyfile
    will_return(__wrap_getDefine_Int_default, 41);     // ctrl_msg_queue_size
    will_return(__wrap_getDefine_Int_default, 43);     // keyupdate_interval
    will_return(__wrap_getDefine_Int_default, 47);     // router_forwarding_disabled
    will_return(__wrap_getDefine_Int_default, 53);     // state_interval
    will_return(__wrap_getDefine_Int_default, 59);     // nofile
    will_return(__wrap_getDefine_Int_default, 61);     // sender_pool
    will_return(__wrap_getDefine_Int_default, 67);     // request_pool
    will_return(__wrap_getDefine_Int_default, 71);     // request_timeout
    will_return(__wrap_getDefine_Int_default, 73);     // response_timeout
    will_return(__wrap_getDefine_Int_default, 79);     // rto_sec
    will_return(__wrap_getDefine_Int_default, 83);     // rto_msec
    will_return(__wrap_getDefine_Int_default, 89);     // max_attempts
    will_return(__wrap_getDefine_Int_default, 101);    // shared_reload_interval
    will_return(__wrap_getDefine_Int_default, 103);    // disk_storage
    will_return(__wrap_getDefine_Int_default, 107);    // _s_verify_counter
    will_return(__wrap_getDefine_Int_default, 109);    // batch_events_capacity
    will_return(__wrap_getDefine_Int_default, 113);    // batch_events_per_agent_capacity
    will_return(__wrap_getDefine_Int_default, 127);    // enrich_cache_expire_time

    // Mock ReadConfig calls
    expect_value(__wrap_ReadConfig, modules, CREMOTE);
    expect_string(__wrap_ReadConfig, cfgfile, "test_ossec.conf");
    will_return(__wrap_ReadConfig, 0);

    expect_value(__wrap_ReadConfig, modules, CGLOBAL);
    expect_string(__wrap_ReadConfig, cfgfile, "test_ossec.conf");
    will_return(__wrap_ReadConfig, 0);

    // Mock get_node_name and get_cluster_name calls
    will_return(__wrap_get_node_name, NULL);
    will_return(__wrap_get_cluster_name, NULL);

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
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "shared_reload")->valueint, 101);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "disk_storage")->valueint, 103);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "verify_msg_id")->valueint, 107);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "batch_events_capacity")->valueint, 109);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "batch_events_per_agent_capacity")->valueint, 113);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "enrich_cache_expire_time")->valueint, 127);

    cJSON_Delete(json);
}

// Read_remote tests

static void test_read_remote_valid_port(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("port", "1514")
    );

    int result = Read_Remote(&ts->xml, nodes, ts->logr, NULL);

    assert_int_equal(result, OS_SUCCESS);
    assert_int_equal(ts->logr->port, 1514);

    free_node_array(nodes);
}

static void test_read_remote_invalid_port(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("port", "-1")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'port': -1.");

    int result = Read_Remote(&ts->xml, nodes, ts->logr, NULL);

    assert_int_equal(result, OS_INVALID);
    assert_int_equal(ts->logr->port, 0);

    free_node_array(nodes);
}

static void test_read_remote_connection_section(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("connection", "secure")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'connection'.");

    int result = Read_Remote(&ts->xml, nodes, ts->logr, NULL);

    assert_int_equal(result, OS_INVALID);

    free_node_array(nodes);
}

static void test_read_remote_allowed_ips_section(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("allowed-ips", "x")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'allowed-ips'.");

    int result = Read_Remote(&ts->xml, nodes, ts->logr, NULL);

    assert_int_equal(result, OS_INVALID);

    free_node_array(nodes);
}

static void test_read_remote_denied_ips_section(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("denied-ips", "x")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'denied-ips'.");

    int result = Read_Remote(&ts->xml, nodes, ts->logr, NULL);

    assert_int_equal(result, OS_INVALID);

    free_node_array(nodes);
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
        cmocka_unit_test_setup_teardown(test_read_remote_valid_port, setup, teardown),
        cmocka_unit_test_setup_teardown(test_read_remote_invalid_port, setup, teardown),
        cmocka_unit_test_setup_teardown(test_read_remote_connection_section, setup, teardown),
        cmocka_unit_test_setup_teardown(test_read_remote_allowed_ips_section, setup, teardown),
        cmocka_unit_test_setup_teardown(test_read_remote_denied_ips_section, setup, teardown),

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
