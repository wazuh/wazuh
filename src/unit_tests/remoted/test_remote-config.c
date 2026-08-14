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

int w_remoted_parse_legacy(XML_NODE node, remoted * logr);

int w_remoted_parse_https(XML_NODE node, remoted * logr);

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
    logr->https.verification_mode = REMOTED_HTTPS_VERIFY_UNSET;
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
    if (ts->logr->https.bind_addr) free(ts->logr->https.bind_addr);
    if (ts->logr->https.certificate) free(ts->logr->https.certificate);
    if (ts->logr->https.key) free(ts->logr->https.key);
    if (ts->logr->https.ca) free(ts->logr->https.ca);
    if (ts->logr->https.ciphers) free(ts->logr->https.ciphers);
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

/* Mocks every internal option RemotedConfig reads, in order, ending with
 * legacy_task_polling_interval returning `legacy_value` (after asserting the
 * call site still passes min=300/max=86400/default=900). Shared by the main
 * prime-number test and the dedicated legacy_task_polling_interval boundary
 * test so the latter doesn't have to duplicate ~40 unrelated will_return calls. */
static void mock_remoted_internal_options(int legacy_value) {
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
    will_return(__wrap_getDefine_Int_default, 1031);   // queue_max_bytes (prime >= 1024 to pass validation)
    will_return(__wrap_getDefine_Int_default, 1033);   // batch_events_max_bytes (prime >= 1024 to pass validation)
    will_return(__wrap_getDefine_Int_default, 127);    // enrich_cache_expire_time
    expect_value(__wrap_getDefine_Int_default, min, 300);
    expect_value(__wrap_getDefine_Int_default, max, 86400);
    expect_value(__wrap_getDefine_Int_default, default_val, 900);
    will_return(__wrap_getDefine_Int_default, legacy_value); // legacy_task_polling_interval

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
}

static void test_remoted_internal_options_config(void **state) {
    (void) state;

    // Set internal options with prime numbers using mocked getDefine_Int
    mock_remoted_internal_options(131); // legacy_task_polling_interval

    // Call RemotedConfig to load all internal options
    int ret = RemotedConfig("test_ossec.conf", &logr);
    assert_int_equal(ret, 1);

    // verification_mode must start UNSET (not NONE/0), so a later absent
    // <https><verification_mode> stays distinguishable from an explicit "none".
    assert_int_equal(logr.https.verification_mode, REMOTED_HTTPS_VERIFY_UNSET);

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
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "queue_max_bytes")->valueint, 1031);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "batch_events_max_bytes")->valueint, 1033);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "enrich_cache_expire_time")->valueint, 127);
    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "legacy_task_polling_interval")->valueint, 131);

    cJSON_Delete(json);
}

/* Verifies config.c wires the 300/86400/900 (min/max/default) triple and that
 * the floor (300) round-trips through getRemoteInternalConfig() -- not the
 * real clamp/reject logic itself, which is generic shared code with no
 * existing coverage anywhere in the repo. */
static void test_remoted_legacy_task_polling_interval_bounds(void **state) {
    (void) state;

    mock_remoted_internal_options(300); // legacy_task_polling_interval floor

    int ret = RemotedConfig("test_ossec.conf", &logr);
    assert_int_equal(ret, 1);

    cJSON *json = getRemoteInternalConfig();
    assert_non_null(json);

    cJSON *internal = cJSON_GetObjectItem(json, "internal");
    assert_non_null(internal);

    cJSON *remoted_obj = cJSON_GetObjectItem(internal, "remoted");
    assert_non_null(remoted_obj);

    assert_int_equal(cJSON_GetObjectItem(remoted_obj, "legacy_task_polling_interval")->valueint, 300);

    cJSON_Delete(json);
}

// Test w_remoted_parse_legacy

static void test_w_remoted_parse_legacy_valid_port(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("port", "1514")
    );

    int result = w_remoted_parse_legacy(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_int_equal(ts->logr->port, 1514);

    free_node_array(nodes);
}

static void test_w_remoted_parse_legacy_invalid_port(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("port", "-1")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'port': -1.");

    int result = w_remoted_parse_legacy(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);
    assert_int_equal(ts->logr->port, 0);

    free_node_array(nodes);
}

static void test_w_remoted_parse_legacy_connection_section(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("connection", "secure")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'connection'.");

    int result = w_remoted_parse_legacy(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);

    free_node_array(nodes);
}

static void test_w_remoted_parse_legacy_allowed_ips_section(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("allowed-ips", "x")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'allowed-ips'.");

    int result = w_remoted_parse_legacy(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);

    free_node_array(nodes);
}

static void test_w_remoted_parse_legacy_denied_ips_section(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("denied-ips", "x")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'denied-ips'.");

    int result = w_remoted_parse_legacy(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);

    free_node_array(nodes);
}

// Test w_remoted_parse_https

static void test_w_remoted_parse_https_valid_full(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(8,
        create_xml_node("port", "9443"),
        create_xml_node("bind_addr", "0.0.0.0"),
        create_xml_node("certificate", "etc/remoted-https/server.crt"),
        create_xml_node("key", "etc/remoted-https/server.key"),
        create_xml_node("ca", "etc/remoted-https/ca.crt"),
        create_xml_node("verification_mode", "certificate"),
        create_xml_node("ciphers", "HIGH:!ADH"),
        create_xml_node("max_body_size", "50MB")
    );

    expect_string(__wrap_OS_IsValidIP, ip_address, "0.0.0.0");
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_int_equal(ts->logr->https.port, 9443);
    assert_string_equal(ts->logr->https.bind_addr, "0.0.0.0");
    assert_string_equal(ts->logr->https.certificate, "etc/remoted-https/server.crt");
    assert_string_equal(ts->logr->https.key, "etc/remoted-https/server.key");
    assert_string_equal(ts->logr->https.ca, "etc/remoted-https/ca.crt");
    assert_int_equal(ts->logr->https.verification_mode, REMOTED_HTTPS_VERIFY_CERTIFICATE);
    assert_string_equal(ts->logr->https.ciphers, "HIGH:!ADH");
    assert_int_equal(ts->logr->https.max_body_size, 50L * 1024 * 1024);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_invalid_port(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("port", "70000")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "(1205): Invalid port number: '70000'.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_invalid_bind_addr(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("bind_addr", "not-an-ip")
    );

    expect_string(__wrap_OS_IsValidIP, ip_address, "not-an-ip");
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 0);

    expect_string(__wrap__merror, formatted_msg,
                  "(1237): Invalid ip address: 'not-an-ip'.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_invalid_verification_mode(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("verification_mode", "invalid_value")
    );

    expect_string(__wrap__mwarn, formatted_msg,
                  "(9001): Ignored invalid value 'invalid_value' for 'verification_mode'.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    // Invalid input is ignored (mwarn above), leaving verification_mode exactly as it
    // started -- UNSET, since this test never configures <ca> either (create_remoted()
    // mirrors RemotedConfig()'s real pre-parse UNSET initialization).
    assert_int_equal(ts->logr->https.verification_mode, REMOTED_HTTPS_VERIFY_UNSET);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_verification_mode_without_ca(void **state) {
    test_state *ts = *state;

    // <verification_mode> alone, no <ca>: no longer a hard error -- ca resolution
    // (XML/env var/default) happens later in the C++ module, which the parser can't
    // see, so the parser must not fail this. See M7 in the review history.
    xml_node **nodes = create_node_array(1,
        create_xml_node("verification_mode", "certificate")
    );

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_int_equal(ts->logr->https.verification_mode, REMOTED_HTTPS_VERIFY_CERTIFICATE);
    assert_null(ts->logr->https.ca);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_verification_mode_full(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("verification_mode", "full")
    );

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_int_equal(ts->logr->https.verification_mode, REMOTED_HTTPS_VERIFY_FULL);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_ca_without_verification_mode_defaults_to_certificate(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("ca", "etc/remoted-https/ca.crt")
    );

    expect_string(__wrap__mwarn, formatted_msg,
                  "The '<remote><https><ca>' option is configured but '<verification_mode>' is not; "
                  "defaulting '<verification_mode>' to 'certificate'.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_int_equal(ts->logr->https.verification_mode, REMOTED_HTTPS_VERIFY_CERTIFICATE);
    assert_string_equal(ts->logr->https.ca, "etc/remoted-https/ca.crt");

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_ca_with_explicit_none_verification_mode_not_overridden(void **state) {
    test_state *ts = *state;

    // <ca> and an EXPLICIT <verification_mode>none</verification_mode> together: the
    // auto-upgrade special case only fires when verification_mode is still UNSET, so an
    // explicit choice (even "none", which the operator may want e.g. while staging a CA
    // file before enabling verification) must never be silently overridden, and no
    // warning should be logged.
    xml_node **nodes = create_node_array(2,
        create_xml_node("ca", "etc/remoted-https/ca.crt"),
        create_xml_node("verification_mode", "none")
    );

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_int_equal(ts->logr->https.verification_mode, REMOTED_HTTPS_VERIFY_NONE);
    assert_string_equal(ts->logr->https.ca, "etc/remoted-https/ca.crt");

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_minimal_block_no_ca_no_verification_mode_succeeds(void **state) {
    test_state *ts = *state;

    // Regression test: an <https> block that configures something other than
    // verification_mode/ca must parse successfully with no warning at all -- this is
    // the "HTTPS with no mTLS configured" scenario documented as the zero-config
    // default, and previously broke when verification_mode's UNSET sentinel was
    // introduced without updating this cross-field check.
    xml_node **nodes = create_node_array(1,
        create_xml_node("port", "9443")
    );

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_int_equal(ts->logr->https.verification_mode, REMOTED_HTTPS_VERIFY_UNSET);
    assert_null(ts->logr->https.ca);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_invalid_max_body_size(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("max_body_size", "not-a-size")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'max_body_size': not-a-size.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_zero_max_body_size(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("max_body_size", "0")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'max_body_size': 0.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_negative_max_body_size(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("max_body_size", "-1024")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'max_body_size': -1024.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_max_body_size_unit_suffixes(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("max_body_size", "2KB")
    );

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_int_equal(ts->logr->https.max_body_size, 2L * 1024);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_ciphers_too_long(void **state) {
    test_state *ts = *state;

    char long_ciphers[REMOTED_HTTPS_CIPHERS_MAX_LEN + 2];
    memset(long_ciphers, 'A', sizeof(long_ciphers) - 1);
    long_ciphers[sizeof(long_ciphers) - 1] = '\0';

    xml_node **nodes = create_node_array(1,
        create_xml_node("ciphers", long_ciphers)
    );

    expect_string(__wrap__merror, formatted_msg,
                  "Value for '<remote><https><ciphers>' exceeds the maximum length of 255 characters.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);
    assert_null(ts->logr->https.ciphers);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_certificate_too_long(void **state) {
    test_state *ts = *state;

    char long_certificate[REMOTED_HTTPS_CERTIFICATE_MAX_LEN + 2];
    memset(long_certificate, 'A', sizeof(long_certificate) - 1);
    long_certificate[sizeof(long_certificate) - 1] = '\0';

    xml_node **nodes = create_node_array(1,
        create_xml_node("certificate", long_certificate)
    );

    expect_string(__wrap__merror, formatted_msg,
                  "Value for '<remote><https><certificate>' exceeds the maximum length of 511 characters.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);
    assert_null(ts->logr->https.certificate);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_invalid_element(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("invalid_element", "x")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'invalid_element'.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);

    free_node_array(nodes);
}

// Read_remote tests

static void test_read_remote_flat_legacy_option_rejected(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("port", "1514")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'port'.");

    int result = Read_Remote(&ts->xml, nodes, ts->logr, NULL);

    assert_int_equal(result, OS_INVALID);

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

static void test_read_remote_local_ip_defaults_to_loopback(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(0);

    int result = Read_Remote(&ts->xml, nodes, ts->logr, NULL);

    assert_int_equal(result, 0);
    assert_non_null(ts->logr->lip);
    assert_string_equal(ts->logr->lip, "127.0.0.1");
    assert_int_equal(ts->logr->port, DEFAULT_REMOTE_PORT);
    assert_int_equal(ts->logr->proto, REMOTED_NET_PROTOCOL_DEFAULT);

    free_node_array(nodes);
}

static void test_read_remote_local_ip_not_defaulted_for_ipv6(void **state) {
    test_state *ts = *state;
    ts->logr->ipv6 = 1;

    xml_node **nodes = create_node_array(0);

    int result = Read_Remote(&ts->xml, nodes, ts->logr, NULL);

    assert_int_equal(result, 0);
    assert_null(ts->logr->lip);

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
        cmocka_unit_test(test_remoted_legacy_task_polling_interval_bounds),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_legacy_valid_port, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_legacy_invalid_port, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_legacy_connection_section, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_legacy_allowed_ips_section, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_legacy_denied_ips_section, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_valid_full, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_invalid_port, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_invalid_bind_addr, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_invalid_verification_mode, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_verification_mode_without_ca, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_verification_mode_full, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_w_remoted_parse_https_ca_without_verification_mode_defaults_to_certificate, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_w_remoted_parse_https_ca_with_explicit_none_verification_mode_not_overridden, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_w_remoted_parse_https_minimal_block_no_ca_no_verification_mode_succeeds, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_invalid_max_body_size, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_zero_max_body_size, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_negative_max_body_size, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_max_body_size_unit_suffixes, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_ciphers_too_long, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_certificate_too_long, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_invalid_element, setup, teardown),
        cmocka_unit_test_setup_teardown(test_read_remote_flat_legacy_option_rejected, setup, teardown),
        cmocka_unit_test_setup_teardown(test_read_remote_connection_section, setup, teardown),
        cmocka_unit_test_setup_teardown(test_read_remote_allowed_ips_section, setup, teardown),
        cmocka_unit_test_setup_teardown(test_read_remote_denied_ips_section, setup, teardown),
        cmocka_unit_test_setup_teardown(test_read_remote_local_ip_defaults_to_loopback, setup, teardown),
        cmocka_unit_test_setup_teardown(test_read_remote_local_ip_not_defaulted_for_ipv6, setup, teardown),

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
