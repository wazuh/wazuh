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
#include "../wrappers/wazuh/config/mconf-config_wrappers.h"
#include "../../external/cJSON/cJSON.h"

int w_remoted_get_net_protocol(const char * content);

void w_remoted_parse_agents(XML_NODE node, remoted * logr);

int w_remoted_parse_legacy(XML_NODE node, remoted * logr);

int w_remoted_parse_https(XML_NODE node, remoted * logr);

int Read_Remote_JSON(const cJSON *remote, void *d1);

/* Queue size the mocked `remote` section carries into RemotedConfig(): -1 = omit the key (the reader
 * then keeps the 131072 RemotedConfig() pre-sets), otherwise the value the post-load validation sees. */
static long s_mconf_queue_size = -1;

/* The `remote` section w_mconf_section() returns for a default installation. No local_ip, so the
 * OS_IsValidIP wrap is not involved and the reader fills 127.0.0.1 itself. */
static cJSON *mock_remote_section(void) {
    char json[256];

    if (s_mconf_queue_size >= 0) {
        snprintf(json, sizeof(json),
                 "{\"legacy\":{\"enabled\":true,\"port\":1514,\"protocol\":[\"tcp\"],\"queue_size\":%ld},"
                 "\"https\":{},\"agents\":{\"allow_higher_versions\":false}}", s_mconf_queue_size);
        s_mconf_queue_size = -1;
    } else {
        snprintf(json, sizeof(json),
                 "{\"legacy\":{\"enabled\":true,\"port\":1514,\"protocol\":[\"tcp\"]},"
                 "\"https\":{},\"agents\":{\"allow_higher_versions\":false}}");
    }

    return cJSON_Parse(json);
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
    if (ts->logr->https.global_prefix) free(ts->logr->https.global_prefix);
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
static void mock_remoted_internal_option_values(int legacy_value) {
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
}

/* RemotedConfig() fills the global logr; the default local_ip is heap-allocated, so every test that
 * drives it releases the previous state first (LeakSanitizer runs on this binary). */
static void reset_global_logr(void) {
    os_free(logr.lip);
    memset(&logr, 0, sizeof(logr));
}

/* Internal options plus the YAML document RemotedConfig() loads (one w_mconf_load, then the
 * `remote` and `global` sections) and the cluster getters. */
static void mock_remoted_internal_options(int legacy_value) {
    mock_remoted_internal_option_values(legacy_value);

    expect_string(__wrap_w_mconf_load, cfgfile, "test_ossec.conf");
    will_return(__wrap_w_mconf_load, 0);
    expect_string(__wrap_w_mconf_section, section, "remote");
    will_return(__wrap_w_mconf_section, mock_remote_section());
    expect_string(__wrap_w_mconf_section, section, "global");
    will_return(__wrap_w_mconf_section,
                cJSON_Parse("{\"agents_disconnection_time\":900,\"agents_disconnection_alert_time\":0}"));

    // Mock get_node_name and get_cluster_name calls
    will_return(__wrap_get_node_name, NULL);
    will_return(__wrap_get_cluster_name, NULL);
}

static void test_remoted_internal_options_config(void **state) {
    (void) state;
    reset_global_logr();

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
    os_free(logr.lip);
}

/* Verifies config.c wires the 300/86400/900 (min/max/default) triple and that
 * the floor (300) round-trips through getRemoteInternalConfig() -- not the
 * real clamp/reject logic itself, which is generic shared code with no
 * existing coverage anywhere in the repo. */
static void test_remoted_legacy_task_polling_interval_bounds(void **state) {
    (void) state;
    reset_global_logr();

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
    os_free(logr.lip);
}

/* docs/ref/modules/remoted/configuration.md documents that <queue_size> above
 * 262144 logs a warning (confirmed in config.c: `if (cfg->queue_size > 262144)`),
 * which had no test anywhere in this file. s_mconf_queue_size puts that value in the
 * mocked `remote` section, since the YAML loader itself is mocked out here. */
static void test_remoted_queue_size_above_threshold_warns(void **state) {
    (void) state;
    reset_global_logr();

    s_mconf_queue_size = 262145; // one above the threshold

    mock_remoted_internal_options(1);
    expect_string(__wrap__mwarn, formatted_msg, "Queue size is very high. The application may run out of memory.");

    int ret = RemotedConfig("test_ossec.conf", &logr);

    // The warning does not fail the config: RemotedConfig() only rejects
    // queue_size < 1 (a separate, unrelated check), so this must still succeed.
    assert_int_equal(ret, 1);
    assert_int_equal(logr.queue_size, 262145);
    os_free(logr.lip);
}

/* Boundary check for the same guard: exactly 262144 must NOT warn (config.c's
 * condition is strictly `>`), so no expect_string(__wrap__mwarn, ...) is set up
 * here -- cmocka would fail this test if mwarn were called without a matching
 * expectation queued. */
static void test_remoted_queue_size_at_threshold_does_not_warn(void **state) {
    (void) state;
    reset_global_logr();

    s_mconf_queue_size = 262144; // exactly at the threshold

    mock_remoted_internal_options(1);

    int ret = RemotedConfig("test_ossec.conf", &logr);

    assert_int_equal(ret, 1);
    assert_int_equal(logr.queue_size, 262144);
    os_free(logr.lip);
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

static void test_w_remoted_parse_legacy_enabled_yes(void **state) {
    test_state *ts = *state;
    ts->logr->legacy_enabled = false;

    xml_node **nodes = create_node_array(1,
        create_xml_node("enabled", "yes")
    );

    int result = w_remoted_parse_legacy(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_true(ts->logr->legacy_enabled);

    free_node_array(nodes);
}

static void test_w_remoted_parse_legacy_enabled_no(void **state) {
    test_state *ts = *state;
    ts->logr->legacy_enabled = true;

    xml_node **nodes = create_node_array(1,
        create_xml_node("enabled", "no")
    );

    int result = w_remoted_parse_legacy(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_false(ts->logr->legacy_enabled);

    free_node_array(nodes);
}

static void test_w_remoted_parse_legacy_enabled_invalid(void **state) {
    test_state *ts = *state;
    ts->logr->legacy_enabled = true;

    xml_node **nodes = create_node_array(1,
        create_xml_node("enabled", "maybe")
    );

    expect_string(__wrap__mwarn, formatted_msg, "(9001): Ignored invalid value 'maybe' for 'enabled'.");

    int result = w_remoted_parse_legacy(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_true(ts->logr->legacy_enabled);

    free_node_array(nodes);
}

// Test w_remoted_parse_https

static void test_w_remoted_parse_https_valid_full(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(9,
        create_xml_node("port", "9443"),
        create_xml_node("bind_addr", "0.0.0.0"),
        create_xml_node("global_prefix", "/wazuh-manager/"),
        create_xml_node("certificate", "etc/remoted-https/server.crt"),
        create_xml_node("key", "etc/remoted-https/server.key"),
        create_xml_node("ca", "etc/remoted-https/ca.crt"),
        create_xml_node("verification_mode", "certificate"),
        create_xml_node("ciphers", "TLS_AES_256_GCM_SHA384"),
        create_xml_node("max_body_size", "50MB")
    );

    expect_string(__wrap_OS_IsValidIP, ip_address, "0.0.0.0");
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_int_equal(ts->logr->https.port, 9443);
    assert_string_equal(ts->logr->https.bind_addr, "0.0.0.0");
    assert_string_equal(ts->logr->https.global_prefix, "/wazuh-manager/");
    assert_string_equal(ts->logr->https.certificate, "etc/remoted-https/server.crt");
    assert_string_equal(ts->logr->https.key, "etc/remoted-https/server.key");
    assert_string_equal(ts->logr->https.ca, "etc/remoted-https/ca.crt");
    assert_int_equal(ts->logr->https.verification_mode, REMOTED_HTTPS_VERIFY_CERTIFICATE);
    assert_string_equal(ts->logr->https.ciphers, "TLS_AES_256_GCM_SHA384");
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

// global_prefix: valid values

static void test_w_remoted_parse_https_global_prefix_valid(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("global_prefix", "/wazuh-manager/")
    );

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_string_equal(ts->logr->https.global_prefix, "/wazuh-manager/");

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_global_prefix_root_identity(void **state) {
    test_state *ts = *state;

    // "/" is the explicit identity value: accepted, endpoints served unprefixed.
    xml_node **nodes = create_node_array(1,
        create_xml_node("global_prefix", "/")
    );

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_string_equal(ts->logr->https.global_prefix, "/");

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_global_prefix_no_trailing_slash(void **state) {
    test_state *ts = *state;

    // Both spellings are accepted; trailing-slash normalization is the C++ side's job.
    xml_node **nodes = create_node_array(1,
        create_xml_node("global_prefix", "/wazuh-manager")
    );

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_string_equal(ts->logr->https.global_prefix, "/wazuh-manager");

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_global_prefix_multi_segment(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("global_prefix", "/edge/wazuh-5")
    );

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_string_equal(ts->logr->https.global_prefix, "/edge/wazuh-5");

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_global_prefix_max_len_boundary(void **state) {
    test_state *ts = *state;

    // Exactly REMOTED_HTTPS_GLOBAL_PREFIX_MAX_LEN (255) characters: the last accepted length
    // (one less than the 256-byte C-ABI buffer, leaving room for the NUL).
    char value[REMOTED_HTTPS_GLOBAL_PREFIX_MAX_LEN + 1];
    value[0] = '/';
    memset(value + 1, 'a', REMOTED_HTTPS_GLOBAL_PREFIX_MAX_LEN - 1);
    value[REMOTED_HTTPS_GLOBAL_PREFIX_MAX_LEN] = '\0';

    xml_node **nodes = create_node_array(1,
        create_xml_node("global_prefix", value)
    );

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_SUCCESS);
    assert_string_equal(ts->logr->https.global_prefix, value);

    free_node_array(nodes);
}

// global_prefix: invalid values (every one is fatal, so 'remoted -t' reports it)

static void test_w_remoted_parse_https_global_prefix_too_long(void **state) {
    test_state *ts = *state;

    // One character over the limit: rejected by the shared max-len check, never truncated.
    char value[REMOTED_HTTPS_GLOBAL_PREFIX_MAX_LEN + 2];
    value[0] = '/';
    memset(value + 1, 'a', REMOTED_HTTPS_GLOBAL_PREFIX_MAX_LEN);
    value[REMOTED_HTTPS_GLOBAL_PREFIX_MAX_LEN + 1] = '\0';

    xml_node **nodes = create_node_array(1,
        create_xml_node("global_prefix", value)
    );

    expect_string(__wrap__merror, formatted_msg,
                  "Value for '<remote><https><global_prefix>' exceeds the maximum length of 255 characters.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);
    assert_null(ts->logr->https.global_prefix);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_global_prefix_empty(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("global_prefix", "")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "Invalid '<remote><https><global_prefix>' option: the value cannot be empty.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);
    assert_null(ts->logr->https.global_prefix);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_global_prefix_no_leading_slash(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("global_prefix", "wazuh")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "Invalid '<remote><https><global_prefix>' option: 'wazuh' must start with '/'.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);
    assert_null(ts->logr->https.global_prefix);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_global_prefix_empty_segment(void **state) {
    test_state *ts = *state;

    const char *values[] = { "//", "/a//b", NULL };
    const char *messages[] = {
        "Invalid '<remote><https><global_prefix>' option: '//' contains an empty path segment ('//').",
        "Invalid '<remote><https><global_prefix>' option: '/a//b' contains an empty path segment ('//').",
        NULL
    };

    for (int i = 0; values[i]; i++) {
        xml_node **nodes = create_node_array(1,
            create_xml_node("global_prefix", values[i])
        );

        expect_string(__wrap__merror, formatted_msg, messages[i]);

        int result = w_remoted_parse_https(nodes, ts->logr);

        assert_int_equal(result, OS_INVALID);
        assert_null(ts->logr->https.global_prefix);

        free_node_array(nodes);
    }
}

static void test_w_remoted_parse_https_global_prefix_bad_chars(void **state) {
    test_state *ts = *state;

    // One representative per rejected class: query, space, percent-encoding (the prefix is
    // matched byte-exactly against the wire, never decoded).
    const char *values[] = { "/a?x=1", "/a b", "/a%20b", NULL };
    const char *messages[] = {
        "Invalid character '?' in the '<remote><https><global_prefix>' option: allowed characters are "
        "A-Z, a-z, 0-9, '.', '_', '~', '-' and '/'.",
        "Invalid character ' ' in the '<remote><https><global_prefix>' option: allowed characters are "
        "A-Z, a-z, 0-9, '.', '_', '~', '-' and '/'.",
        "Invalid character '%' in the '<remote><https><global_prefix>' option: allowed characters are "
        "A-Z, a-z, 0-9, '.', '_', '~', '-' and '/'.",
        NULL
    };

    for (int i = 0; values[i]; i++) {
        xml_node **nodes = create_node_array(1,
            create_xml_node("global_prefix", values[i])
        );

        expect_string(__wrap__merror, formatted_msg, messages[i]);

        int result = w_remoted_parse_https(nodes, ts->logr);

        assert_int_equal(result, OS_INVALID);
        assert_null(ts->logr->https.global_prefix);

        free_node_array(nodes);
    }
}

static void test_w_remoted_parse_https_global_prefix_dot_segment(void **state) {
    test_state *ts = *state;

    // Proxies dot-normalize request paths, so a '.'/'..' prefix could never match consistently.
    const char *values[] = { "/./a", "/a/../b", "/a/..", NULL };

    for (int i = 0; values[i]; i++) {
        xml_node **nodes = create_node_array(1,
            create_xml_node("global_prefix", values[i])
        );

        char message[256];
        snprintf(message, sizeof(message),
                 "Invalid '<remote><https><global_prefix>' option: '%s' contains a '.' or '..' path segment.",
                 values[i]);
        expect_string(__wrap__merror, formatted_msg, message);

        int result = w_remoted_parse_https(nodes, ts->logr);

        assert_int_equal(result, OS_INVALID);
        assert_null(ts->logr->https.global_prefix);

        free_node_array(nodes);
    }
}

static void test_w_remoted_parse_https_invalid_verification_mode(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("verification_mode", "invalid_value")
    );

    // Rejected rather than ignored: silently defaulting an invalid verification_mode to 'none'
    // would disable client-certificate verification on a typo.
    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'verification_mode': invalid_value.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_invalid_ciphers(void **state) {
    test_state *ts = *state;

    // A TLS 1.2-style cipher string is rejected at parse time; left unchecked it would make the
    // HTTPS server fail to start at runtime, past the point 'wazuh-manager-remoted -t' could catch it.
    xml_node **nodes = create_node_array(1,
        create_xml_node("ciphers", "HIGH:!ADH")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "Invalid TLS 1.3 cipher suite 'HIGH' in the '<remote><https><ciphers>' option.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);

    free_node_array(nodes);
}

static void test_w_remoted_parse_https_invalid_dual_stack(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(1,
        create_xml_node("dual_stack", "maybe")
    );

    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'dual_stack': maybe.");

    int result = w_remoted_parse_https(nodes, ts->logr);

    assert_int_equal(result, OS_INVALID);

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

static void test_read_remote_no_legacy_block_disables_legacy(void **state) {
    test_state *ts = *state;

    xml_node **nodes = create_node_array(0);

    int result = Read_Remote(&ts->xml, nodes, ts->logr, NULL);

    assert_int_equal(result, 0);
    assert_false(ts->logr->legacy_enabled);
    assert_null(ts->logr->lip);
    assert_int_equal(ts->logr->port, 0);
    assert_int_equal(ts->logr->proto, 0);

    free_node_array(nodes);
}

static void test_read_remote_legacy_block_present_defaults_applied(void **state) {
    test_state *ts = *state;
    ts->logr->legacy_enabled = true;

    xml_node **nodes = create_node_array(0);

    int result = Read_Remote(&ts->xml, nodes, ts->logr, NULL);

    assert_int_equal(result, 0);
    assert_true(ts->logr->legacy_enabled);
    assert_non_null(ts->logr->lip);
    assert_string_equal(ts->logr->lip, "127.0.0.1");
    assert_int_equal(ts->logr->port, DEFAULT_REMOTE_PORT);
    assert_int_equal(ts->logr->proto, REMOTED_NET_PROTOCOL_DEFAULT);

    free_node_array(nodes);
}

static void test_read_remote_explicit_values_cleared_when_disabled(void **state) {
    test_state *ts = *state;
    ts->logr->legacy_enabled = false;
    ts->logr->port = 1514;
    ts->logr->proto = REMOTED_NET_PROTOCOL_TCP;
    os_strdup("127.0.0.1", ts->logr->lip);

    xml_node **nodes = create_node_array(0);

    int result = Read_Remote(&ts->xml, nodes, ts->logr, NULL);

    assert_int_equal(result, 0);
    assert_false(ts->logr->legacy_enabled);
    assert_int_equal(ts->logr->port, 0);
    assert_int_equal(ts->logr->proto, 0);
    assert_null(ts->logr->lip);

    free_node_array(nodes);
}

static void test_read_remote_local_ip_not_defaulted_for_ipv6(void **state) {
    test_state *ts = *state;
    ts->logr->ipv6 = 1;
    ts->logr->legacy_enabled = true;

    xml_node **nodes = create_node_array(0);

    int result = Read_Remote(&ts->xml, nodes, ts->logr, NULL);

    assert_int_equal(result, 0);
    assert_null(ts->logr->lip);

    free_node_array(nodes);
}

/* getRemoteConfig() -- what GET /manager/configuration?section=remote reports.
 *
 * These read the GLOBAL logr (remoted.c), not the per-test one the parser tests allocate, since
 * that is what the real function reports on. Each test sets only the fields it asserts and clears
 * the global afterwards, so no state leaks into the next one.
 *
 * Regression guard: this used to emit the pre-5.0 FLAT shape -- every option directly under the
 * connection object, plus a "connection":"secure" key for an option that no longer exists -- and
 * omitted the whole <https> block, so the manager's actual agent-facing listener was invisible to
 * the API. */
/* Read_Remote_JSON(): the effective `remote` section of etc/wazuh-manager.yml (defaults applied by the
 * loader) poured into the same struct the XML reader fills. */

static cJSON *json_or_fail(const char *text) {
    cJSON *json = cJSON_Parse(text);
    assert_non_null(json);
    return json;
}

static void expect_valid_ip(const char *ip) {
    expect_string(__wrap_OS_IsValidIP, ip_address, ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);
}

static void test_Read_Remote_JSON_effective_defaults(void **state) {
    test_state *ts = *state;
    /* What the loader returns for tests/vectors/valid/generated-manager.yml (E1b) */
    cJSON *remote = json_or_fail(
        "{\"legacy\":{\"enabled\":true,\"port\":1514,\"protocol\":[\"tcp\"],\"ipv6\":false,\"local_ip\":\"127.0.0.1\","
        "\"queue_size\":131072,\"rids_closing_time\":\"5m\",\"connection_overtake_time\":60},"
        "\"https\":{\"port\":1517,\"bind_addr\":\"127.0.0.1\",\"global_prefix\":\"/wazuh-manager/\","
        "\"certificate\":\"etc/certs/remoted.pem\",\"key\":\"etc/certs/remoted-key.pem\",\"ca\":\"\"},"
        "\"agents\":{\"allow_higher_versions\":false}}");

    expect_valid_ip("127.0.0.1"); // legacy.local_ip
    expect_valid_ip("127.0.0.1"); // https.bind_addr

    assert_int_equal(Read_Remote_JSON(remote, ts->logr), 0);

    assert_true(ts->logr->legacy_enabled);
    assert_int_equal(ts->logr->port, 1514);
    assert_int_equal(ts->logr->proto, REMOTED_NET_PROTOCOL_TCP);
    assert_int_equal(ts->logr->ipv6, 0);
    assert_string_equal(ts->logr->lip, "127.0.0.1");
    assert_int_equal(ts->logr->queue_size, 131072);
    assert_int_equal(ts->logr->rids_closing_time, 300);
    assert_int_equal(ts->logr->connection_overtake_time, 60);
    assert_int_equal(ts->logr->https.port, 1517);
    assert_string_equal(ts->logr->https.bind_addr, "127.0.0.1");
    assert_string_equal(ts->logr->https.global_prefix, "/wazuh-manager/");
    assert_string_equal(ts->logr->https.certificate, "etc/certs/remoted.pem");
    assert_string_equal(ts->logr->https.key, "etc/certs/remoted-key.pem");
    assert_null(ts->logr->https.ca);
    assert_int_equal(ts->logr->https.verification_mode, REMOTED_HTTPS_VERIFY_UNSET);
    assert_null(ts->logr->https.ciphers);
    assert_int_equal(ts->logr->https.max_body_size, 0);
    assert_int_equal(ts->logr->https.dual_stack, REMOTED_HTTPS_DUAL_STACK_UNSET);
    assert_false(ts->logr->allow_higher_versions);

    cJSON_Delete(remote);
}

static void test_Read_Remote_JSON_legacy_disabled_clears_listener(void **state) {
    test_state *ts = *state;
    cJSON *remote = json_or_fail(
        "{\"legacy\":{\"enabled\":false,\"port\":1514,\"protocol\":[\"tcp\"],\"local_ip\":\"127.0.0.1\"},\"https\":{},\"agents\":{}}");

    expect_valid_ip("127.0.0.1");

    assert_int_equal(Read_Remote_JSON(remote, ts->logr), 0);
    assert_false(ts->logr->legacy_enabled);
    assert_int_equal(ts->logr->port, 0);
    assert_int_equal(ts->logr->proto, 0);
    assert_null(ts->logr->lip);

    cJSON_Delete(remote);
}

static void test_Read_Remote_JSON_protocol_list_and_ipv6_without_local_ip(void **state) {
    test_state *ts = *state;
    /* No local_ip and an IPv6 listener: the reader must not fall back to 127.0.0.1 (P61) */
    cJSON *remote = json_or_fail("{\"legacy\":{\"enabled\":true,\"protocol\":[\"tcp\",\"udp\"],\"ipv6\":true}}");

    assert_int_equal(Read_Remote_JSON(remote, ts->logr), 0);
    assert_int_equal(ts->logr->proto, REMOTED_NET_PROTOCOL_TCP | REMOTED_NET_PROTOCOL_UDP);
    assert_int_equal(ts->logr->ipv6, 1);
    assert_null(ts->logr->lip);
    assert_int_equal(ts->logr->port, DEFAULT_REMOTE_PORT);

    cJSON_Delete(remote);
}

static void test_Read_Remote_JSON_durations_and_sizes_int_or_string(void **state) {
    test_state *ts = *state;
    cJSON *as_strings = json_or_fail(
        "{\"legacy\":{\"enabled\":true,\"rids_closing_time\":\"10m\",\"connection_overtake_time\":120},"
        "\"https\":{\"max_body_size\":\"2M\"}}");
    cJSON *as_numbers = json_or_fail("{\"legacy\":{\"enabled\":true,\"rids_closing_time\":600},\"https\":{\"max_body_size\":4096}}");

    assert_int_equal(Read_Remote_JSON(as_strings, ts->logr), 0);
    assert_int_equal(ts->logr->rids_closing_time, 600);
    assert_int_equal(ts->logr->connection_overtake_time, 120);
    assert_int_equal(ts->logr->https.max_body_size, 2L * 1024 * 1024);

    assert_int_equal(Read_Remote_JSON(as_numbers, ts->logr), 0);
    assert_int_equal(ts->logr->rids_closing_time, 600);
    assert_int_equal(ts->logr->https.max_body_size, 4096);

    cJSON_Delete(as_strings);
    cJSON_Delete(as_numbers);
}

static void test_Read_Remote_JSON_ca_infers_certificate_mode(void **state) {
    test_state *ts = *state;
    cJSON *remote = json_or_fail("{\"https\":{\"certificate\":\"c.pem\",\"key\":\"k.pem\",\"ca\":\"ca.pem\"}}");

    expect_string(__wrap__mwarn, formatted_msg,
                  "The '<remote><https><ca>' option is configured but '<verification_mode>' is not; "
                  "defaulting '<verification_mode>' to 'certificate'.");

    assert_int_equal(Read_Remote_JSON(remote, ts->logr), 0);
    assert_string_equal(ts->logr->https.ca, "ca.pem");
    assert_int_equal(ts->logr->https.verification_mode, REMOTED_HTTPS_VERIFY_CERTIFICATE);

    cJSON_Delete(remote);
}

static void test_Read_Remote_JSON_enum_and_dual_stack(void **state) {
    test_state *ts = *state;
    cJSON *full = json_or_fail("{\"https\":{\"bind_addr\":\"::\",\"verification_mode\":\"full\",\"dual_stack\":true}}");
    cJSON *off = json_or_fail("{\"https\":{\"dual_stack\":false}}");

    expect_valid_ip("::");

    assert_int_equal(Read_Remote_JSON(full, ts->logr), 0);
    assert_int_equal(ts->logr->https.verification_mode, REMOTED_HTTPS_VERIFY_FULL);
    assert_int_equal(ts->logr->https.dual_stack, REMOTED_HTTPS_DUAL_STACK_YES);

    /* bind_addr stays "::" from the first document, so no "only applies to IPv6" warning */
    assert_int_equal(Read_Remote_JSON(off, ts->logr), 0);
    assert_int_equal(ts->logr->https.dual_stack, REMOTED_HTTPS_DUAL_STACK_NO);

    cJSON_Delete(full);
    cJSON_Delete(off);
}

static void test_Read_Remote_JSON_https_string_too_long(void **state) {
    test_state *ts = *state;
    char address[REMOTED_HTTPS_BIND_ADDR_MAX_LEN + 2];
    char json[REMOTED_HTTPS_BIND_ADDR_MAX_LEN + 64];

    memset(address, 'a', sizeof(address) - 1);
    address[sizeof(address) - 1] = '\0';
    snprintf(json, sizeof(json), "{\"https\":{\"bind_addr\":\"%s\"}}", address);
    cJSON *remote = json_or_fail(json);

    expect_string(__wrap__merror, formatted_msg,
                  "Value for '<remote><https><bind_addr>' exceeds the maximum length of 255 characters.");

    assert_int_equal(Read_Remote_JSON(remote, ts->logr), OS_INVALID);

    cJSON_Delete(remote);
}

/* RemotedConfig() over the mocked YAML document */

static void test_RemotedConfig_loads_sections_from_mconf(void **state) {
    (void) state;
    reset_global_logr();

    mock_remoted_internal_options(1);

    assert_int_equal(RemotedConfig("test_ossec.conf", &logr), 1);
    assert_true(logr.legacy_enabled);
    assert_int_equal(logr.port, 1514);
    assert_int_equal(logr.proto, REMOTED_NET_PROTOCOL_TCP);
    assert_string_equal(logr.lip, REMOTED_LEGACY_LOCAL_IP_DEFAULT);
    assert_int_equal(logr.queue_size, 131072);
    assert_int_equal(logr.global.agents_disconnection_time, 900);
    assert_int_equal(logr.global.agents_disconnection_alert_time, 0);

    os_free(logr.lip);
}

static void test_RemotedConfig_fails_when_mconf_load_fails(void **state) {
    (void) state;
    reset_global_logr();

    mock_remoted_internal_option_values(1);
    expect_string(__wrap_w_mconf_load, cfgfile, "bad.yml");
    will_return(__wrap_w_mconf_load, -1); // the helper already logged CONFIG_YAML_INVALID

    assert_int_equal(RemotedConfig("bad.yml", &logr), OS_INVALID);
}

/* getconfig: the effective sections, not a hand-built view of the struct */

static void test_getRemoteConfig_returns_effective_section(void **state) {
    (void) state;

    expect_string(__wrap_w_mconf_section, section, "remote");
    will_return(__wrap_w_mconf_section,
                cJSON_Parse("{\"https\":{\"port\":1517,\"ca\":\"\",\"max_body_size\":\"2M\"},\"legacy\":{\"enabled\":true}}"));

    cJSON *root = getRemoteConfig();
    cJSON *remote = cJSON_GetObjectItem(root, "remote");
    assert_true(cJSON_IsObject(remote));

    cJSON *https = cJSON_GetObjectItem(remote, "https");
    assert_int_equal(cJSON_GetObjectItem(https, "port")->valueint, 1517);
    assert_non_null(cJSON_GetObjectItem(https, "ca"));
    assert_string_equal(cJSON_GetObjectItem(https, "max_body_size")->valuestring, "2M");
    assert_true(cJSON_IsTrue(cJSON_GetObjectItem(cJSON_GetObjectItem(remote, "legacy"), "enabled")));

    cJSON_Delete(root);
}

static void test_getRemoteConfig_without_document_is_empty(void **state) {
    (void) state;

    expect_string(__wrap_w_mconf_section, section, "remote");
    will_return(__wrap_w_mconf_section, NULL);

    cJSON *root = getRemoteConfig();
    cJSON *remote = cJSON_GetObjectItem(root, "remote");
    assert_true(cJSON_IsObject(remote));
    assert_null(remote->child);

    cJSON_Delete(root);
}

static void test_getRemoteGlobalConfig_returns_effective_section(void **state) {
    (void) state;

    expect_string(__wrap_w_mconf_section, section, "global");
    will_return(__wrap_w_mconf_section,
                cJSON_Parse("{\"agents_disconnection_time\":900,\"agents_disconnection_alert_time\":0}"));

    cJSON *root = getRemoteGlobalConfig();
    cJSON *global = cJSON_GetObjectItem(root, "global");
    assert_true(cJSON_IsObject(global));
    assert_int_equal(cJSON_GetObjectItem(global, "agents_disconnection_time")->valueint, 900);
    assert_null(cJSON_GetObjectItem(global, "remoted"));

    cJSON_Delete(root);
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
        cmocka_unit_test(test_remoted_queue_size_above_threshold_warns),
        cmocka_unit_test(test_remoted_queue_size_at_threshold_does_not_warn),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_legacy_valid_port, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_legacy_invalid_port, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_legacy_connection_section, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_legacy_allowed_ips_section, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_legacy_denied_ips_section, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_legacy_enabled_yes, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_legacy_enabled_no, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_legacy_enabled_invalid, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_valid_full, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_invalid_port, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_invalid_bind_addr, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_global_prefix_valid, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_global_prefix_root_identity, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_global_prefix_no_trailing_slash, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_global_prefix_multi_segment, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_global_prefix_max_len_boundary, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_global_prefix_too_long, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_global_prefix_empty, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_global_prefix_no_leading_slash, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_global_prefix_empty_segment, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_global_prefix_bad_chars, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_global_prefix_dot_segment, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_invalid_verification_mode, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_invalid_ciphers, setup, teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_parse_https_invalid_dual_stack, setup, teardown),
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
        cmocka_unit_test_setup_teardown(test_read_remote_no_legacy_block_disables_legacy, setup, teardown),
        cmocka_unit_test_setup_teardown(test_read_remote_legacy_block_present_defaults_applied, setup, teardown),
        cmocka_unit_test_setup_teardown(test_read_remote_explicit_values_cleared_when_disabled, setup, teardown),
        cmocka_unit_test_setup_teardown(test_read_remote_local_ip_not_defaulted_for_ipv6, setup, teardown),

        /* Read_Remote_JSON() -- the effective `remote` section of etc/wazuh-manager.yml */
        cmocka_unit_test_setup_teardown(test_Read_Remote_JSON_effective_defaults, setup, teardown),
        cmocka_unit_test_setup_teardown(test_Read_Remote_JSON_legacy_disabled_clears_listener, setup, teardown),
        cmocka_unit_test_setup_teardown(test_Read_Remote_JSON_protocol_list_and_ipv6_without_local_ip, setup, teardown),
        cmocka_unit_test_setup_teardown(test_Read_Remote_JSON_durations_and_sizes_int_or_string, setup, teardown),
        cmocka_unit_test_setup_teardown(test_Read_Remote_JSON_ca_infers_certificate_mode, setup, teardown),
        cmocka_unit_test_setup_teardown(test_Read_Remote_JSON_enum_and_dual_stack, setup, teardown),
        cmocka_unit_test_setup_teardown(test_Read_Remote_JSON_https_string_too_long, setup, teardown),

        /* RemotedConfig() and getconfig over the mocked YAML document (global logr, no fixture) */
        cmocka_unit_test(test_RemotedConfig_loads_sections_from_mconf),
        cmocka_unit_test(test_RemotedConfig_fails_when_mconf_load_fails),
        cmocka_unit_test(test_getRemoteConfig_returns_effective_section),
        cmocka_unit_test(test_getRemoteConfig_without_document_is_empty),
        cmocka_unit_test(test_getRemoteGlobalConfig_returns_effective_section),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
