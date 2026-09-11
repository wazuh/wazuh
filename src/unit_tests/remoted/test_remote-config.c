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

int w_remoted_https_check_max_len(const char * element, const char * content, size_t max_len);
int w_remoted_validate_tls13_ciphers(const char * ciphers);
int w_remoted_validate_global_prefix(const char * prefix);

int Read_Remote_JSON(const cJSON *remote, void *d1);

/* Queue size the mocked `remote` section carries into RemotedConfig(): -1 = omit the key (the reader
 * then keeps the 131072 RemotedConfig() pre-sets), otherwise the value the post-load validation sees. */
static long s_mconf_queue_size = -1;

/* The `remote` section w_mconf_section() returns for a default installation. No local_ip, so the
 * OS_IsValidIP wrap is not involved and the reader fills 0.0.0.0 itself. */
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
    remoted *logr;
} test_state;

/* setup/teardown */

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

/* Internal options plus the document RemotedConfig() loads (one w_mconf_load, then the
 * `remote` and `global` sections) and the cluster getters. */
static void mock_remoted_internal_options(int legacy_value) {
    mock_remoted_internal_option_values(legacy_value);

    expect_string(__wrap_w_mconf_load, cfgfile, "test_ossec.conf");
    will_return(__wrap_w_mconf_load, 0);
    expect_string(__wrap_w_mconf_section, section, "remote");
    will_return(__wrap_w_mconf_section, mock_remote_section());
    expect_string(__wrap_w_mconf_section, section, "global");
    will_return(__wrap_w_mconf_section,
                cJSON_Parse("{\"agents_disconnection_time\":900}"));

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
    // https.verification_mode stays distinguishable from an explicit "none".
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

/* docs/ref/modules/remoted/configuration.md documents that queue_size above
 * 262144 logs a warning (confirmed in config.c: `if (cfg->queue_size > 262144)`),
 * which had no test anywhere in this file. s_mconf_queue_size puts that value in the
 * mocked `remote` section, since the loader itself is mocked out here. */
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


/* Validators shared with Read_Remote_JSON(), exercised directly now that the XML reader is gone. */

static void test_w_remoted_validate_global_prefix_accepts_usable_prefixes(void **state) {
    (void) state;
    assert_int_equal(w_remoted_validate_global_prefix("/"), OS_SUCCESS);
    assert_int_equal(w_remoted_validate_global_prefix("/wazuh-manager-5/"), OS_SUCCESS);
    assert_int_equal(w_remoted_validate_global_prefix("/a/b_c.d~e"), OS_SUCCESS);
}

static void test_w_remoted_validate_global_prefix_rejects_empty_and_relative(void **state) {
    (void) state;
    expect_string(__wrap__merror, formatted_msg, "Invalid 'remote.https.global_prefix' option: the value cannot be empty.");
    assert_int_equal(w_remoted_validate_global_prefix(""), OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "Invalid 'remote.https.global_prefix' option: the value cannot be empty.");
    assert_int_equal(w_remoted_validate_global_prefix(NULL), OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "Invalid 'remote.https.global_prefix' option: 'wazuh' must start with '/'.");
    assert_int_equal(w_remoted_validate_global_prefix("wazuh"), OS_INVALID);
}

static void test_w_remoted_validate_global_prefix_rejects_bad_chars_and_segments(void **state) {
    (void) state;
    expect_string(__wrap__merror, formatted_msg, "Invalid character '?' in the 'remote.https.global_prefix' option: allowed "
                  "characters are A-Z, a-z, 0-9, '.', '_', '~', '-' and '/'.");
    assert_int_equal(w_remoted_validate_global_prefix("/a?b"), OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "Invalid 'remote.https.global_prefix' option: '/a//b' contains an empty path segment ('//').");
    assert_int_equal(w_remoted_validate_global_prefix("/a//b"), OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "Invalid 'remote.https.global_prefix' option: '/a/../b' contains a '.' or '..' path segment.");
    assert_int_equal(w_remoted_validate_global_prefix("/a/../b"), OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "Invalid 'remote.https.global_prefix' option: '/./a' contains a '.' or '..' path segment.");
    assert_int_equal(w_remoted_validate_global_prefix("/./a"), OS_INVALID);
}

static void test_w_remoted_validate_tls13_ciphers_accepts_and_rejects(void **state) {
    (void) state;
    assert_int_equal(w_remoted_validate_tls13_ciphers("TLS_AES_256_GCM_SHA384"), OS_SUCCESS);
    assert_int_equal(w_remoted_validate_tls13_ciphers("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"), OS_SUCCESS);
    expect_string(__wrap__merror, formatted_msg, "Invalid 'remote.https.ciphers' option: expected TLS 1.3 cipher suite names.");
    assert_int_equal(w_remoted_validate_tls13_ciphers(""), OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "Invalid 'remote.https.ciphers' option: 'TLS_AES_256_GCM_SHA384::TLS_CHACHA20_POLY1305_SHA256' "
                  "has an empty cipher suite name.");
    assert_int_equal(w_remoted_validate_tls13_ciphers("TLS_AES_256_GCM_SHA384::TLS_CHACHA20_POLY1305_SHA256"), OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "Invalid TLS 1.3 cipher suite 'ECDHE-RSA-AES128-GCM-SHA256' in the 'remote.https.ciphers' option.");
    assert_int_equal(w_remoted_validate_tls13_ciphers("ECDHE-RSA-AES128-GCM-SHA256:TLS_AES_256_GCM_SHA384"), OS_INVALID);
}

static void test_w_remoted_https_check_max_len_boundary(void **state) {
    (void) state;
    assert_int_equal(w_remoted_https_check_max_len("certificate", "abc", 3), OS_SUCCESS);
    expect_string(__wrap__merror, formatted_msg, "Value for 'remote.https.certificate' exceeds the maximum length of 3 characters.");
    assert_int_equal(w_remoted_https_check_max_len("certificate", "abcd", 3), OS_INVALID);
}

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
    /* What the loader returns for tests/vectors/valid/generated-manager.conf (E1a) */
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
    /* No local_ip and an IPv6 listener: the reader must not fall back to 0.0.0.0 (P61) */
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
                  "The 'remote.https.ca' option is configured but 'verification_mode' is not; "
                  "defaulting 'verification_mode' to 'certificate'.");

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
                  "Value for 'remote.https.bind_addr' exceeds the maximum length of 255 characters.");

    assert_int_equal(Read_Remote_JSON(remote, ts->logr), OS_INVALID);

    cJSON_Delete(remote);
}

/* RemotedConfig() over the mocked document */

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

    os_free(logr.lip);
}

static void test_RemotedConfig_fails_when_mconf_load_fails(void **state) {
    (void) state;
    reset_global_logr();

    mock_remoted_internal_option_values(1);
    expect_string(__wrap_w_mconf_load, cfgfile, "bad.conf");
    will_return(__wrap_w_mconf_load, -1); // the helper already logged CONFIG_INVALID

    assert_int_equal(RemotedConfig("bad.conf", &logr), OS_INVALID);
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
                cJSON_Parse("{\"agents_disconnection_time\":900}"));

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
        /* Internal options and post-load validation */
        cmocka_unit_test(test_remoted_internal_options_config),
        cmocka_unit_test(test_remoted_legacy_task_polling_interval_bounds),
        cmocka_unit_test(test_remoted_queue_size_above_threshold_warns),
        cmocka_unit_test(test_remoted_queue_size_at_threshold_does_not_warn),

        /* Validators shared by Read_Remote_JSON() */
        cmocka_unit_test(test_w_remoted_validate_global_prefix_accepts_usable_prefixes),
        cmocka_unit_test(test_w_remoted_validate_global_prefix_rejects_empty_and_relative),
        cmocka_unit_test(test_w_remoted_validate_global_prefix_rejects_bad_chars_and_segments),
        cmocka_unit_test(test_w_remoted_validate_tls13_ciphers_accepts_and_rejects),
        cmocka_unit_test(test_w_remoted_https_check_max_len_boundary),

        /* Read_Remote_JSON() -- the effective `remote` section of etc/wazuh-manager.conf */
        cmocka_unit_test_setup_teardown(test_Read_Remote_JSON_effective_defaults, setup, teardown),
        cmocka_unit_test_setup_teardown(test_Read_Remote_JSON_legacy_disabled_clears_listener, setup, teardown),
        cmocka_unit_test_setup_teardown(test_Read_Remote_JSON_protocol_list_and_ipv6_without_local_ip, setup, teardown),
        cmocka_unit_test_setup_teardown(test_Read_Remote_JSON_durations_and_sizes_int_or_string, setup, teardown),
        cmocka_unit_test_setup_teardown(test_Read_Remote_JSON_ca_infers_certificate_mode, setup, teardown),
        cmocka_unit_test_setup_teardown(test_Read_Remote_JSON_enum_and_dual_stack, setup, teardown),
        cmocka_unit_test_setup_teardown(test_Read_Remote_JSON_https_string_too_long, setup, teardown),

        /* RemotedConfig() and getconfig over the mocked document (global logr, no fixture) */
        cmocka_unit_test(test_RemotedConfig_loads_sections_from_mconf),
        cmocka_unit_test(test_RemotedConfig_fails_when_mconf_load_fails),
        cmocka_unit_test(test_getRemoteConfig_returns_effective_section),
        cmocka_unit_test(test_getRemoteConfig_without_document_is_empty),
        cmocka_unit_test(test_getRemoteGlobalConfig_returns_effective_section),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
