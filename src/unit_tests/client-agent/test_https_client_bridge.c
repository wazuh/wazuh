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

#include "shared.h"
#include "agentd.h"
#include "https_client_bridge.h"
#include "https_client.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* hc_create/hc_start/hc_destroy mocks (no pre-existing wrapper for this ABI):
 * hc_create captures both the config and the callback table it was given, so
 * tests can inspect exactly what the bridge built and invoke its callbacks
 * directly (e.g. on_reenroll_required) without a real https_client module. */
static hc_config_t g_captured_config;
static bool g_captured_config_valid = false;
static hc_callbacks_t g_captured_callbacks;

hc_handle *__wrap_hc_create(const hc_config_t *config, const hc_callbacks_t *callbacks)
{
    check_expected_ptr(callbacks);
    if (config) {
        g_captured_config = *config;
        g_captured_config_valid = true;
    }
    if (callbacks) {
        g_captured_callbacks = *callbacks;
    }
    return (hc_handle *)mock();
}

bool __wrap_hc_start(hc_handle *handle)
{
    check_expected_ptr(handle);
    return mock();
}

void __wrap_hc_destroy(hc_handle *handle)
{
    check_expected_ptr(handle);
}

bool __wrap_hc_set_agent_key(hc_handle *handle, const char *key_hex)
{
    check_expected_ptr(handle);
    check_expected(key_hex);
    return mock();
}

bool __wrap_hc_submit_event(hc_handle *handle, const uint8_t *frame, size_t length)
{
    check_expected_ptr(handle);
    check_expected(frame);
    check_expected(length);
    return mock();
}

int __wrap_try_enroll_to_server(const char *server_rip, uint32_t network_interface)
{
    check_expected(server_rip);
    check_expected(network_interface);
    return mock();
}

void __wrap_w_agentd_state_update(w_agentd_state_update_t type, void *data)
{
    check_expected(type);
    check_expected(data);
}

/* bridge_build_config() reads the client-buffer occupancy options exactly as
 * buffer_init() does, and the real getDefine_Int() merror_exit()s when a name
 * is not in internal_options.conf. No case here exercises those values, so
 * answer with the shipped defaults instead of scripting three returns into
 * every test that starts the client. */
int __wrap_getDefine_Int(const char *high_name, const char *low_name, int min, int max)
{
    (void)high_name;
    (void)min;
    (void)max;

    if (strcmp(low_name, "warn_level") == 0) {
        return 90;
    }
    if (strcmp(low_name, "normal_level") == 0) {
        return 70;
    }
    if (strcmp(low_name, "tolerance") == 0) {
        return 15;
    }

    return 0;
}

/* bridge_reenroll_thread is not static (see its own comment) precisely so it
 * can be called directly here, synchronously, bypassing w_create_thread.
 * g_https_client_stopping is likewise not static: setup_test() below resets
 * it every test, since w_https_client_start() (the normal reset point) isn't
 * called by the tests that invoke bridge_reenroll_thread directly. */
extern void *bridge_reenroll_thread(void *arg);
extern bool g_https_client_stopping;

/* A fake, never-dereferenced handle: the bridge only compares it against
 * NULL and passes it back to hc_start/hc_destroy, both mocked here. */
static hc_handle *const FAKE_HANDLE = (hc_handle *)0x1;

static void add_server_config(const char *address, int port)
{
    os_calloc(2, sizeof(agent_server), agt->server);
    os_strdup(address, agt->server[0].rip);
    agt->server[0].port = port;
    agt->server_count = 1;
}

static void set_agent_key(const char *id, const char *raw_key)
{
    os_calloc(1, sizeof(keyentry *), keys.keyentries);
    os_calloc(1, sizeof(keyentry), keys.keyentries[0]);
    if (id) {
        os_strdup(id, keys.keyentries[0]->id);
    }
    if (raw_key) {
        os_strdup(raw_key, keys.keyentries[0]->raw_key);
    }
}

/* Allocates agt->enrollment_cfg with enabled=true; when manager_name is
 * non-NULL also sets an enrollment target (the address tried first). Mirrors
 * the shape start_agent.c/register_configure_agent.sh build at runtime. */
static void enable_enrollment(const char *manager_name)
{
    agt->enrollment_cfg = (w_enrollment_ctx *)calloc(1, sizeof(w_enrollment_ctx));
    agt->enrollment_cfg->enabled = true;
    if (manager_name) {
        agt->enrollment_cfg->target_cfg = (w_enrollment_target *)calloc(1, sizeof(w_enrollment_target));
        os_strdup(manager_name, agt->enrollment_cfg->target_cfg->manager_name);
    }
}

static int setup_test(void **state)
{
    (void)state;
    agt = (agent *)calloc(1, sizeof(agent));
    memset(&keys, 0, sizeof(keys));
    g_captured_config_valid = false;
    g_https_client_stopping = false;

    add_server_config("10.0.0.1", 8443);
    /* A syntactically valid 64-hex-char (32-byte, AES-256) key by default;
     * individual tests override this to exercise the rejection paths. */
    set_agent_key("001", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    return 0;
}

static int teardown_test(void **state)
{
    (void)state;
    w_https_client_stop();

    if (agt) {
        if (agt->server) {
            os_free(agt->server[0].rip);
            os_free(agt->server);
        }
        os_free(agt->profile);
        os_free(agt->ssl.certificate);
        os_free(agt->ssl.key);
        os_free(agt->ssl.certificate_authorities);
        os_free(agt->ssl.ciphers);
        if (agt->enrollment_cfg) {
            if (agt->enrollment_cfg->target_cfg) {
                os_free(agt->enrollment_cfg->target_cfg->manager_name);
                free(agt->enrollment_cfg->target_cfg);
            }
            free(agt->enrollment_cfg);
        }
        free(agt);
        agt = NULL;
    }
    if (keys.keyentries) {
        if (keys.keyentries[0]) {
            os_free(keys.keyentries[0]->id);
            os_free(keys.keyentries[0]->raw_key);
            os_free(keys.keyentries[0]);
        }
        os_free(keys.keyentries);
    }

    return 0;
}

/* verify_mode mapping + TLS field copying (the point of this workstream) */

static void test_full_verify_mode_and_ca_reach_the_module(void **state)
{
    (void)state;
    os_strdup("/etc/wazuh/ca.pem", agt->ssl.certificate_authorities);
    agt->ssl.verification_mode = AGENT_VERIFY_FULL;

    expect_string(__wrap__minfo, formatted_msg, "https_client: starting.");
    expect_any(__wrap_hc_create, callbacks);
    will_return(__wrap_hc_create, FAKE_HANDLE);
    expect_value(__wrap_hc_start, handle, FAKE_HANDLE);
    will_return(__wrap_hc_start, true);
    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);

    w_https_client_start();

    assert_true(g_captured_config_valid);
    assert_string_equal(g_captured_config.server_host, "10.0.0.1");
    assert_int_equal(g_captured_config.server_port, 8443);
    assert_string_equal(g_captured_config.agent_id, "001");
    assert_int_equal(g_captured_config.verify_mode, HC_VERIFY_FULL);
    assert_string_equal(g_captured_config.ca_path, "/etc/wazuh/ca.pem");

    w_https_client_stop(); /* Consumes the hc_destroy expectation queued above. */
}

static void test_certificate_verify_mode_maps_to_hc_verify_cert(void **state)
{
    (void)state;
    agt->ssl.verification_mode = AGENT_VERIFY_CERT;

    expect_string(__wrap__minfo, formatted_msg, "https_client: starting.");
    expect_any(__wrap_hc_create, callbacks);
    will_return(__wrap_hc_create, FAKE_HANDLE);
    expect_value(__wrap_hc_start, handle, FAKE_HANDLE);
    will_return(__wrap_hc_start, true);
    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);

    w_https_client_start();

    assert_int_equal(g_captured_config.verify_mode, HC_VERIFY_CERT);

    w_https_client_stop();
}

static void test_none_verify_mode_maps_to_hc_verify_none(void **state)
{
    (void)state;
    agt->ssl.verification_mode = AGENT_VERIFY_NONE;

    expect_string(__wrap__minfo, formatted_msg, "https_client: starting.");
    expect_any(__wrap_hc_create, callbacks);
    will_return(__wrap_hc_create, FAKE_HANDLE);
    expect_value(__wrap_hc_start, handle, FAKE_HANDLE);
    will_return(__wrap_hc_start, true);
    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);

    w_https_client_start();

    assert_int_equal(g_captured_config.verify_mode, HC_VERIFY_NONE);

    w_https_client_stop();
}

static void test_client_cert_key_and_ciphers_are_copied(void **state)
{
    (void)state;
    os_strdup("/etc/wazuh/agent.pem", agt->ssl.certificate);
    os_strdup("/etc/wazuh/agent.key", agt->ssl.key);
    os_strdup("HIGH:!aNULL", agt->ssl.ciphers);

    expect_string(__wrap__minfo, formatted_msg, "https_client: starting.");
    expect_any(__wrap_hc_create, callbacks);
    will_return(__wrap_hc_create, FAKE_HANDLE);
    expect_value(__wrap_hc_start, handle, FAKE_HANDLE);
    will_return(__wrap_hc_start, true);
    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);

    w_https_client_start();

    assert_string_equal(g_captured_config.client_cert, "/etc/wazuh/agent.pem");
    assert_string_equal(g_captured_config.client_key, "/etc/wazuh/agent.key");
    assert_string_equal(g_captured_config.ciphers, "HIGH:!aNULL");

    w_https_client_stop();
}

/* Key validation (M4): a broken client.keys must be caught once, loudly, at
 * start -- not left to fail every signing attempt silently forever. */

static void test_missing_key_refuses_to_start(void **state)
{
    (void)state;
    os_free(keys.keyentries[0]->raw_key);
    keys.keyentries[0]->raw_key = NULL;

    expect_string(__wrap__minfo, formatted_msg, "https_client: starting.");
    expect_string(__wrap__merror, formatted_msg,
                  "https_client: agent key is missing or has an invalid length for AES-CMAC "
                  "(expected 32, 48 or 64 hex characters); refusing to start.");

    w_https_client_start();
    /* No hc_create expectation: must not be reached. */
}

static void test_wrong_length_key_refuses_to_start(void **state)
{
    (void)state;
    os_free(keys.keyentries[0]->raw_key);
    os_strdup("aabbccdd", keys.keyentries[0]->raw_key); /* 8 hex chars: not 32/48/64 */

    expect_string(__wrap__minfo, formatted_msg, "https_client: starting.");
    expect_string(__wrap__merror, formatted_msg,
                  "https_client: agent key is missing or has an invalid length for AES-CMAC "
                  "(expected 32, 48 or 64 hex characters); refusing to start.");

    w_https_client_start();
}

static void test_non_hex_key_refuses_to_start(void **state)
{
    (void)state;
    os_free(keys.keyentries[0]->raw_key);
    /* Right length (32 chars) but 'z' is not a hex digit. */
    os_strdup("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", keys.keyentries[0]->raw_key);

    expect_string(__wrap__minfo, formatted_msg, "https_client: starting.");
    expect_string(__wrap__merror, formatted_msg,
                  "https_client: agent key is missing or has an invalid length for AES-CMAC "
                  "(expected 32, 48 or 64 hex characters); refusing to start.");

    w_https_client_start();
}

static void test_valid_48_char_key_is_accepted(void **state)
{
    (void)state;
    os_free(keys.keyentries[0]->raw_key);
    os_strdup("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", keys.keyentries[0]->raw_key); /* 48 hex chars */

    expect_string(__wrap__minfo, formatted_msg, "https_client: starting.");
    expect_any(__wrap_hc_create, callbacks);
    will_return(__wrap_hc_create, FAKE_HANDLE);
    expect_value(__wrap_hc_start, handle, FAKE_HANDLE);
    will_return(__wrap_hc_start, true);
    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);

    w_https_client_start();

    assert_string_equal(g_captured_config.agent_key,
                         "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    w_https_client_stop();
}

/* Lifecycle failure paths */

static void test_hc_create_failure_is_logged(void **state)
{
    (void)state;
    expect_string(__wrap__minfo, formatted_msg, "https_client: starting.");
    expect_any(__wrap_hc_create, callbacks);
    will_return(__wrap_hc_create, NULL);
    expect_string(__wrap__merror, formatted_msg, "https_client: failed to create the client instance.");

    w_https_client_start();
    /* No hc_start/hc_destroy expectation: neither must be reached. */
}

static void test_hc_start_failure_destroys_and_logs(void **state)
{
    (void)state;
    expect_string(__wrap__minfo, formatted_msg, "https_client: starting.");
    expect_any(__wrap_hc_create, callbacks);
    will_return(__wrap_hc_create, FAKE_HANDLE);
    expect_value(__wrap_hc_start, handle, FAKE_HANDLE);
    will_return(__wrap_hc_start, false);
    expect_string(__wrap__merror, formatted_msg, "https_client: failed to start (configuration rejected).");
    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);

    w_https_client_start();
}

/* 401 -> re-enrollment (M5): bridge_on_reenroll_required's spawn decision,
 * exercised through the real callback the module would actually invoke
 * (captured from a successful w_https_client_start()). */

static void start_client_successfully(void)
{
    expect_string(__wrap__minfo, formatted_msg, "https_client: starting.");
    expect_any(__wrap_hc_create, callbacks);
    will_return(__wrap_hc_create, FAKE_HANDLE);
    expect_value(__wrap_hc_start, handle, FAKE_HANDLE);
    will_return(__wrap_hc_start, true);
    w_https_client_start();
}

static void test_reenroll_callback_disabled_enrollment_logs_error_only(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__mwarn, formatted_msg, "https_client: credential rejected (401); re-enrolling.");
    expect_string(__wrap__merror, formatted_msg,
                  "https_client: re-enrollment required but auto-enrollment is disabled "
                  "(<enrollment><enabled>); traffic stays paused until the key is fixed manually.");

    g_captured_callbacks.on_reenroll_required(g_captured_callbacks.user_data);
    /* No CreateThread expectation needed: the shared __wrap_CreateThread
     * always succeeds without invoking its argument, and this path must not
     * even reach the call. */

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_reenroll_callback_enabled_enrollment_only_warns(void **state)
{
    (void)state;
    enable_enrollment("enroll.example.com");
    start_client_successfully();

    expect_string(__wrap__mwarn, formatted_msg, "https_client: credential rejected (401); re-enrolling.");
    /* No __wrap__merror expectation: the disabled-path error must not fire. */

    g_captured_callbacks.on_reenroll_required(g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* bridge_reenroll_thread's retry-loop logic, called directly (synchronously)
 * to bypass w_create_thread/CreateThread -- the shared CreateThread test
 * double intentionally never runs the function it's handed. */

static void test_reenroll_thread_succeeds_on_first_attempt(void **state)
{
    (void)state;
    enable_enrollment("enroll.example.com");

    expect_string(__wrap_try_enroll_to_server, server_rip, "enroll.example.com");
    expect_value(__wrap_try_enroll_to_server, network_interface, 0);
    will_return(__wrap_try_enroll_to_server, 0);
    expect_value(__wrap_hc_set_agent_key, handle, FAKE_HANDLE);
    expect_string(__wrap_hc_set_agent_key, key_hex, keys.keyentries[0]->raw_key);
    will_return(__wrap_hc_set_agent_key, true);
    expect_string(__wrap__minfo, formatted_msg,
                  "https_client: re-enrollment succeeded; reloading the signing key.");

    bridge_reenroll_thread(FAKE_HANDLE);
}

static void test_reenroll_thread_falls_back_to_server_without_enrollment_target(void **state)
{
    (void)state;
    enable_enrollment(NULL); /* enrollment_cfg->target_cfg stays NULL */

    expect_string(__wrap_try_enroll_to_server, server_rip, "10.0.0.1"); /* agt->server[0], from setup_test */
    expect_value(__wrap_try_enroll_to_server, network_interface, 0);
    will_return(__wrap_try_enroll_to_server, 0);
    expect_value(__wrap_hc_set_agent_key, handle, FAKE_HANDLE);
    expect_string(__wrap_hc_set_agent_key, key_hex, keys.keyentries[0]->raw_key);
    will_return(__wrap_hc_set_agent_key, true);
    expect_string(__wrap__minfo, formatted_msg,
                  "https_client: re-enrollment succeeded; reloading the signing key.");

    bridge_reenroll_thread(FAKE_HANDLE);
}

static void test_reenroll_thread_retries_with_backoff_then_succeeds(void **state)
{
    (void)state;
    enable_enrollment("enroll.example.com");

    /* First pass: the enrollment target fails, so (mirroring
     * w_agentd_keys_init) the same pass also falls back to agt->server[0]
     * before ever sleeping -- only a whole failed pass waits. */
    expect_string(__wrap_try_enroll_to_server, server_rip, "enroll.example.com");
    expect_value(__wrap_try_enroll_to_server, network_interface, 0);
    will_return(__wrap_try_enroll_to_server, -1);

    expect_string(__wrap_try_enroll_to_server, server_rip, "10.0.0.1"); /* agt->server[0], from setup_test */
    expect_value(__wrap_try_enroll_to_server, network_interface, 0);
    will_return(__wrap_try_enroll_to_server, -1);

    expect_string(__wrap__mdebug1, formatted_msg,
                  "https_client: re-enrollment attempt failed; retrying in 5 seconds.");
    expect_value(__wrap_sleep, seconds, 5); /* first back-off step */

    /* Second pass: the enrollment target succeeds immediately, no fallback. */
    expect_string(__wrap_try_enroll_to_server, server_rip, "enroll.example.com");
    expect_value(__wrap_try_enroll_to_server, network_interface, 0);
    will_return(__wrap_try_enroll_to_server, 0);

    expect_value(__wrap_hc_set_agent_key, handle, FAKE_HANDLE);
    expect_string(__wrap_hc_set_agent_key, key_hex, keys.keyentries[0]->raw_key);
    will_return(__wrap_hc_set_agent_key, true);
    expect_string(__wrap__minfo, formatted_msg,
                  "https_client: re-enrollment succeeded; reloading the signing key.");

    bridge_reenroll_thread(FAKE_HANDLE);
}

static void test_reenroll_thread_aborts_when_stopping_flag_already_set(void **state)
{
    (void)state;
    enable_enrollment("enroll.example.com");

    w_https_client_stop(); /* g_https_client is NULL here, so no hc_destroy call; only sets the flag. */

    expect_string(__wrap__mdebug1, formatted_msg,
                  "https_client: agent shutting down; abandoning re-enrollment.");

    bridge_reenroll_thread(FAKE_HANDLE);
    /* No try_enroll_to_server/hc_set_agent_key expectation: must not be reached. */
}

static void test_reenroll_thread_logs_error_when_new_key_fails_validation(void **state)
{
    (void)state;
    enable_enrollment("enroll.example.com");

    expect_string(__wrap_try_enroll_to_server, server_rip, "enroll.example.com");
    expect_value(__wrap_try_enroll_to_server, network_interface, 0);
    will_return(__wrap_try_enroll_to_server, 0);
    expect_value(__wrap_hc_set_agent_key, handle, FAKE_HANDLE);
    expect_string(__wrap_hc_set_agent_key, key_hex, keys.keyentries[0]->raw_key);
    will_return(__wrap_hc_set_agent_key, false);
    expect_string(__wrap__minfo, formatted_msg,
                  "https_client: re-enrollment succeeded; reloading the signing key.");
    expect_string(__wrap__merror, formatted_msg,
                  "https_client: re-enrolled, but the new key failed validation; traffic stays paused.");

    bridge_reenroll_thread(FAKE_HANDLE);
}

/* on_state_change -> .state (M7 partial): exercised through the real
 * callback, like the reenroll spawn-decision tests above. */

static void test_registered_state_maps_to_active(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__mdebug1, formatted_msg, "https_client connection state -> 2");
    expect_value(__wrap_w_agentd_state_update, type, UPDATE_STATUS);
    expect_value(__wrap_w_agentd_state_update, data, GA_STATUS_ACTIVE);

    g_captured_callbacks.on_state_change(HC_STATE_REGISTERED, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_starting_state_maps_to_pending(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__mdebug1, formatted_msg, "https_client connection state -> 1");
    expect_value(__wrap_w_agentd_state_update, type, UPDATE_STATUS);
    expect_value(__wrap_w_agentd_state_update, data, GA_STATUS_PENDING);

    g_captured_callbacks.on_state_change(HC_STATE_STARTING, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_stopped_state_maps_to_nactive(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__mdebug1, formatted_msg, "https_client connection state -> 0");
    expect_value(__wrap_w_agentd_state_update, type, UPDATE_STATUS);
    expect_value(__wrap_w_agentd_state_update, data, GA_STATUS_NACTIVE);

    g_captured_callbacks.on_state_change(HC_STATE_STOPPED, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_rejected_state_maps_to_nactive(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__mdebug1, formatted_msg, "https_client connection state -> 3");
    expect_value(__wrap_w_agentd_state_update, type, UPDATE_STATUS);
    expect_value(__wrap_w_agentd_state_update, data, GA_STATUS_NACTIVE);

    g_captured_callbacks.on_state_change(HC_STATE_REJECTED, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* w_https_client_submit_event: the stateless intake seam (#37835) */

static void test_submit_event_forwards_the_frame_to_the_module(void **state)
{
    (void)state;
    const char *frame = "1:/var/log/syslog:hello";
    start_client_successfully();

    expect_value(__wrap_hc_submit_event, handle, FAKE_HANDLE);
    expect_string(__wrap_hc_submit_event, frame, frame);
    expect_value(__wrap_hc_submit_event, length, strlen(frame));
    will_return(__wrap_hc_submit_event, true);

    assert_int_equal(w_https_client_submit_event(frame, strlen(frame)), 0);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_submit_event_reports_a_dropped_frame(void **state)
{
    (void)state;
    const char *frame = "1:/var/log/syslog:dropped";
    start_client_successfully();

    /* The accumulator is full: drop-newest, traced like the leaky bucket did. */
    expect_value(__wrap_hc_submit_event, handle, FAKE_HANDLE);
    expect_string(__wrap_hc_submit_event, frame, frame);
    expect_value(__wrap_hc_submit_event, length, strlen(frame));
    will_return(__wrap_hc_submit_event, false);
    expect_string(__wrap__mdebug2, formatted_msg,
                  "https_client: unable to store new packet: buffer is full.");

    assert_int_equal(w_https_client_submit_event(frame, strlen(frame)), -1);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_submit_event_rejects_an_empty_frame(void **state)
{
    (void)state;
    start_client_successfully();

    /* Guarded before the module is ever reached: no hc_submit_event expectation
     * is queued, so cmocka fails the test if one is made. */
    assert_int_equal(w_https_client_submit_event(NULL, 8), -1);
    assert_int_equal(w_https_client_submit_event("frame", 0), -1);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_submit_event_is_a_noop_before_start(void **state)
{
    (void)state;
    /* No client yet: the handle is NULL, so nothing may be called through it. */
    assert_int_equal(w_https_client_submit_event("1:/loc:early", 12), -1);
}

static void test_submit_event_is_a_noop_once_stopping(void **state)
{
    (void)state;
    start_client_successfully();

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();

    /* After stop() the handle is destroyed; the stopping flag is what keeps a
     * late intake frame from reaching freed memory. */
    assert_int_equal(w_https_client_submit_event("1:/loc:late", 11), -1);
}

static void test_auth_error_state_maps_to_nactive(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__mdebug1, formatted_msg, "https_client connection state -> 4");
    expect_value(__wrap_w_agentd_state_update, type, UPDATE_STATUS);
    expect_value(__wrap_w_agentd_state_update, data, GA_STATUS_NACTIVE);

    g_captured_callbacks.on_state_change(HC_STATE_AUTH_ERROR, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_full_verify_mode_and_ca_reach_the_module, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_certificate_verify_mode_maps_to_hc_verify_cert, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_none_verify_mode_maps_to_hc_verify_none, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_client_cert_key_and_ciphers_are_copied, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_missing_key_refuses_to_start, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wrong_length_key_refuses_to_start, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_non_hex_key_refuses_to_start, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_valid_48_char_key_is_accepted, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_hc_create_failure_is_logged, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_hc_start_failure_destroys_and_logs, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_reenroll_callback_disabled_enrollment_logs_error_only, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_reenroll_callback_enabled_enrollment_only_warns, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_reenroll_thread_succeeds_on_first_attempt, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_reenroll_thread_falls_back_to_server_without_enrollment_target, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_reenroll_thread_retries_with_backoff_then_succeeds, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_reenroll_thread_aborts_when_stopping_flag_already_set, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_reenroll_thread_logs_error_when_new_key_fails_validation, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_registered_state_maps_to_active, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_starting_state_maps_to_pending, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_stopped_state_maps_to_nactive, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_rejected_state_maps_to_nactive, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_auth_error_state_maps_to_nactive, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_submit_event_forwards_the_frame_to_the_module, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_submit_event_reports_a_dropped_frame, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_submit_event_rejects_an_empty_frame, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_submit_event_is_a_noop_before_start, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_submit_event_is_a_noop_once_stopping, setup_test, teardown_test),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
