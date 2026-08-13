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
#include "task_registry_client.h"
#include "vd_offset_client.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "sha256_op.h"

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

bool __wrap_hc_set_config_hash(hc_handle *handle, const char *config_hash)
{
    check_expected_ptr(handle);
    check_expected(config_hash);
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

/* bridge_on_config_downloaded's apply chain (M1/finding 1): no pre-existing
 * wrapper for these two ABIs either (unlike w_copy_file/UnmergeFiles/
 * cldir_ex_ignore below, which reuse the shared wrappers already used by
 * remoted/test_manager.c and wazuh_modules/agent_upgrade). */
int __wrap_verifyRemoteConf(void)
{
    return mock();
}

bool __wrap_reloadAgent(void)
{
    return mock();
}

void __wrap_startup_gate_release_from_https_apply(void)
{
    function_called();
}

/* bridge_on_config_downloaded() reads the gate to tell an initial apply
 * (modules still blocked, reload regardless of <auto_restart>) from a
 * configuration change on a running agent (<auto_restart> decides). */
bool __wrap_startup_gate_is_ready(void)
{
    return mock();
}

/* WAIT_FILE producer lock: no pre-existing wrapper for either ABI. */
void __wrap_os_delwait(void)
{
    function_called();
}

void __wrap_os_setwait(void)
{
    function_called();
}

/* Real-package validation fix: config_checksum's seed must be a SHA-256 of
 * SHAREDCFG_FILE (matching the module's own ConfigHashState/manager config_hash comparison
 * space), not the legacy MD5 getsharedfiles() used to seed it with. No pre-existing wrapper for
 * this ABI either. */
int __wrap_OS_SHA256_File(const char *fname, os_sha256 output, int mode)
{
    check_expected(fname);
    check_expected(mode);

    const char *hash = mock_ptr_type(const char *);
    if (!hash) {
        return -1;
    }

    strncpy(output, hash, sizeof(os_sha256) - 1);
    output[sizeof(os_sha256) - 1] = '\0';
    return 0;
}

/* bridge_on_startup_result republishes the agent metadata; the real one
 * (start_agent.c) would touch the metadata shared memory, out of scope here. */
void __wrap_w_agentd_populate_metadata(void)
{
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

/* bridge_build_config() also reads the compression toggle via
 * getDefine_Int_default(), which -- unlike getDefine_Int() above -- returns
 * default_val instead of merror_exit()ing when the key is missing. No case
 * here exercises it either, so answer with the shipped default. */
int __wrap_getDefine_Int_default(const char *high_name, const char *low_name, int min, int max, int default_val)
{
    (void)high_name;
    (void)min;
    (void)max;

    if (strcmp(low_name, "https_compression_enabled") == 0) {
        return 0;
    }

    return default_val;
}

/* bridge_reenroll_thread is not static (see its own comment) precisely so it
 * can be called directly here, synchronously, bypassing w_create_thread.
 * g_https_client_stopping is likewise not static: setup_test() below resets
 * it every test, since w_https_client_start() (the normal reset point) isn't
 * called by the tests that invoke bridge_reenroll_thread directly. */
extern void *bridge_reenroll_thread(void *arg);
extern bool g_https_client_stopping;

/* bridge_control_task_thread/bridge_upgrade_thread are
 * likewise non-static so tests can call them directly, bypassing
 * w_create_thread (whose shared __wrap_CreateThread mock never runs the
 * function it's given -- see pthreads_op_wrappers.c). Their context structs
 * are file-local to https_client_bridge.c (no header exposes them): these
 * mirrors intentionally match that layout exactly (same member order/types)
 * so a pointer built here is valid when the real code reads it as its own
 * struct. Keep them in sync if the real structs change. */
extern void *bridge_control_task_thread(void *arg);
extern void *bridge_upgrade_thread(void *arg);

struct bridge_control_task_ctx_mirror {
    char *task_id;
    bool restart;
};

struct bridge_upgrade_ctx_mirror {
    char *task_id;
    char *wpk_file;
    char *installer;
};

/* __wrap_task_registry_check_and_record, __wrap_restartAgent: no shared
 * wrapper exists for these yet (they are new). check_expected/
 * mock() so each test controls the answer. (__wrap_reloadAgent is defined
 * above, shared with the config-downloaded reload chain tests.) Returns
 * task_registry_result_t, not a plain bool, so a genuine duplicate can be
 * distinguished from a registry error -- see bridge_check_and_record_task(). */
task_registry_result_t __wrap_task_registry_check_and_record(const char *task_id)
{
    check_expected(task_id);
    return (task_registry_result_t)mock();
}

/* __wrap_vd_offset_client_observe/__wrap_vd_offset_client_clear_pending: same
 * check_expected/mock() shape as __wrap_task_registry_check_and_record above.
 * bridge_vd_offset_observe() forwards whatever ends up in *out_changed/
 * *out_pending/*out_pending_offset regardless of the real function's bool
 * return (vd_offset_client_observe() zero-initializes them on any failure
 * path, so there is nothing else for the bridge to branch on) -- so this wrap
 * does not need a will_return for its own return value; only the three out
 * params are test-controlled. bridge_vd_offset_clear_pending()'s return DOES
 * matter (it becomes the callback's own return value), so that wrap needs one. */
bool __wrap_vd_offset_client_observe(uint64_t offset, bool *out_changed, bool *out_pending,
                                     uint64_t *out_pending_offset)
{
    check_expected(offset);

    if (out_changed) {
        *out_changed = (bool)mock();
    }
    if (out_pending) {
        *out_pending = (bool)mock();
    }
    if (out_pending_offset) {
        *out_pending_offset = (uint64_t)mock();
    }

    return true;
}

bool __wrap_vd_offset_client_clear_pending(uint64_t offset)
{
    check_expected(offset);
    return (bool)mock();
}

bool __wrap_restartAgent(void)
{
    return mock();
}

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
    /* Mirrors OS_AddKey()/OS_ReadKeys(): a real (even if since-corrupted)
     * entry means keysize is at least 1. keysize == 0 is reserved for "never
     * enrolled" (see bridge_build_config()'s DEBUG-vs-ERROR split). */
    keys.keysize = 1;
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

    /* Process-wide globals bridge_on_startup_result writes into (finding 1b,
     * config.c): reset every test so none leaks state into the next one. */
    memset(&agent_module_limits, 0, sizeof(agent_module_limits));
    agent_cluster_name[0] = '\0';
    agent_agent_groups[0] = '\0';

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
    expect_string(__wrap_OS_SHA256_File, fname, SHAREDCFG_FILE);
    expect_value(__wrap_OS_SHA256_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA256_File, NULL);
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
    expect_string(__wrap_OS_SHA256_File, fname, SHAREDCFG_FILE);
    expect_value(__wrap_OS_SHA256_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA256_File, NULL);
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
    expect_string(__wrap_OS_SHA256_File, fname, SHAREDCFG_FILE);
    expect_value(__wrap_OS_SHA256_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA256_File, NULL);
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
    expect_string(__wrap_OS_SHA256_File, fname, SHAREDCFG_FILE);
    expect_value(__wrap_OS_SHA256_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA256_File, NULL);
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

static void test_config_checksum_is_sha256_of_local_merged_file(void **state)
{
    (void)state;
    static const char *const SOME_SHA256 =
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    expect_string(__wrap__minfo, formatted_msg, "https_client: starting.");
    expect_string(__wrap_OS_SHA256_File, fname, SHAREDCFG_FILE);
    expect_value(__wrap_OS_SHA256_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA256_File, SOME_SHA256);
    expect_any(__wrap_hc_create, callbacks);
    will_return(__wrap_hc_create, FAKE_HANDLE);
    expect_value(__wrap_hc_start, handle, FAKE_HANDLE);
    will_return(__wrap_hc_start, true);
    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);

    w_https_client_start();

    assert_string_equal(g_captured_config.config_checksum, SOME_SHA256);

    w_https_client_stop();
}

static void test_config_checksum_is_empty_when_local_file_unreadable(void **state)
{
    (void)state;

    expect_string(__wrap__minfo, formatted_msg, "https_client: starting.");
    expect_string(__wrap_OS_SHA256_File, fname, SHAREDCFG_FILE);
    expect_value(__wrap_OS_SHA256_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA256_File, NULL); /* Simulates OS_SHA256_File's -1 (unreadable). */
    expect_any(__wrap_hc_create, callbacks);
    will_return(__wrap_hc_create, FAKE_HANDLE);
    expect_value(__wrap_hc_start, handle, FAKE_HANDLE);
    will_return(__wrap_hc_start, true);
    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);

    w_https_client_start();

    assert_string_equal(g_captured_config.config_checksum, "");

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

/* keysize == 0 is "never enrolled yet" -- an expected transient on a fresh
 * agent, not an error. start_agent_prepare() blocks on enrollment before
 * w_https_client_start() ever runs, so this should not be reachable in
 * practice; kept as defense-in-depth against a future ordering regression. */
static void test_no_keystore_defers_at_debug(void **state)
{
    (void)state;
    os_free(keys.keyentries[0]->raw_key);
    keys.keyentries[0]->raw_key = NULL;
    keys.keysize = 0;

    expect_string(__wrap__minfo, formatted_msg, "https_client: starting.");
    expect_string(__wrap__mdebug1, formatted_msg,
                  "https_client: not enrolled yet (no client.keys); deferring start.");

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
    expect_string(__wrap_OS_SHA256_File, fname, SHAREDCFG_FILE);
    expect_value(__wrap_OS_SHA256_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA256_File, NULL);
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
    expect_string(__wrap_OS_SHA256_File, fname, SHAREDCFG_FILE);
    expect_value(__wrap_OS_SHA256_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA256_File, NULL);
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
    expect_string(__wrap_OS_SHA256_File, fname, SHAREDCFG_FILE);
    expect_value(__wrap_OS_SHA256_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA256_File, NULL);
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
    expect_string(__wrap_OS_SHA256_File, fname, SHAREDCFG_FILE);
    expect_value(__wrap_OS_SHA256_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA256_File, NULL);
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

/* Finding 2: a REGISTERED transition must clear the WAIT_FILE/os_setwait()
 * producer lock too (the interim fix for it never releasing over HTTPS). */
static void test_registered_state_maps_to_active(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__mdebug1, formatted_msg, "https_client connection state -> registered (2)");
    expect_value(__wrap_w_agentd_state_update, type, UPDATE_STATUS);
    expect_value(__wrap_w_agentd_state_update, data, GA_STATUS_ACTIVE);
    expect_function_call(__wrap_os_delwait);

    g_captured_callbacks.on_state_change(HC_STATE_REGISTERED, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* A REGISTERED transition after a reconnect must clear the lock again:
 * os_delwait() is idempotent, so this is wired unconditionally, not once. */
static void test_registered_state_twice_clears_wait_file_each_time(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__mdebug1, formatted_msg, "https_client connection state -> registered (2)");
    expect_value(__wrap_w_agentd_state_update, type, UPDATE_STATUS);
    expect_value(__wrap_w_agentd_state_update, data, GA_STATUS_ACTIVE);
    expect_function_call(__wrap_os_delwait);
    g_captured_callbacks.on_state_change(HC_STATE_REGISTERED, g_captured_callbacks.user_data);

    expect_string(__wrap__mdebug1, formatted_msg, "https_client connection state -> registered (2)");
    expect_value(__wrap_w_agentd_state_update, type, UPDATE_STATUS);
    expect_value(__wrap_w_agentd_state_update, data, GA_STATUS_ACTIVE);
    expect_function_call(__wrap_os_delwait);
    g_captured_callbacks.on_state_change(HC_STATE_REGISTERED, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* on_producer_pause: the confirmed-disconnect pause. Both directions move the
 * lock and the .state status together. */
static void test_producer_pause_arms_the_lock_and_reports_disconnected(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__mwarn, formatted_msg, "Manager unreachable. Pausing module event production.");
    expect_function_call(__wrap_os_setwait);
    expect_value(__wrap_w_agentd_state_update, type, UPDATE_STATUS);
    expect_value(__wrap_w_agentd_state_update, data, GA_STATUS_NACTIVE);

    g_captured_callbacks.on_producer_pause(true, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* The release cannot ride on on_state_change: an agent that loses the manager
 * while REGISTERED never leaves that state, so there is no transition to hook. */
static void test_producer_pause_release_clears_the_lock_and_reports_connected(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__minfo, formatted_msg, "Manager reachable again. Resuming module event production.");
    expect_function_call(__wrap_os_delwait);
    expect_value(__wrap_w_agentd_state_update, type, UPDATE_STATUS);
    expect_value(__wrap_w_agentd_state_update, data, GA_STATUS_ACTIVE);

    g_captured_callbacks.on_producer_pause(false, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_starting_state_maps_to_pending(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__mdebug1, formatted_msg, "https_client connection state -> starting (1)");
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

    expect_string(__wrap__mdebug1, formatted_msg, "https_client connection state -> stopped (0)");
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

    expect_string(__wrap__mdebug1, formatted_msg, "https_client connection state -> rejected (3)");
    expect_value(__wrap_w_agentd_state_update, type, UPDATE_STATUS);
    expect_value(__wrap_w_agentd_state_update, data, GA_STATUS_NACTIVE);

    g_captured_callbacks.on_state_change(HC_STATE_REJECTED, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* w_https_client_submit_event: the stateless intake seam */

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

    expect_string(__wrap__mdebug1, formatted_msg, "https_client connection state -> auth_error (4)");
    expect_value(__wrap_w_agentd_state_update, type, UPDATE_STATUS);
    expect_value(__wrap_w_agentd_state_update, data, GA_STATUS_NACTIVE);

    g_captured_callbacks.on_state_change(HC_STATE_AUTH_ERROR, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* bridge_on_config_downloaded: the /download apply chain + startup_gate release. */

static const char *const DOWNLOAD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85";
static const char *const DOWNLOAD_FILE = "/tmp/https-client-spool/download-xyz";

static void expect_config_downloaded_log(const char *hash, const char *file)
{
    /* expect_string() keeps a reference to this buffer rather than copying
     * it (confirmed the hard way: a local/automatic buffer here caused a
     * stack-use-after-return once bridge_on_config_downloaded() actually ran
     * and check_expected() dereferenced it) -- static so it outlives this
     * call, matching the lifetime expect_string() actually needs. */
    static char expected[256];
    snprintf(expected, sizeof(expected), "https_client config downloaded (hash=%s, file=%s)",
             hash ? hash : "?", file ? file : "?");
    expect_string(__wrap__mdebug1, formatted_msg, expected);
}

static void expect_copy_unmerge_cleanup_ok(void)
{
    expect_string(__wrap_w_copy_file, src, DOWNLOAD_FILE);
    expect_string(__wrap_w_copy_file, dst, SHAREDCFG_FILE);
    expect_value(__wrap_w_copy_file, mode, 'b');
    expect_value(__wrap_w_copy_file, silent, 0);
    will_return(__wrap_w_copy_file, 0);

    expect_string(__wrap_UnmergeFiles, finalpath, SHAREDCFG_FILE);
    expect_string(__wrap_UnmergeFiles, optdir, SHAREDCFG_DIR);
    expect_value(__wrap_UnmergeFiles, mode, OS_TEXT);
    will_return(__wrap_UnmergeFiles, 1); /* UnmergeFiles: 1 = success, 0 = failure. */

    expect_string(__wrap_cldir_ex_ignore, name, SHAREDCFG_DIR);
    will_return(__wrap_cldir_ex_ignore, 0);
}

/* The hash of the bytes just applied: a debug detail, unlike the reload the
 * user does see reported at INFO. */
static void expect_applying_config_log(void)
{
    expect_string(__wrap__mdebug1, formatted_msg,
                  "Applying configuration downloaded over HTTPS (hash="
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85).");
}

/* Anti-race sequencing: when reloadAgent() actually dispatches, the gate must
 * NOT be released here -- agentd.c's own SIGUSR1 handling
 * (needs_config_reload) releases it once the restart that reload triggers has
 * actually happened. Releasing inline regardless of reloadAgent()'s outcome
 * would let a module still blocked in startup_gate_wait_for_ready() unblock
 * and start a moment before the reload chain restarts it anyway. */
static void test_config_downloaded_happy_path_reload_dispatched_defers_gate_to_sigusr1(void **state)
{
    (void)state;
    agt->flags.remote_conf = 1;
    agt->flags.auto_restart = 1;
    start_client_successfully();

    expect_config_downloaded_log(DOWNLOAD_HASH, DOWNLOAD_FILE);
    expect_copy_unmerge_cleanup_ok();
    will_return(__wrap_verifyRemoteConf, 0); /* valid */
    expect_applying_config_log();
    will_return(__wrap_startup_gate_is_ready, false); /* Still blocked: initial apply. */
    expect_string(__wrap__minfo, formatted_msg,
                  "Agent is reloading due to shared configuration changes.");
    will_return(__wrap_reloadAgent, true);
    /* No expect_function_call(__wrap_startup_gate_release_from_https_apply):
     * must NOT be reached when the reload chain actually dispatched. */

    g_captured_callbacks.on_config_downloaded(DOWNLOAD_HASH, DOWNLOAD_FILE, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* Fallback: reloadAgent() could not even dispatch (control socket
 * unreachable -- concretely, the fresh-install/first-boot case, where
 * modulesd/monitoring processes are still blocked in their very first
 * startup_gate_wait_for_ready() call and have no prior instance to restart).
 * No SIGUSR1 will ever arrive to release the gate later, so this is the only
 * release path such an agent will ever get -- release inline. */
static void test_config_downloaded_releases_gate_when_reload_chain_unreachable(void **state)
{
    (void)state;
    agt->flags.remote_conf = 1;
    agt->flags.auto_restart = 1;
    start_client_successfully();

    expect_config_downloaded_log(DOWNLOAD_HASH, DOWNLOAD_FILE);
    expect_copy_unmerge_cleanup_ok();
    will_return(__wrap_verifyRemoteConf, 0);
    expect_applying_config_log();
    will_return(__wrap_startup_gate_is_ready, false);
    expect_string(__wrap__minfo, formatted_msg,
                  "Agent is reloading due to shared configuration changes.");
    will_return(__wrap_reloadAgent, false); /* Control socket unreachable (e.g. first boot). */
    expect_string(__wrap__mdebug1, formatted_msg,
                  "Could not dispatch the reload chain; releasing "
                  "the startup gate directly instead (no restart will arrive to do it).");
    expect_function_call(__wrap_startup_gate_release_from_https_apply);

    g_captured_callbacks.on_config_downloaded(DOWNLOAD_HASH, DOWNLOAD_FILE, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* <auto_restart>no</auto_restart> on an agent whose modules are already
 * running: the configuration is staged for the next restart, nothing is
 * reloaded behind the user's back, and the operator is told at INFO that the
 * agent is now running configuration older than what is on disk. */
static void test_config_downloaded_auto_restart_disabled_stages_without_reloading(void **state)
{
    (void)state;
    agt->flags.remote_conf = 1;
    agt->flags.auto_restart = 0;
    start_client_successfully();

    expect_config_downloaded_log(DOWNLOAD_HASH, DOWNLOAD_FILE);
    expect_copy_unmerge_cleanup_ok();
    will_return(__wrap_verifyRemoteConf, 0);
    expect_applying_config_log();
    will_return(__wrap_startup_gate_is_ready, true); /* Modules already started. */
    expect_string(__wrap__minfo, formatted_msg,
                  "Agent must restart to apply the new shared configuration; auto_restart is disabled.");
    /* No reloadAgent/gate-release expectation: must not be reached. */

    g_captured_callbacks.on_config_downloaded(DOWNLOAD_HASH, DOWNLOAD_FILE, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* <auto_restart>no</auto_restart> cannot leave modules blocked forever: with
 * the gate still closed they are waiting for this very configuration to
 * start, so the reload runs anyway, and is reported like any other restart the
 * agent decides on its own. */
static void test_config_downloaded_blocked_gate_reloads_despite_auto_restart_disabled(void **state)
{
    (void)state;
    agt->flags.remote_conf = 1;
    agt->flags.auto_restart = 0;
    start_client_successfully();

    expect_config_downloaded_log(DOWNLOAD_HASH, DOWNLOAD_FILE);
    expect_copy_unmerge_cleanup_ok();
    will_return(__wrap_verifyRemoteConf, 0);
    expect_applying_config_log();
    will_return(__wrap_startup_gate_is_ready, false);
    expect_string(__wrap__minfo, formatted_msg,
                  "Agent is reloading to apply startup hash validated configuration.");
    will_return(__wrap_reloadAgent, true);

    g_captured_callbacks.on_config_downloaded(DOWNLOAD_HASH, DOWNLOAD_FILE, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_config_downloaded_invalid_config_skips_reload_and_gate(void **state)
{
    (void)state;
    agt->flags.remote_conf = 1;
    start_client_successfully();

    expect_config_downloaded_log(DOWNLOAD_HASH, DOWNLOAD_FILE);
    expect_copy_unmerge_cleanup_ok();
    will_return(__wrap_verifyRemoteConf, -1); /* invalid */
    expect_string(__wrap__merror, formatted_msg,
                  "Downloaded configuration failed validation; not reloading.");
    /* No reloadAgent/gate-release expectation: must not be reached. */

    g_captured_callbacks.on_config_downloaded(DOWNLOAD_HASH, DOWNLOAD_FILE, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_config_downloaded_remote_conf_disabled_stages_files_only(void **state)
{
    (void)state;
    agt->flags.remote_conf = 0;
    start_client_successfully();

    expect_config_downloaded_log(DOWNLOAD_HASH, DOWNLOAD_FILE);
    expect_copy_unmerge_cleanup_ok();
    /* No verifyRemoteConf/reloadAgent/gate-release expectation: remote_conf is
     * off, mirrors receiver.c's own guard. */

    g_captured_callbacks.on_config_downloaded(DOWNLOAD_HASH, DOWNLOAD_FILE, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_config_downloaded_copy_failure_corrects_module_hash(void **state)
{
    (void)state;
    agt->flags.remote_conf = 1;
    start_client_successfully();

    expect_config_downloaded_log(DOWNLOAD_HASH, DOWNLOAD_FILE);

    expect_string(__wrap_w_copy_file, src, DOWNLOAD_FILE);
    expect_string(__wrap_w_copy_file, dst, SHAREDCFG_FILE);
    expect_value(__wrap_w_copy_file, mode, 'b');
    expect_value(__wrap_w_copy_file, silent, 0);
    will_return(__wrap_w_copy_file, -1); /* I/O error */

    expect_string(__wrap__merror, formatted_msg,
                  "Could not copy the downloaded configuration into "
                  "'" SHAREDCFG_FILE "'; keeping the previously applied one.");
    expect_value(__wrap_hc_set_config_hash, handle, FAKE_HANDLE);
    expect_string(__wrap_hc_set_config_hash, config_hash, "");
    will_return(__wrap_hc_set_config_hash, true);
    /* No UnmergeFiles/verifyRemoteConf/reloadAgent/gate-release expectation:
     * nothing was actually applied. */

    g_captured_callbacks.on_config_downloaded(DOWNLOAD_HASH, DOWNLOAD_FILE, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_config_downloaded_unmerge_failure_corrects_module_hash(void **state)
{
    (void)state;
    agt->flags.remote_conf = 1;
    start_client_successfully();

    expect_config_downloaded_log(DOWNLOAD_HASH, DOWNLOAD_FILE);

    expect_string(__wrap_w_copy_file, src, DOWNLOAD_FILE);
    expect_string(__wrap_w_copy_file, dst, SHAREDCFG_FILE);
    expect_value(__wrap_w_copy_file, mode, 'b');
    expect_value(__wrap_w_copy_file, silent, 0);
    will_return(__wrap_w_copy_file, 0);

    expect_string(__wrap_UnmergeFiles, finalpath, SHAREDCFG_FILE);
    expect_string(__wrap_UnmergeFiles, optdir, SHAREDCFG_DIR);
    expect_value(__wrap_UnmergeFiles, mode, OS_TEXT);
    will_return(__wrap_UnmergeFiles, 0); /* failure */

    expect_string(__wrap__merror, formatted_msg,
                  "Failed to unmerge the downloaded configuration "
                  "('" SHAREDCFG_FILE "'); keeping the previously applied files.");
    /* AG_IN_UNMERGE manager-visible report, now submitted to the /stateless
     * accumulator like any other event. */
    expect_value(__wrap_hc_submit_event, handle, FAKE_HANDLE);
    expect_string(__wrap_hc_submit_event, frame, "1:wazuh-agent:wazuh: Could not unmerge shared file.");
    expect_any(__wrap_hc_submit_event, length);
    will_return(__wrap_hc_submit_event, true);
    expect_value(__wrap_hc_set_config_hash, handle, FAKE_HANDLE);
    expect_string(__wrap_hc_set_config_hash, config_hash, "");
    will_return(__wrap_hc_set_config_hash, true);
    /* No cldir_ex_ignore/verifyRemoteConf/reloadAgent/gate-release expectation. */

    g_captured_callbacks.on_config_downloaded(DOWNLOAD_HASH, DOWNLOAD_FILE, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_config_downloaded_null_file_path_is_a_noop(void **state)
{
    (void)state;
    agt->flags.remote_conf = 1;
    start_client_successfully();

    expect_config_downloaded_log(DOWNLOAD_HASH, NULL);
    expect_string(__wrap__merror, formatted_msg,
                  "https_client: config downloaded callback fired without a file path; nothing to apply.");
    /* No w_copy_file expectation: must not be reached. */

    g_captured_callbacks.on_config_downloaded(DOWNLOAD_HASH, NULL, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* bridge_on_startup_result: module limits + cluster-name authority + agent groups. */

#define FULL_LIMITS_JSON_FMT \
    "{\"limits\":{\"fim\":{\"file\":%d,\"registry_key\":2,\"registry_value\":3}," \
    "\"syscollector\":{\"hotfixes\":4,\"packages\":5,\"processes\":6,\"ports\":7," \
    "\"network_iface\":8,\"network_protocol\":9,\"network_address\":10,\"hardware\":11," \
    "\"os_info\":12,\"users\":13,\"groups\":14,\"services\":15,\"browser_extensions\":16}," \
    "\"sca\":{\"checks\":17}}," \
    "\"cluster\":{\"name\":\"demo-cluster\"}," \
    "\"agent\":{\"groups\":[\"default\",\"linux\"]}}"

static void test_startup_result_rejected_does_not_touch_globals(void **state)
{
    (void)state;
    strcpy(agent_cluster_name, "sentinel");
    start_client_successfully();

    expect_string(__wrap__mdebug1, formatted_msg, "https_client startup rejected: (no metadata)");

    g_captured_callbacks.on_startup_result(false, NULL, g_captured_callbacks.user_data);

    assert_string_equal(agent_cluster_name, "sentinel"); /* Untouched: not accepted. */
    assert_false(agent_module_limits.limits_received);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_startup_result_invalid_json_logs_and_returns(void **state)
{
    (void)state;
    strcpy(agent_cluster_name, "sentinel");
    start_client_successfully();

    expect_string(__wrap__mdebug1, formatted_msg, "https_client startup accepted: not-json{");
    expect_string(__wrap__mdebug2, formatted_msg,
                  "https_client: startup metadata is not valid JSON; module limits and "
                  "cluster identity are unchanged.");

    g_captured_callbacks.on_startup_result(true, "not-json{", g_captured_callbacks.user_data);

    assert_string_equal(agent_cluster_name, "sentinel");
    assert_false(agent_module_limits.limits_received);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_startup_result_first_time_applies_without_reload(void **state)
{
    (void)state;
    char body[1024];
    snprintf(body, sizeof(body), FULL_LIMITS_JSON_FMT, 100);
    start_client_successfully();

    /* Loosen the first log's exact-match: use expect_any since the raw JSON
     * body is long and not the point of this test. */
    expect_any(__wrap__mdebug1, formatted_msg); /* "https_client startup accepted: <json>" */
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: module limits received from manager.");
    /* limits_received was false (fresh global): no changed-check, no reload. */
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: cluster identity -> name='demo-cluster'.");
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: agent groups -> default,linux.");

    g_captured_callbacks.on_startup_result(true, body, g_captured_callbacks.user_data);

    assert_true(agent_module_limits.limits_received);
    assert_int_equal(agent_module_limits.fim.file, 100);
    assert_string_equal(agent_cluster_name, "demo-cluster");
    assert_string_equal(agent_agent_groups, "default,linux");

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_startup_result_limits_changed_reloads_under_auto_restart(void **state)
{
    (void)state;
    char body_v1[1024];
    char body_v2[1024];
    snprintf(body_v1, sizeof(body_v1), FULL_LIMITS_JSON_FMT, 100);
    snprintf(body_v2, sizeof(body_v2), FULL_LIMITS_JSON_FMT, 200);
    agt->flags.auto_restart = 1;
    start_client_successfully();

    expect_any(__wrap__mdebug1, formatted_msg);
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: module limits received from manager.");
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: cluster identity -> name='demo-cluster'.");
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: agent groups -> default,linux.");
    g_captured_callbacks.on_startup_result(true, body_v1, g_captured_callbacks.user_data); /* Establishes previous_limits. */

    expect_any(__wrap__mdebug1, formatted_msg);
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: module limits received from manager.");
    expect_string(__wrap__minfo, formatted_msg, "Agent is reloading due to module limits changes.");
    will_return(__wrap_reloadAgent, true);
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: cluster identity -> name='demo-cluster'.");
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: agent groups -> default,linux.");

    g_captured_callbacks.on_startup_result(true, body_v2, g_captured_callbacks.user_data);

    assert_int_equal(agent_module_limits.fim.file, 200);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_startup_result_limits_changed_no_reload_without_auto_restart(void **state)
{
    (void)state;
    char body_v1[1024];
    char body_v2[1024];
    snprintf(body_v1, sizeof(body_v1), FULL_LIMITS_JSON_FMT, 100);
    snprintf(body_v2, sizeof(body_v2), FULL_LIMITS_JSON_FMT, 200);
    agt->flags.auto_restart = 0;
    start_client_successfully();

    expect_any(__wrap__mdebug1, formatted_msg);
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: module limits received from manager.");
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: cluster identity -> name='demo-cluster'.");
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: agent groups -> default,linux.");
    g_captured_callbacks.on_startup_result(true, body_v1, g_captured_callbacks.user_data);

    expect_any(__wrap__mdebug1, formatted_msg);
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: module limits received from manager.");
    expect_string(__wrap__mdebug1, formatted_msg, "Module limits have been updated.");
    /* No reloadAgent expectation: must not be reached. */
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: cluster identity -> name='demo-cluster'.");
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: agent groups -> default,linux.");

    g_captured_callbacks.on_startup_result(true, body_v2, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_startup_result_limits_unchanged_no_reload(void **state)
{
    (void)state;
    char body[1024];
    snprintf(body, sizeof(body), FULL_LIMITS_JSON_FMT, 100);
    agt->flags.auto_restart = 1;
    start_client_successfully();

    expect_any(__wrap__mdebug1, formatted_msg);
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: module limits received from manager.");
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: cluster identity -> name='demo-cluster'.");
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: agent groups -> default,linux.");
    g_captured_callbacks.on_startup_result(true, body, g_captured_callbacks.user_data);

    /* Same body again: module_limits_changed() must see no difference. */
    expect_any(__wrap__mdebug1, formatted_msg);
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: module limits received from manager.");
    /* No reload/"updated" log: unchanged skips the whole changed-branch. */
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: cluster identity -> name='demo-cluster'.");
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: agent groups -> default,linux.");

    g_captured_callbacks.on_startup_result(true, body, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* on_agent_groups: the Notify-driven groups refresh (bug #11). Unlike
 * bridge_apply_agent_groups() (Startup-only), this is the only thing that keeps
 * agent_agent_groups from going stale after a group-only change, since settings_hash
 * deliberately excludes groups and never re-triggers a Startup for one. */

static void test_agent_groups_notify_updates_on_change(void **state)
{
    (void)state;
    start_client_successfully();
    strcpy(agent_agent_groups, "default");

    expect_string(__wrap__mdebug1, formatted_msg, "https_client: agent groups -> default,test.");

    g_captured_callbacks.on_agent_groups("default,test", g_captured_callbacks.user_data);

    assert_string_equal(agent_agent_groups, "default,test");

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_agent_groups_notify_no_op_when_unchanged(void **state)
{
    (void)state;
    start_client_successfully();
    strcpy(agent_agent_groups, "default,test");

    /* No "agent groups ->" log expected: unchanged, so the compare-before-write
     * short-circuits before the log/republish. */
    g_captured_callbacks.on_agent_groups("default,test", g_captured_callbacks.user_data);

    assert_string_equal(agent_agent_groups, "default,test");

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_agent_groups_notify_preserves_empty(void **state)
{
    (void)state;
    start_client_successfully();
    strcpy(agent_agent_groups, "default");

    /* Empty is a real, meaningful value here (agcom.c: fallback to merged.mg),
     * never turned into "default" the way /download's own selector would. */
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: agent groups -> (none).");

    g_captured_callbacks.on_agent_groups("", g_captured_callbacks.user_data);

    assert_string_equal(agent_agent_groups, "");

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_startup_result_missing_limits_object_leaves_limits_unchanged(void **state)
{
    (void)state;
    const char *body = "{\"cluster\":{\"name\":\"demo-cluster\",\"node\":\"node01\"},"
                       "\"agent\":{\"groups\":[\"default\"]}}";
    start_client_successfully();

    expect_any(__wrap__mdebug1, formatted_msg);
    expect_string(__wrap__mdebug2, formatted_msg,
                  "https_client: no valid 'limits' object in the startup response; "
                  "module limits are unchanged.");
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: cluster identity -> name='demo-cluster'.");
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: agent groups -> default.");

    g_captured_callbacks.on_startup_result(true, body, g_captured_callbacks.user_data);

    assert_false(agent_module_limits.limits_received);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* Overwrite cluster/groups unconditionally, even to
 * empty, rather than leaving a stale value when the manager omits them. */
static void test_startup_result_cluster_and_groups_cleared_when_absent(void **state)
{
    (void)state;
    strcpy(agent_cluster_name, "stale-cluster");
    strcpy(agent_agent_groups, "stale,groups");
    start_client_successfully();

    const char *body = "{}";

    expect_string(__wrap__mdebug1, formatted_msg, "https_client startup accepted: {}");
    expect_string(__wrap__mdebug2, formatted_msg,
                  "https_client: no valid 'limits' object in the startup response; "
                  "module limits are unchanged.");
    expect_string(__wrap__mdebug1, formatted_msg, "https_client: cluster identity -> name=''.");
    /* No "agent groups ->" log: bridge_apply_agent_groups only logs when
     * the resulting CSV is non-empty. */

    g_captured_callbacks.on_startup_result(true, body, g_captured_callbacks.user_data);

    assert_string_equal(agent_cluster_name, "");
    assert_string_equal(agent_agent_groups, "");

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}


/* check_and_record_task: the durable-dedup callback the C++ module
 * calls synchronously before dispatch (ITaskIdStore/TaskIdStoreAdapter). */

static void test_check_and_record_task_new_returns_one(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap_task_registry_check_and_record, task_id, "t1");
    will_return(__wrap_task_registry_check_and_record, TASK_REGISTRY_RESULT_NEW);

    assert_int_equal(g_captured_callbacks.check_and_record_task("t1", g_captured_callbacks.user_data), 1);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_check_and_record_task_duplicate_returns_zero_and_counts_it(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap_task_registry_check_and_record, task_id, "t1");
    will_return(__wrap_task_registry_check_and_record, TASK_REGISTRY_RESULT_DUPLICATE);
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_DISCARDED_DUPLICATE);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    assert_int_equal(g_captured_callbacks.check_and_record_task("t1", g_captured_callbacks.user_data), 0);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* A registry ERROR (agent-info unreachable/malformed reply) must be
 * counted as a real failure, not silently folded into the duplicate-discard metric --
 * the two are otherwise indistinguishable (both were "false" as a plain bool). */
static void test_check_and_record_task_error_returns_zero_and_counts_failed_not_duplicate(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap_task_registry_check_and_record, task_id, "t1");
    will_return(__wrap_task_registry_check_and_record, TASK_REGISTRY_RESULT_ERROR);
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_FAILED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    assert_int_equal(g_captured_callbacks.check_and_record_task("t1", g_captured_callbacks.user_data), 0);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_check_and_record_task_null_id_returns_minus_one(void **state)
{
    (void)state;
    start_client_successfully();

    /* No task_registry_check_and_record expectation: guarded before the call. */
    assert_int_equal(g_captured_callbacks.check_and_record_task(NULL, g_captured_callbacks.user_data), -1);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* vd_offset_observe/vd_offset_clear_pending: the IVdOffsetStore backing
 * (hc_callbacks_t.vd_offset_observe/vd_offset_clear_pending) -- see
 * bridge_vd_offset_observe()/bridge_vd_offset_clear_pending(). */

static void test_vd_offset_observe_forwards_changed_pending_and_offset(void **state)
{
    (void)state;
    start_client_successfully();

    expect_value(__wrap_vd_offset_client_observe, offset, 100);
    will_return(__wrap_vd_offset_client_observe, true);  /* *out_changed */
    will_return(__wrap_vd_offset_client_observe, true);  /* *out_pending */
    will_return(__wrap_vd_offset_client_observe, 100);   /* *out_pending_offset */

    int changed = -1;
    int pending = -1;
    uint64_t pending_offset = 0;
    g_captured_callbacks.vd_offset_observe(100, &changed, &pending, &pending_offset,
                                           g_captured_callbacks.user_data);

    assert_int_equal(changed, 1);
    assert_int_equal(pending, 1);
    assert_int_equal(pending_offset, 100);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_vd_offset_observe_reports_no_change_when_not_newer(void **state)
{
    (void)state;
    start_client_successfully();

    expect_value(__wrap_vd_offset_client_observe, offset, 50);
    will_return(__wrap_vd_offset_client_observe, false); /* *out_changed */
    will_return(__wrap_vd_offset_client_observe, true);  /* *out_pending: unrelated pending state */
    will_return(__wrap_vd_offset_client_observe, 100);   /* *out_pending_offset */

    int changed = -1;
    int pending = -1;
    uint64_t pending_offset = 0;
    g_captured_callbacks.vd_offset_observe(50, &changed, &pending, &pending_offset,
                                           g_captured_callbacks.user_data);

    assert_int_equal(changed, 0);
    assert_int_equal(pending, 1);
    assert_int_equal(pending_offset, 100);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_vd_offset_observe_tolerates_null_out_params(void **state)
{
    (void)state;
    start_client_successfully();

    expect_value(__wrap_vd_offset_client_observe, offset, 100);
    will_return(__wrap_vd_offset_client_observe, true);
    will_return(__wrap_vd_offset_client_observe, true);
    will_return(__wrap_vd_offset_client_observe, 100);

    /* Must not crash when the caller doesn't care about some outputs. */
    g_captured_callbacks.vd_offset_observe(100, NULL, NULL, NULL, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_vd_offset_clear_pending_forwards_true(void **state)
{
    (void)state;
    start_client_successfully();

    expect_value(__wrap_vd_offset_client_clear_pending, offset, 100);
    will_return(__wrap_vd_offset_client_clear_pending, true);

    assert_int_equal(g_captured_callbacks.vd_offset_clear_pending(100, g_captured_callbacks.user_data), 1);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_vd_offset_clear_pending_forwards_false(void **state)
{
    (void)state;
    start_client_successfully();

    expect_value(__wrap_vd_offset_client_clear_pending, offset, 50);
    will_return(__wrap_vd_offset_client_clear_pending, false);

    assert_int_equal(g_captured_callbacks.vd_offset_clear_pending(50, g_captured_callbacks.user_data), 0);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* on_task routing: active_response forwards to execd inline; an
 * unknown/unsupported type (including remote_upgrade reaching here by
 * mistake) is rejected. */

/* The manager's own contract confirms a payload without a top-level "wazuh"
 * key is not a valid alternate shape -- it never happens in real traffic,
 * so it's now treated as malformed, same as unparsable JSON. */
static void test_on_task_active_response_missing_wazuh_key_counts_failed(void **state)
{
    (void)state;
    start_client_successfully();
    agt->execdq = 5;

    /* No OS_SendUnix expectation: guarded before the call. */
    expect_string(__wrap__mdebug1, formatted_msg, "https_client task received: id=t1 type=active_response");
    expect_string(__wrap__merror, formatted_msg,
                  "https_client: active_response task t1 has a malformed payload; dropping.");
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_FAILED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    g_captured_callbacks.on_task("t1", "active_response", "{\"cmd\":\"x\"}", g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_on_task_active_response_already_wrapped_payload_forwards_as_is(void **state)
{
    (void)state;
    start_client_successfully();
    agt->execdq = 5;

    const char *payload = "{\"wazuh\":{\"active_response\":{\"executable\":\"x\"}}}";
    expect_string(__wrap__mdebug1, formatted_msg, "https_client task received: id=t1 type=active_response");
    expect_value(__wrap_OS_SendUnix, socket, 5);
    expect_string(__wrap_OS_SendUnix, msg, payload);
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 0);
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_DISPATCHED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    g_captured_callbacks.on_task("t1", "active_response", payload, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* Locks in the confirmed contract's full example verbatim: a complete AR
 * document with "rule"/"data"/"agent" siblings next
 * to "wazuh" forwards to execd byte-for-byte unchanged, not just the
 * minimal {"wazuh":{"active_response":{...}}} shape tested above. */
static void test_on_task_active_response_full_confirmed_contract_forwards_unchanged(void **state)
{
    (void)state;
    start_client_successfully();
    agt->execdq = 5;

    const char *payload =
        "{\"wazuh\":{\"active_response\":{\"name\":\"firewall-drop\",\"executable\":\"firewall-drop\","
        "\"extra_arguments\":\"192.168.1.100\",\"type\":\"stateless\",\"location\":\"local\","
        "\"agent_id\":\"001\"},\"agent\":{\"id\":\"001\"}},"
        "\"rule\":{\"id\":5503,\"description\":\"Brute force attack detected\"},"
        "\"data\":{\"srcip\":\"192.168.1.100\"}}";
    expect_string(__wrap__mdebug1, formatted_msg, "https_client task received: id=t1 type=active_response");
    expect_value(__wrap_OS_SendUnix, socket, 5);
    expect_string(__wrap_OS_SendUnix, msg, payload);
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 0);
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_DISPATCHED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    g_captured_callbacks.on_task("t1", "active_response", payload, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_on_task_active_response_malformed_payload_counts_failed(void **state)
{
    (void)state;
    start_client_successfully();
    agt->execdq = 5;

    /* No OS_SendUnix expectation: guarded before the call. */
    expect_string(__wrap__mdebug1, formatted_msg, "https_client task received: id=t1 type=active_response");
    expect_string(__wrap__merror, formatted_msg,
                  "https_client: active_response task t1 has a malformed payload; dropping.");
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_FAILED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    g_captured_callbacks.on_task("t1", "active_response", "not-json{{", g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_on_task_active_response_execd_send_failure_counts_failed(void **state)
{
    (void)state;
    start_client_successfully();
    agt->execdq = 5;

    expect_string(__wrap__mdebug1, formatted_msg, "https_client task received: id=t1 type=active_response");
    expect_value(__wrap_OS_SendUnix, socket, 5);
    expect_string(__wrap_OS_SendUnix, msg, "{\"wazuh\":{\"active_response\":{}}}");
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, -1);
    expect_string(__wrap__mdebug1, formatted_msg,
                  "https_client: active_response task t1: error communicating with execd.");
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_FAILED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    g_captured_callbacks.on_task("t1", "active_response", "{\"wazuh\":{\"active_response\":{}}}", g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_on_task_no_execd_queue_counts_failed(void **state)
{
    (void)state;
    start_client_successfully();
    agt->execdq = -1;

    /* No OS_SendUnix expectation: guarded before the call. */
    expect_string(__wrap__mdebug1, formatted_msg, "https_client task received: id=t1 type=active_response");
    expect_string(__wrap__mdebug1, formatted_msg,
                  "https_client: active_response task t1 dropped: execd queue not available.");
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_FAILED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    g_captured_callbacks.on_task("t1", "active_response", "{\"wazuh\":{\"active_response\":{}}}", g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_on_task_unknown_type_counts_failed(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__mdebug1, formatted_msg, "https_client task received: id=t1 type=remote_upgrade");
    expect_string(__wrap__merror, formatted_msg,
                  "https_client: task t1 has an unknown/unsupported task_type 'remote_upgrade'; dropping.");
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_FAILED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    /* remote_upgrade reaching on_task at all would mean ControlStream's own
     * interception broke; either way this is the generic unknown-type path. */
    g_captured_callbacks.on_task("t1", "remote_upgrade", "{}", g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_on_task_missing_id_or_type_counts_failed(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__mdebug1, formatted_msg, "https_client task received: id=? type=active_response");
    expect_string(__wrap__merror, formatted_msg, "https_client: task missing id/type; dropping.");
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_FAILED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);
    g_captured_callbacks.on_task(NULL, "active_response", "{}", g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* agent_restart/agent_reload: bridge_control_task_thread is called
 * directly (see the mirrored-struct note above), exercising the actual
 * restartAgent()/reloadAgent() dispatch and metric outcome that
 * w_create_thread's mock would otherwise skip. */

static void test_control_task_thread_restart_success_counts_dispatched(void **state)
{
    (void)state;
    will_return(__wrap_restartAgent, true);
    expect_string(__wrap__minfo, formatted_msg, "https_client: task t-restart (agent_restart) dispatched.");
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_DISPATCHED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    struct bridge_control_task_ctx_mirror *ctx;
    os_malloc(sizeof(*ctx), ctx);
    os_strdup("t-restart", ctx->task_id);
    ctx->restart = true;

    bridge_control_task_thread(ctx); /* Frees ctx itself, matching the real thread. */
}

static void test_control_task_thread_reload_failure_counts_failed(void **state)
{
    (void)state;
    will_return(__wrap_reloadAgent, false);
    expect_string(__wrap__merror, formatted_msg, "https_client: task t-reload (agent_reload) failed to dispatch.");
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_FAILED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    struct bridge_control_task_ctx_mirror *ctx;
    os_malloc(sizeof(*ctx), ctx);
    os_strdup("t-reload", ctx->task_id);
    ctx->restart = false;

    bridge_control_task_thread(ctx);
}

/* remote_upgrade: bridge_on_remote_upgrade_ready's guard clauses run
 * synchronously (they stage the file / validate before ever spawning a
 * thread), so they are reachable via the captured callback directly. The
 * dispatch-to-upgrade-module step itself (bridge_upgrade_thread) is called
 * directly afterward, same convention as the control-task tests above. */

static void test_on_remote_upgrade_ready_missing_fields_counts_failed(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__merror, formatted_msg,
                  "https_client: remote_upgrade callback missing required fields; aborting.");
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_FAILED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    g_captured_callbacks.on_remote_upgrade_ready("t1", NULL, "/tmp/wpk", "upgrade.sh",
                                                 g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_on_remote_upgrade_ready_unsafe_wpk_file_counts_failed(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap_w_ref_parent_folder, path, "../evil.wpk");
    will_return(__wrap_w_ref_parent_folder, 1); /* Unsafe: contains a parent-folder reference. */
    expect_string(__wrap__merror, formatted_msg,
                  "https_client: remote_upgrade task t1: wpk_file '../evil.wpk' is not a safe "
                  "filename; aborting.");
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_FAILED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    g_captured_callbacks.on_remote_upgrade_ready("t1", "../evil.wpk", "/tmp/wpk", "upgrade.sh",
                                                 g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

static void test_on_remote_upgrade_ready_stage_copy_failure_counts_failed(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap_w_ref_parent_folder, path, "agent.wpk");
    will_return(__wrap_w_ref_parent_folder, 0);
    expect_string(__wrap_w_copy_file, src, "/tmp/wpk");
    expect_string(__wrap_w_copy_file, dst, INCOMING_DIR "/agent.wpk");
    expect_value(__wrap_w_copy_file, mode, 'b');
    expect_value(__wrap_w_copy_file, silent, 0);
    will_return(__wrap_w_copy_file, -1);
    expect_string(__wrap__merror, formatted_msg,
                  "https_client: remote_upgrade task t1: could not stage the WPK at '" INCOMING_DIR
                  "/agent.wpk'; aborting.");
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_FAILED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    g_captured_callbacks.on_remote_upgrade_ready("t1", "agent.wpk", "/tmp/wpk", "upgrade.sh",
                                                 g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* bridge_upgrade_thread now opens COM_LOCAL_SOCK first (lock_restart) before it ever
 * touches AGENT_UPGRADE_SOCK; this helper queues a successful lock_restart round trip so tests
 * that are really about the upgrade-dispatch step don't have to restate it every time. */
static void expect_lock_restart_success(void)
{
    expect_string(__wrap_OS_ConnectUnixDomain, path, COM_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, 3);
    expect_value(__wrap_OS_SendSecureTCP, sock, 3);
    expect_string(__wrap_OS_SendSecureTCP, msg, "lock_restart -1");
    expect_any(__wrap_OS_SendSecureTCP, size);
    will_return(__wrap_OS_SendSecureTCP, 0);
}

static void test_upgrade_thread_socket_unreachable_counts_failed(void **state)
{
    (void)state;

    expect_lock_restart_success();

    expect_string(__wrap_OS_ConnectUnixDomain, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, -1);
    /* errno/strerror() content is not deterministic here (the mock doesn't
     * set errno), so the log content itself is not asserted -- only that the
     * failure path logs and counts it. */
    expect_any(__wrap__merror, formatted_msg);
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_FAILED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    struct bridge_upgrade_ctx_mirror *ctx;
    os_malloc(sizeof(*ctx), ctx);
    os_strdup("t-up", ctx->task_id);
    os_strdup("agent.wpk", ctx->wpk_file);
    os_strdup("upgrade.sh", ctx->installer);

    bridge_upgrade_thread(ctx);
}

static void test_upgrade_thread_module_accepts_counts_dispatched(void **state)
{
    (void)state;

    expect_lock_restart_success();

    expect_string(__wrap_OS_ConnectUnixDomain, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, 7);
    expect_value(__wrap_OS_SendSecureTCP, sock, 7);
    expect_string(__wrap_OS_SendSecureTCP, msg,
                  "{\"command\":\"upgrade\",\"parameters\":{\"file\":\"agent.wpk\","
                  "\"installer\":\"upgrade.sh\"}}");
    expect_any(__wrap_OS_SendSecureTCP, size);
    will_return(__wrap_OS_SendSecureTCP, 0);
    expect_value(__wrap_OS_RecvSecureTCP, sock, 7);
    expect_any(__wrap_OS_RecvSecureTCP, size);
    will_return(__wrap_OS_RecvSecureTCP, "{\"error\":0,\"message\":\"ok\",\"data\":[]}");
    will_return(__wrap_OS_RecvSecureTCP, 38);
    expect_string(__wrap__minfo, formatted_msg,
                  "https_client: remote_upgrade task t-up dispatched to the upgrade module "
                  "(installer running; the agent may restart shortly). No /control response is "
                  "sent.");
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_DISPATCHED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    struct bridge_upgrade_ctx_mirror *ctx;
    os_malloc(sizeof(*ctx), ctx);
    os_strdup("t-up", ctx->task_id);
    os_strdup("agent.wpk", ctx->wpk_file);
    os_strdup("upgrade.sh", ctx->installer);

    bridge_upgrade_thread(ctx);
}

/* lock_restart: a failed connect/send to COM_LOCAL_SOCK only logs a warning -- it must
 * not stop the upgrade dispatch that follows, since the lock is best-effort (mirroring the old
 * manager-driven protocol's own tolerance for this step). */
static void test_upgrade_thread_lock_restart_connect_failure_still_dispatches(void **state)
{
    (void)state;

    expect_string(__wrap_OS_ConnectUnixDomain, path, COM_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, -1);
    expect_any(__wrap__mwarn, formatted_msg);

    expect_string(__wrap_OS_ConnectUnixDomain, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, 7);
    expect_value(__wrap_OS_SendSecureTCP, sock, 7);
    expect_string(__wrap_OS_SendSecureTCP, msg,
                  "{\"command\":\"upgrade\",\"parameters\":{\"file\":\"agent.wpk\","
                  "\"installer\":\"upgrade.sh\"}}");
    expect_any(__wrap_OS_SendSecureTCP, size);
    will_return(__wrap_OS_SendSecureTCP, 0);
    expect_value(__wrap_OS_RecvSecureTCP, sock, 7);
    expect_any(__wrap_OS_RecvSecureTCP, size);
    will_return(__wrap_OS_RecvSecureTCP, "{\"error\":0,\"message\":\"ok\",\"data\":[]}");
    will_return(__wrap_OS_RecvSecureTCP, 38);
    expect_string(__wrap__minfo, formatted_msg,
                  "https_client: remote_upgrade task t-up dispatched to the upgrade module "
                  "(installer running; the agent may restart shortly). No /control response is "
                  "sent.");
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_DISPATCHED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    struct bridge_upgrade_ctx_mirror *ctx;
    os_malloc(sizeof(*ctx), ctx);
    os_strdup("t-up", ctx->task_id);
    os_strdup("agent.wpk", ctx->wpk_file);
    os_strdup("upgrade.sh", ctx->installer);

    bridge_upgrade_thread(ctx);
}

static void test_upgrade_thread_lock_restart_send_failure_still_dispatches(void **state)
{
    (void)state;

    expect_string(__wrap_OS_ConnectUnixDomain, path, COM_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, 3);
    expect_value(__wrap_OS_SendSecureTCP, sock, 3);
    expect_string(__wrap_OS_SendSecureTCP, msg, "lock_restart -1");
    expect_any(__wrap_OS_SendSecureTCP, size);
    will_return(__wrap_OS_SendSecureTCP, -1);
    expect_any(__wrap__mwarn, formatted_msg);

    expect_string(__wrap_OS_ConnectUnixDomain, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, 7);
    expect_value(__wrap_OS_SendSecureTCP, sock, 7);
    expect_string(__wrap_OS_SendSecureTCP, msg,
                  "{\"command\":\"upgrade\",\"parameters\":{\"file\":\"agent.wpk\","
                  "\"installer\":\"upgrade.sh\"}}");
    expect_any(__wrap_OS_SendSecureTCP, size);
    will_return(__wrap_OS_SendSecureTCP, 0);
    expect_value(__wrap_OS_RecvSecureTCP, sock, 7);
    expect_any(__wrap_OS_RecvSecureTCP, size);
    will_return(__wrap_OS_RecvSecureTCP, "{\"error\":0,\"message\":\"ok\",\"data\":[]}");
    will_return(__wrap_OS_RecvSecureTCP, 38);
    expect_string(__wrap__minfo, formatted_msg,
                  "https_client: remote_upgrade task t-up dispatched to the upgrade module "
                  "(installer running; the agent may restart shortly). No /control response is "
                  "sent.");
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_TASK_DISPATCHED);
    expect_value(__wrap_w_agentd_state_update, data, NULL);

    struct bridge_upgrade_ctx_mirror *ctx;
    os_malloc(sizeof(*ctx), ctx);
    os_strdup("t-up", ctx->task_id);
    os_strdup("agent.wpk", ctx->wpk_file);
    os_strdup("upgrade.sh", ctx->installer);

    bridge_upgrade_thread(ctx);
}

/* bridge_on_buffer_level: the same wazuh-agent.buffer event the leaky bucket
 * emitted, now through the accumulator. */
static void test_buffer_level_full_emits_the_state_event(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__mwarn, formatted_msg, FULL_BUFFER);
    expect_value(__wrap_hc_submit_event, handle, FAKE_HANDLE);
    expect_string(__wrap_hc_submit_event, frame,
                  "1:wazuh-agent:{\"event.module\":\"wazuh-agent\",\"event.category\":\"change\","
                  "\"event.dataset\":\"wazuh-agent.buffer\",\"event.severity\":2,"
                  "\"event.action\":\"full\"}");
    expect_any(__wrap_hc_submit_event, length);
    will_return(__wrap_hc_submit_event, true);

    g_captured_callbacks.on_buffer_level(HC_BUFFER_FULL, g_captured_callbacks.user_data);

    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);
    w_https_client_stop();
}

/* An unknown level is traced, not reported. */
static void test_buffer_level_unknown_is_traced_only(void **state)
{
    (void)state;
    start_client_successfully();

    expect_string(__wrap__mdebug2, formatted_msg, "https_client: unknown buffer level 42.");
    /* No hc_submit_event expectation: nothing may be emitted. */

    g_captured_callbacks.on_buffer_level(42, g_captured_callbacks.user_data);

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
        cmocka_unit_test_setup_teardown(test_config_checksum_is_sha256_of_local_merged_file, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_config_checksum_is_empty_when_local_file_unreadable, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_missing_key_refuses_to_start, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_no_keystore_defers_at_debug, setup_test, teardown_test),
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
        cmocka_unit_test_setup_teardown(test_registered_state_twice_clears_wait_file_each_time, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_producer_pause_arms_the_lock_and_reports_disconnected, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_producer_pause_release_clears_the_lock_and_reports_connected, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_starting_state_maps_to_pending, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_stopped_state_maps_to_nactive, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_rejected_state_maps_to_nactive, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_auth_error_state_maps_to_nactive, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_submit_event_forwards_the_frame_to_the_module, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_buffer_level_full_emits_the_state_event, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_buffer_level_unknown_is_traced_only, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_submit_event_reports_a_dropped_frame, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_submit_event_rejects_an_empty_frame, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_submit_event_is_a_noop_before_start, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_submit_event_is_a_noop_once_stopping, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_config_downloaded_happy_path_reload_dispatched_defers_gate_to_sigusr1, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_config_downloaded_releases_gate_when_reload_chain_unreachable, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_config_downloaded_auto_restart_disabled_stages_without_reloading, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_config_downloaded_blocked_gate_reloads_despite_auto_restart_disabled, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_config_downloaded_invalid_config_skips_reload_and_gate, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_config_downloaded_remote_conf_disabled_stages_files_only, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_config_downloaded_copy_failure_corrects_module_hash, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_config_downloaded_unmerge_failure_corrects_module_hash, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_config_downloaded_null_file_path_is_a_noop, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_startup_result_rejected_does_not_touch_globals, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_startup_result_invalid_json_logs_and_returns, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_startup_result_first_time_applies_without_reload, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_startup_result_limits_changed_reloads_under_auto_restart, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_startup_result_limits_changed_no_reload_without_auto_restart, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_startup_result_limits_unchanged_no_reload, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_startup_result_missing_limits_object_leaves_limits_unchanged, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_startup_result_cluster_and_groups_cleared_when_absent, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_agent_groups_notify_updates_on_change, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_agent_groups_notify_no_op_when_unchanged, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_agent_groups_notify_preserves_empty, setup_test, teardown_test),
        // Durable check-and-record callback
        cmocka_unit_test_setup_teardown(test_check_and_record_task_new_returns_one, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_check_and_record_task_duplicate_returns_zero_and_counts_it, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_check_and_record_task_error_returns_zero_and_counts_failed_not_duplicate, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_check_and_record_task_null_id_returns_minus_one, setup_test, teardown_test),

        cmocka_unit_test_setup_teardown(test_vd_offset_observe_forwards_changed_pending_and_offset, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_vd_offset_observe_reports_no_change_when_not_newer, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_vd_offset_observe_tolerates_null_out_params, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_vd_offset_clear_pending_forwards_true, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_vd_offset_clear_pending_forwards_false, setup_test, teardown_test),

        // on_task routing
        cmocka_unit_test_setup_teardown(test_on_task_active_response_missing_wazuh_key_counts_failed, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_on_task_active_response_already_wrapped_payload_forwards_as_is, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_on_task_active_response_full_confirmed_contract_forwards_unchanged, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_on_task_active_response_malformed_payload_counts_failed, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_on_task_active_response_execd_send_failure_counts_failed, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_on_task_no_execd_queue_counts_failed, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_on_task_unknown_type_counts_failed, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_on_task_missing_id_or_type_counts_failed, setup_test, teardown_test),

        // agent_restart/agent_reload worker thread body
        cmocka_unit_test(test_control_task_thread_restart_success_counts_dispatched),
        cmocka_unit_test(test_control_task_thread_reload_failure_counts_failed),

        // remote_upgrade
        cmocka_unit_test_setup_teardown(test_on_remote_upgrade_ready_missing_fields_counts_failed, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_on_remote_upgrade_ready_unsafe_wpk_file_counts_failed, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_on_remote_upgrade_ready_stage_copy_failure_counts_failed, setup_test, teardown_test),
        cmocka_unit_test(test_upgrade_thread_socket_unreachable_counts_failed),
        cmocka_unit_test(test_upgrade_thread_module_accepts_counts_dispatched),
        cmocka_unit_test(test_upgrade_thread_lock_restart_connect_failure_still_dispatches),
        cmocka_unit_test(test_upgrade_thread_lock_restart_send_failure_still_dispatches),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
