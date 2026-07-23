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
 * hc_create captures the config it was given so tests can inspect exactly
 * what the bridge built, without requiring a real https_client module. */
static hc_config_t g_captured_config;
static bool g_captured_config_valid = false;

hc_handle *__wrap_hc_create(const hc_config_t *config, const hc_callbacks_t *callbacks)
{
    check_expected_ptr(callbacks);
    if (config) {
        g_captured_config = *config;
        g_captured_config_valid = true;
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

static int setup_test(void **state)
{
    (void)state;
    agt = (agent *)calloc(1, sizeof(agent));
    memset(&keys, 0, sizeof(keys));
    g_captured_config_valid = false;

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

/* Gate */

static void test_disabled_gate_never_creates_the_client(void **state)
{
    (void)state;
    will_return(__wrap_getDefine_Int_default, 0);

    w_https_client_start();
    /* No expectation queued for hc_create: cmocka fails the test if the
     * disabled gate still reaches it. */
}

/* verify_mode mapping + TLS field copying (the point of this workstream) */

static void test_full_verify_mode_and_ca_reach_the_module(void **state)
{
    (void)state;
    os_strdup("/etc/wazuh/ca.pem", agt->ssl.certificate_authorities);
    agt->ssl.verification_mode = AGENT_VERIFY_FULL;

    will_return(__wrap_getDefine_Int_default, 1);
    expect_string(__wrap__minfo, formatted_msg, "https_client: enabled (agent.https_client=1).");
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

    will_return(__wrap_getDefine_Int_default, 1);
    expect_string(__wrap__minfo, formatted_msg, "https_client: enabled (agent.https_client=1).");
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

    will_return(__wrap_getDefine_Int_default, 1);
    expect_string(__wrap__minfo, formatted_msg, "https_client: enabled (agent.https_client=1).");
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

    will_return(__wrap_getDefine_Int_default, 1);
    expect_string(__wrap__minfo, formatted_msg, "https_client: enabled (agent.https_client=1).");
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

    will_return(__wrap_getDefine_Int_default, 1);
    expect_string(__wrap__minfo, formatted_msg, "https_client: enabled (agent.https_client=1).");
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

    will_return(__wrap_getDefine_Int_default, 1);
    expect_string(__wrap__minfo, formatted_msg, "https_client: enabled (agent.https_client=1).");
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

    will_return(__wrap_getDefine_Int_default, 1);
    expect_string(__wrap__minfo, formatted_msg, "https_client: enabled (agent.https_client=1).");
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

    will_return(__wrap_getDefine_Int_default, 1);
    expect_string(__wrap__minfo, formatted_msg, "https_client: enabled (agent.https_client=1).");
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
    will_return(__wrap_getDefine_Int_default, 1);
    expect_string(__wrap__minfo, formatted_msg, "https_client: enabled (agent.https_client=1).");
    expect_any(__wrap_hc_create, callbacks);
    will_return(__wrap_hc_create, NULL);
    expect_string(__wrap__merror, formatted_msg, "https_client: failed to create the client instance.");

    w_https_client_start();
    /* No hc_start/hc_destroy expectation: neither must be reached. */
}

static void test_hc_start_failure_destroys_and_logs(void **state)
{
    (void)state;
    will_return(__wrap_getDefine_Int_default, 1);
    expect_string(__wrap__minfo, formatted_msg, "https_client: enabled (agent.https_client=1).");
    expect_any(__wrap_hc_create, callbacks);
    will_return(__wrap_hc_create, FAKE_HANDLE);
    expect_value(__wrap_hc_start, handle, FAKE_HANDLE);
    will_return(__wrap_hc_start, false);
    expect_string(__wrap__merror, formatted_msg, "https_client: failed to start (configuration rejected).");
    expect_value(__wrap_hc_destroy, handle, FAKE_HANDLE);

    w_https_client_start();
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_disabled_gate_never_creates_the_client, setup_test, teardown_test),
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
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
