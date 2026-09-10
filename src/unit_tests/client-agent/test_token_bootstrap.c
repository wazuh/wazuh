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
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "shared.h"
#include "agentd.h"
#include "token_bootstrap.h"
#include "enrollment.h"
#include "enrollment_token.h"
#include "reenroll_secret.h"
#include "https_client.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"

/* w_agent_token_bootstrap() runs end to end against real files relative to this binary's
 * working directory (same convention as test_client_conf_ssl_resolution.c): AGENT_ANCHOR_CA,
 * KEYS_FILE and AGENT_ENROLLMENT_TOKEN_FILE are all relative paths, so a real mkdir/fopen here
 * exercises the exact latch/read/write logic production code runs, with nothing to fake at
 * that layer. Only the https_client module boundary
 * (hc_fetch_cacerts/hc_enroll/hc_spki_pin_matches) is mocked, mirroring
 * test_https_client_bridge.c's own convention for that same boundary. */

static hc_config_t g_fetch_config;
static int g_fetch_call_count = 0;

bool __wrap_hc_fetch_cacerts(const hc_config_t *config, const hc_cacerts_request_t *request,
                             hc_cacerts_result_t *result) {
    (void) request;
    g_fetch_call_count++;

    if (config) {
        g_fetch_config = *config;
    }

    if (result) {
        memset(result, 0, sizeof(*result));
        result->http_code = mock_type(long);
        const char *body = (const char *) mock();

        if (body != NULL) {
            strncpy(result->body, body, sizeof(result->body) - 1);
        }
    }

    return (bool) mock();
}

static hc_config_t g_enroll_config;
static hc_enroll_request_t g_enroll_request;
static int g_enroll_call_count = 0;

bool __wrap_hc_enroll(const hc_config_t *config, const hc_enroll_request_t *request,
                      hc_enroll_result_t *result) {
    g_enroll_call_count++;

    if (config) {
        g_enroll_config = *config;
    }

    if (request) {
        g_enroll_request = *request;
    }

    if (result) {
        memset(result, 0, sizeof(*result));
        result->http_code = mock_type(long);
        const char *body = (const char *) mock();

        if (body != NULL) {
            strncpy(result->body, body, sizeof(result->body) - 1);
        }
    }

    return (bool) mock();
}

static int g_spki_call_count = 0;

bool __wrap_hc_spki_pin_matches(const char *cacerts_body, size_t body_len, const char *pin_b64url) {
    (void) cacerts_body;
    (void) body_len;
    (void) pin_b64url;
    g_spki_call_count++;
    return (bool) mock();
}

/* ---- fixtures ---- */

static void remove_test_paths(void) {
    unlink("etc/enrollment_token");
    unlink("etc/certs/root-ca.pem");
    unlink("etc/client.keys");
    unlink(AGENT_REENROLL_SECRET);
}

static int group_setup(void **state) {
    (void) state;
    mkdir("etc", 0755);
    mkdir("etc/certs", 0755);
    remove_test_paths();
    return 0;
}

static int setup_test(void **state) {
    (void) state;
    remove_test_paths();

    agt = (agent *) calloc(1, sizeof(agent));
    os_strdup("test-agent", agt->enrollment.agent_name);
    memset(&keys, 0, sizeof(keys));

    memset(&g_fetch_config, 0, sizeof(g_fetch_config));
    memset(&g_enroll_config, 0, sizeof(g_enroll_config));
    memset(&g_enroll_request, 0, sizeof(g_enroll_request));
    g_fetch_call_count = 0;
    g_enroll_call_count = 0;
    g_spki_call_count = 0;

    return 0;
}

static int teardown_test(void **state) {
    (void) state;

    if (agt) {
        os_free(agt->enrollment.agent_name);
        os_free(agt->enrollment.groups);
        os_free(agt->enrollment.agent_address);
        os_free(agt->enrollment.authorization_pass_path);
        free(agt);
        agt = NULL;
    }

    if (keys.keyentries) {
        if (keys.keyentries[0]) {
            os_free(keys.keyentries[0]->id);
            os_free(keys.keyentries[0]->name);
            os_free(keys.keyentries[0]->raw_key);
            os_free(keys.keyentries[0]);
        }

        os_free(keys.keyentries);
    }

    remove_test_paths();
    return 0;
}

static void write_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "w");
    assert_non_null(fp);
    fputs(content, fp);
    fclose(fp);
}

static char *read_file(const char *path) {
    static char buf[256];
    memset(buf, 0, sizeof(buf));
    FILE *fp = fopen(path, "r");
    assert_non_null(fp);
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    (void) n;
    fclose(fp);
    return buf;
}

/* Builds and writes a real token, through the production encoder, so the decoder this module
 * runs against is exercised with exactly the wire format authd itself mints -- no hand-crafted
 * base64/JSON in this file. */
static void write_token_file(bool has_pin, bool has_key, const char *ca_pem) {
    w_etoken_t token;
    memset(&token, 0, sizeof(token));
    token.ver = 1;
    token.adr = "127.0.0.1:1517/wazuh-manager";

    if (has_pin) {
        token.has_pin = 1;
        memset(token.pin, 0xAB, sizeof(token.pin));
    } else {
        token.ca_pem = (char *) ca_pem;
    }

    if (has_key) {
        token.has_key = 1;
        memset(token.id, 0x01, sizeof(token.id));
        memset(token.secret, 0x02, sizeof(token.secret));
    }

    char *encoded = w_etoken_encode(&token);
    assert_non_null(encoded);
    write_file("etc/enrollment_token", encoded);
    free(encoded);
}

/* w_enrollment_process_response()'s own OS_IsValidIP(ip, NULL) call must be mocked here (same
 * convention test_enrollment.c already follows): real PCRE2 matching is not safe/deterministic
 * to run unmocked under this test's ASan build. */
static void expect_valid_ip(const char *ip) {
    expect_string(__wrap_OS_IsValidIP, ip_address, ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);
}

#define VALID_ENROLL_BODY \
    "{\"id\":\"001\",\"name\":\"test-agent\",\"ip\":\"10.0.0.5\"," \
    "\"key\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}"

/* The same 200, with the fifth field a 5.0 manager actually sends (#39064). */
#define REENROLL_SECRET "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define VALID_ENROLL_BODY_WITH_SECRET \
    "{\"id\":\"001\",\"name\":\"test-agent\",\"ip\":\"10.0.0.5\"," \
    "\"key\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"," \
    "\"reenroll_secret\":\"" REENROLL_SECRET "\"}"

/* ---- tests ---- */

static void test_no_token_file_is_noop(void **state) {
    (void) state;

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_fetch_call_count, 0);
    assert_int_equal(g_enroll_call_count, 0);
    assert_int_not_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_int_not_equal(IsFile("etc/client.keys"), 0);
}

static void test_anchor_already_present_is_noop(void **state) {
    (void) state;
    write_file("etc/certs/root-ca.pem", "EXISTING-ANCHOR");
    write_token_file(true, true, NULL);

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_fetch_call_count, 0);
    assert_int_equal(g_enroll_call_count, 0);
    /* The latch short-circuits before the token is ever read, let alone consumed. */
    assert_int_equal(IsFile("etc/enrollment_token"), 0);
    assert_string_equal(read_file("etc/certs/root-ca.pem"), "EXISTING-ANCHOR");
}

static void test_already_enrolled_is_noop(void **state) {
    (void) state;
    write_file("etc/client.keys", "001 test-agent 10.0.0.5 aaaa\n");
    write_token_file(true, true, NULL);

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_fetch_call_count, 0);
    assert_int_equal(g_enroll_call_count, 0);
    assert_int_not_equal(IsFile("etc/certs/root-ca.pem"), 0);
}

/* Regression test: client.keys can exist as an empty 0-byte placeholder (the package's own
 * conffile default) that no prior test here modeled -- every existing test either unlinked
 * the file or wrote a real, non-empty entry. */
static void test_empty_placeholder_keys_file_is_not_already_enrolled(void **state) {
    (void) state;
    write_file("etc/client.keys", "");
    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pin_matches, 1);
    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");

    /* Only AGENT_ANCHOR_CA hits TempFile()'s benign FSTAT_ERROR mdebug1 here -- KEYS_FILE
     * already exists (the placeholder), so fstat() on it succeeds and that debug line
     * doesn't fire twice. */
    expect_any(__wrap__mdebug1, formatted_msg);

    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    expect_string(__wrap__minfo, formatted_msg,
                  "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's "
                  "trust anchor.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_fetch_call_count, 1);
    assert_int_equal(g_spki_call_count, 1);
    assert_int_equal(g_enroll_call_count, 1);
    assert_int_equal(IsFile("etc/certs/root-ca.pem"), 0);
}

static void test_malformed_token_logs_named_error_and_writes_nothing(void **state) {
    (void) state;
    write_file("etc/enrollment_token", "not-a-valid-token!!!");

    expect_string(__wrap__merror, formatted_msg,
                  "Token bootstrap: could not decode the enrollment token: malformed token.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), -1);
    assert_int_equal(g_fetch_call_count, 0);
    assert_int_equal(g_enroll_call_count, 0);
    assert_int_not_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_int_not_equal(IsFile("etc/client.keys"), 0);
}

static void test_fetch_failure_logs_named_error_and_writes_nothing(void **state) {
    (void) state;
    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 503L);
    will_return(__wrap_hc_fetch_cacerts, NULL);
    will_return(__wrap_hc_fetch_cacerts, 1);

    expect_string(__wrap__merror, formatted_msg,
                  "Token bootstrap: fetching /cacerts from the manager failed: manager returned "
                  "HTTP 503 instead of 200.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), -1);
    assert_int_equal(g_fetch_call_count, 1);
    assert_int_equal(g_enroll_call_count, 0);
    assert_int_not_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_int_not_equal(IsFile("etc/client.keys"), 0);
}

static void test_pin_mismatch_logs_named_error_and_writes_nothing(void **state) {
    (void) state;
    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pin_matches, 0);

    expect_string(__wrap__merror, formatted_msg,
                  "Token bootstrap: fetched CA does not match the enrollment token's pin -- "
                  "refusing to trust it.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), -1);
    assert_int_equal(g_fetch_call_count, 1);
    assert_int_equal(g_spki_call_count, 1);
    assert_int_equal(g_enroll_call_count, 0);
    assert_int_not_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_int_not_equal(IsFile("etc/client.keys"), 0);
}

static void test_full_happy_path_via_pin(void **state) {
    (void) state;
    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pin_matches, 1);
    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");

    /* TempFile() logs a benign FSTAT_ERROR mdebug1 when the file it's about to replace doesn't
     * already exist (true for both AGENT_ANCHOR_CA and KEYS_FILE here); not asserted on exact
     * wording since errno text is platform-specific. */
    expect_any(__wrap__mdebug1, formatted_msg);
    expect_any(__wrap__mdebug1, formatted_msg);

    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    expect_string(__wrap__minfo, formatted_msg,
                  "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's "
                  "trust anchor.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_fetch_call_count, 1);
    assert_int_equal(g_spki_call_count, 1);
    assert_int_equal(g_enroll_call_count, 1);

    assert_int_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_string_equal(read_file("etc/certs/root-ca.pem"), "FAKE-CA-BODY");
    assert_int_equal(IsFile("etc/client.keys"), 0);
    /* The one-shot token is discarded on success. */
    assert_int_not_equal(IsFile("etc/enrollment_token"), 0);

    assert_int_equal(g_enroll_config.verify_mode, HC_VERIFY_FULL);
    assert_true(strlen(g_enroll_config.ca_path) > 0);
    assert_string_equal(g_enroll_request.password, "");
    assert_int_equal((int) strlen(g_enroll_request.token_kid), 22);
    assert_int_equal((int) strlen(g_enroll_request.token_key_hex), 64);
}

/* #39064: the bootstrap runs as ROOT, before the privilege drop, and w_enrollment_process_response()
 * writes the re-enrollment secret from here. So the secret is created by a root-owned process and
 * then has to be handed to the unprivileged user like the anchor and client.keys are -- and unlike
 * those two it must end up WRITABLE by that user, because every later rotation happens in the
 * running daemon. A root-owned secret would survive exactly one enrollment and then fail every
 * rotation silently, which is the same shape of defect 65215f70bf had to fix for client.keys.
 *
 * chown() to the caller's own uid/gid is a no-op here (the suite does not run as root), so what
 * this pins is that the store is written on the root path, with client.keys's mode, and that no
 * ownership error is logged along the way -- an unexpected merror() would fail the test on the
 * strict cmocka log expectations. */
static void test_bootstrap_stores_the_reenroll_secret_from_the_root_path(void **state) {
    (void) state;
    char id[W_REENROLL_ID_SIZE];
    char secret[W_REENROLL_SECRET_SIZE];
    struct stat info;

    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pin_matches, 1);
    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY_WITH_SECRET);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");

    /* One more TempFile() FSTAT_ERROR debug line than the happy path above (the secret is written
     * through one too), plus w_reenroll_secret_store()'s own confirmation. Declared uninteresting
     * rather than counted: the count is not what this test is about. */
    expect_any_always(__wrap__mdebug1, formatted_msg);

    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    expect_string(__wrap__minfo, formatted_msg,
                  "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's "
                  "trust anchor.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);

    assert_int_equal(w_reenroll_secret_load(id, sizeof(id), secret, sizeof(secret)), 1);
    assert_string_equal(id, "001");
    assert_string_equal(secret, REENROLL_SECRET);

    /* client.keys's mode, so the daemon can rewrite it after the drop. */
    assert_int_equal(stat(AGENT_REENROLL_SECRET, &info), 0);
    assert_int_equal(info.st_mode & 0777, 0640);
}

/* A manager that sends no secret must still complete the bootstrap: the token path predates this
 * field and an older manager is not an error. */
static void test_bootstrap_without_a_secret_leaves_no_store(void **state) {
    (void) state;

    write_token_file(true, true, NULL);

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pin_matches, 1);
    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");

    expect_any(__wrap__mdebug1, formatted_msg);
    expect_any(__wrap__mdebug1, formatted_msg);

    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    expect_string(__wrap__minfo, formatted_msg,
                  "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's "
                  "trust anchor.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(IsFile("etc/client.keys"), 0);
    assert_int_not_equal(IsFile(AGENT_REENROLL_SECRET), 0);
}

/* #39028's DoD: "a credential-less token enrolls when the simulator requires no credential,
 * and is not treated as an error." has_key=false must not short-circuit into an error path --
 * enrollment still runs, just with no token_kid/token_key_hex on the wire (and no fallback to
 * a configured password either, per token_bootstrap.c's own comment on that branch --
 * g_enroll_request.password stays empty exactly as it does on the keyed happy path). */
static void test_credential_less_token_enrolls_without_error(void **state) {
    (void) state;
    write_token_file(true, false, NULL);

    will_return(__wrap_hc_fetch_cacerts, 200L);
    will_return(__wrap_hc_fetch_cacerts, "FAKE-CA-BODY");
    will_return(__wrap_hc_fetch_cacerts, 1);
    will_return(__wrap_hc_spki_pin_matches, 1);
    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");

    /* Same benign TempFile() FSTAT_ERROR mdebug1 as the other happy-path tests, once for
     * AGENT_ANCHOR_CA and once for KEYS_FILE. */
    expect_any(__wrap__mdebug1, formatted_msg);
    expect_any(__wrap__mdebug1, formatted_msg);

    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    expect_string(__wrap__minfo, formatted_msg,
                  "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's "
                  "trust anchor.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    assert_int_equal(g_fetch_call_count, 1);
    assert_int_equal(g_spki_call_count, 1);
    assert_int_equal(g_enroll_call_count, 1);

    assert_int_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_string_equal(read_file("etc/certs/root-ca.pem"), "FAKE-CA-BODY");
    assert_int_equal(IsFile("etc/client.keys"), 0);
    assert_int_not_equal(IsFile("etc/enrollment_token"), 0);

    assert_int_equal(g_enroll_config.verify_mode, HC_VERIFY_FULL);
    assert_true(strlen(g_enroll_config.ca_path) > 0);
    /* No key on the token: no kid, no derived key, and no fallback to a configured password
     * either -- the request goes out with no credential at all (see the comment next to this
     * branch in token_bootstrap.c). */
    assert_string_equal(g_enroll_request.password, "");
    assert_int_equal((int) strlen(g_enroll_request.token_kid), 0);
    assert_int_equal((int) strlen(g_enroll_request.token_key_hex), 0);
}

static void test_full_happy_path_via_ca_pem(void **state) {
    (void) state;
    write_token_file(false, true, "FAKE-EMBEDDED-CA");

    will_return(__wrap_hc_enroll, 200L);
    will_return(__wrap_hc_enroll, VALID_ENROLL_BODY);
    will_return(__wrap_hc_enroll, 1);
    expect_valid_ip("10.0.0.5");

    /* Same benign TempFile() FSTAT_ERROR mdebug1 as the pin-path test above, once for
     * AGENT_ANCHOR_CA and once for KEYS_FILE. */
    expect_any(__wrap__mdebug1, formatted_msg);
    expect_any(__wrap__mdebug1, formatted_msg);

    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");
    expect_string(__wrap__minfo, formatted_msg,
                  "Token bootstrap: enrollment succeeded; the manager's CA is now the agent's "
                  "trust anchor.");

    assert_int_equal(w_agent_token_bootstrap(getuid(), getgid()), 0);
    /* No network fetch, no pin-compare: the CA was already embedded in the token. */
    assert_int_equal(g_fetch_call_count, 0);
    assert_int_equal(g_spki_call_count, 0);
    assert_int_equal(g_enroll_call_count, 1);

    assert_int_equal(IsFile("etc/certs/root-ca.pem"), 0);
    assert_string_equal(read_file("etc/certs/root-ca.pem"), "FAKE-EMBEDDED-CA");
    assert_int_equal(IsFile("etc/client.keys"), 0);
    assert_int_not_equal(IsFile("etc/enrollment_token"), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_no_token_file_is_noop, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_anchor_already_present_is_noop, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_already_enrolled_is_noop, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_empty_placeholder_keys_file_is_not_already_enrolled, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_malformed_token_logs_named_error_and_writes_nothing, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_fetch_failure_logs_named_error_and_writes_nothing, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_pin_mismatch_logs_named_error_and_writes_nothing, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_full_happy_path_via_pin, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_bootstrap_stores_the_reenroll_secret_from_the_root_path, setup_test,
                                        teardown_test),
        cmocka_unit_test_setup_teardown(test_bootstrap_without_a_secret_leaves_no_store, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_credential_less_token_enrolls_without_error, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_full_happy_path_via_ca_pem, setup_test, teardown_test),
    };

    return cmocka_run_group_tests(tests, group_setup, NULL);
}
