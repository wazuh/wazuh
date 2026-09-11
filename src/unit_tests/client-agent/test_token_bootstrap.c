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
#include "https_client.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"

/* w_agent_token_bootstrap() runs end to end against real files relative to this binary's
 * working directory (same convention as test_client_conf_ssl_resolution.c): AGENT_ANCHOR_CA,
 * KEYS_FILE and AGENT_ENROLLMENT_TOKEN_FILE are all relative paths, so a real mkdir/fopen here
 * exercises the exact latch/read/write logic production code runs, with nothing to fake at
 * that layer. Only the https_client module boundary
 * (hc_fetch_cacerts/hc_enroll/hc_spki_pinned_certificate) is mocked, mirroring
 * test_https_client_bridge.c's own convention for that same boundary. */

/* Deliberately unlike the fetched body below: the anchor must end up holding the pinned
 * certificate alone, so the two have to be distinguishable. */
#define PINNED_CERT "PINNED-CERT-ONLY"

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

/* Returns the pinned certificate itself, not a verdict: what the bootstrap installs as the
 * anchor must be this certificate alone and never the bundle it was found in, so the tests
 * feed a value here that is deliberately different from the fetched body and then assert on
 * which of the two reached the anchor. A NULL means no certificate matched. */
bool __wrap_hc_spki_pinned_certificate(const char *cacerts_body, size_t body_len,
                                       const char *pin_b64url, char *matched_pem,
                                       size_t matched_pem_size) {
    (void) cacerts_body;
    (void) body_len;
    (void) pin_b64url;
    g_spki_call_count++;

    const char *pem = (const char *) mock();

    if (pem == NULL) {
        return false;
    }

    snprintf(matched_pem, matched_pem_size, "%s", pem);
    return true;
}

/* The bootstrap asks for an anchor owned by root, which an unprivileged process cannot do:
 * running these for real would pass under sudo and fail for everyone else. Wrapped so the
 * outcome is the same either way, and so the ownership the bootstrap asks for can be asserted
 * rather than assumed. The last call of each is recorded for that. */
static uid_t g_anchor_chown_uid = (uid_t) -1;
static gid_t g_anchor_chown_gid = (gid_t) -1;

/* Recorded per target rather than "last call wins": the bootstrap chowns the anchor's
 * directory, then the anchor, then client.keys -- and client.keys goes to the runtime user
 * on purpose, so the final call says nothing about the anchor. */
static bool is_anchor_path(const char *path) {
    const char *suffix = "root-ca.pem";
    const size_t path_len = path ? strlen(path) : 0;
    const size_t suffix_len = strlen(suffix);

    return path_len >= suffix_len && strcmp(path + path_len - suffix_len, suffix) == 0;
}

int __wrap_chown(const char *path, uid_t owner, gid_t group) {
    if (is_anchor_path(path)) {
        g_anchor_chown_uid = owner;
        g_anchor_chown_gid = group;
    }

    return 0;
}

/* Not recorded: the mode is set on the temporary file, before the rename gives it the
 * anchor's name, so there is nothing here to match it against. Wrapped only so an
 * unprivileged run behaves like a privileged one. */
int __wrap_chmod(const char *path, mode_t mode) {
    (void) path;
    (void) mode;
    return 0;
}

/* ---- fixtures ---- */

static void remove_test_paths(void) {
    unlink("etc/enrollment_token");
    unlink("etc/certs/root-ca.pem");
    unlink("etc/client.keys");
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
    g_anchor_chown_uid = (uid_t) -1;
    g_anchor_chown_gid = (gid_t) -1;

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
    will_return(__wrap_hc_spki_pinned_certificate, PINNED_CERT);
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
    will_return(__wrap_hc_spki_pinned_certificate, NULL);

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
    will_return(__wrap_hc_spki_pinned_certificate, PINNED_CERT);
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
    /* The pinned certificate alone, not the bundle it arrived in: anything else in that body
     * was chosen by whoever answered an unverified fetch, and installing it would hand them a
     * trust anchor beside the genuine one. */
    assert_string_equal(read_file("etc/certs/root-ca.pem"), PINNED_CERT);
    assert_int_equal(IsFile("etc/client.keys"), 0);
    /* The one-shot token is discarded on success. */
    assert_int_not_equal(IsFile("etc/enrollment_token"), 0);

    assert_int_equal(g_enroll_config.verify_mode, HC_VERIFY_FULL);
    assert_true(strlen(g_enroll_config.ca_path) > 0);
    assert_string_equal(g_enroll_request.password, "");
    assert_int_equal((int) strlen(g_enroll_request.token_kid), 22);
    assert_int_equal((int) strlen(g_enroll_request.token_key_hex), 64);

    /* The anchor is handed to root and only shares its group, so the user the agent drops to
     * can read the certificate authority it verifies against without being able to replace
     * it. */
    assert_int_equal(g_anchor_chown_uid, 0);
    assert_int_equal(g_anchor_chown_gid, getgid());
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
    will_return(__wrap_hc_spki_pinned_certificate, PINNED_CERT);
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
    /* The pinned certificate alone, not the bundle it arrived in: anything else in that body
     * was chosen by whoever answered an unverified fetch, and installing it would hand them a
     * trust anchor beside the genuine one. */
    assert_string_equal(read_file("etc/certs/root-ca.pem"), PINNED_CERT);
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
        cmocka_unit_test_setup_teardown(test_credential_less_token_enrolls_without_error, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_full_happy_path_via_ca_pem, setup_test, teardown_test),
    };

    return cmocka_run_group_tests(tests, group_setup, NULL);
}
