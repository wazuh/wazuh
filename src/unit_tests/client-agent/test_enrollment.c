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

#include <sys/stat.h>

#include "shared.h"
#include "agentd.h"
#include "enrollment.h"
#include "reenroll_secret.h"
#include "cJSON.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"

/* setup/teardown */

static int setup_test(void **state) {
    (void)state;
    agt = (agent *)calloc(1, sizeof(agent));
    memset(&keys, 0, sizeof(keys));

    /* Every build_request test configures an explicit agent_name: sidesteps
     * gethostname()/OS_ConvertToValidAgentName() (no shared cmocka wrapper
     * exists for either), which is not the point of these tests. */
    os_strdup("test-agent", agt->enrollment.agent_name);

    return 0;
}

static int teardown_test(void **state) {
    (void)state;
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
    return 0;
}

static cJSON *parse_body(const w_enroll_request_t *request) {
    assert_non_null(request->body_json);
    cJSON *body = cJSON_Parse(request->body_json);
    assert_non_null(body);
    return body;
}

/* No authorization_pass_path configured in these tests -> build_request
 * always reaches the "no password" branch, which always logs. */
static void expect_no_password_logged(void) {
    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");
}

static void expect_valid_ip(const char *ip) {
    expect_string(__wrap_OS_IsValidIP, ip_address, ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);
}

static void expect_invalid_ip(const char *ip) {
    expect_string(__wrap_OS_IsValidIP, ip_address, ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 0);
}

/* w_enrollment_build_request */

static void test_build_request_minimal_body(void **state) {
    (void)state;
    w_enroll_request_t request;

    expect_no_password_logged();
    assert_int_equal(w_enrollment_build_request(&request), 0);

    cJSON *body = parse_body(&request);
    assert_string_equal(cJSON_GetObjectItem(body, "name")->valuestring, "test-agent");
    assert_non_null(cJSON_GetObjectItem(body, "version"));
    assert_null(cJSON_GetObjectItem(body, "groups"));
    assert_null(cJSON_GetObjectItem(body, "ip"));
    assert_null(cJSON_GetObjectItem(body, "key_hash"));
    assert_null(request.password);

    cJSON_Delete(body);
    w_enroll_request_destroy(&request);
}

static void test_build_request_includes_groups(void **state) {
    (void)state;
    os_strdup("default,web-servers", agt->enrollment.groups);
    w_enroll_request_t request;

    expect_no_password_logged();
    assert_int_equal(w_enrollment_build_request(&request), 0);

    cJSON *body = parse_body(&request);
    assert_string_equal(cJSON_GetObjectItem(body, "groups")->valuestring, "default,web-servers");

    cJSON_Delete(body);
    w_enroll_request_destroy(&request);
}

static void test_build_request_explicit_agent_address(void **state) {
    (void)state;
    os_strdup("10.0.0.15", agt->enrollment.agent_address);
    w_enroll_request_t request;

    expect_valid_ip("10.0.0.15");
    expect_no_password_logged();
    assert_int_equal(w_enrollment_build_request(&request), 0);

    cJSON *body = parse_body(&request);
    assert_string_equal(cJSON_GetObjectItem(body, "ip")->valuestring, "10.0.0.15");

    cJSON_Delete(body);
    w_enroll_request_destroy(&request);
}

static void test_build_request_use_source_ip_sends_src_literal(void **state) {
    (void)state;
    agt->enrollment.use_source_ip = true;
    w_enroll_request_t request;

    expect_no_password_logged();
    assert_int_equal(w_enrollment_build_request(&request), 0);

    cJSON *body = parse_body(&request);
    assert_string_equal(cJSON_GetObjectItem(body, "ip")->valuestring, "src");

    cJSON_Delete(body);
    w_enroll_request_destroy(&request);
}

static void test_build_request_rejects_incompatible_address_and_source_ip(void **state) {
    (void)state;
    os_strdup("10.0.0.15", agt->enrollment.agent_address);
    agt->enrollment.use_source_ip = true;
    w_enroll_request_t request;

    expect_string(__wrap__merror, formatted_msg,
                  "Incompatible agent_address/use_source_ip options: forcing an IP "
                  "while also requesting the connection's source IP.");

    assert_int_equal(w_enrollment_build_request(&request), -1);
}

static void test_build_request_rejects_invalid_agent_address(void **state) {
    (void)state;
    os_strdup("not-an-ip", agt->enrollment.agent_address);
    w_enroll_request_t request;

    expect_invalid_ip("not-an-ip");
    expect_string(__wrap__merror, formatted_msg, "Invalid IP address provided for agent_address.");

    assert_int_equal(w_enrollment_build_request(&request), -1);
}

static void test_build_request_rejects_invalid_agent_name(void **state) {
    (void)state;
    os_free(agt->enrollment.agent_name);
    os_strdup("invalid name with spaces!", agt->enrollment.agent_name);
    w_enroll_request_t request;

    expect_string(__wrap__merror, formatted_msg,
                  "Invalid agent name \"invalid name with spaces!\". Please pick a valid name.");

    assert_int_equal(w_enrollment_build_request(&request), -1);
}

static void test_build_request_includes_key_hash_when_a_key_exists(void **state) {
    (void)state;
    os_calloc(1, sizeof(keyentry *), keys.keyentries);
    os_calloc(1, sizeof(keyentry), keys.keyentries[0]);
    os_strdup("001", keys.keyentries[0]->id);
    os_strdup("test-agent", keys.keyentries[0]->name);
    os_strdup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              keys.keyentries[0]->raw_key);
    keys.keysize = 1;

    os_sha1 expected_hash;
    assert_int_equal(w_get_key_hash(keys.keyentries[0], expected_hash), OS_SUCCESS);

    w_enroll_request_t request;
    expect_no_password_logged();
    assert_int_equal(w_enrollment_build_request(&request), 0);

    cJSON *body = parse_body(&request);
    assert_string_equal(cJSON_GetObjectItem(body, "key_hash")->valuestring, expected_hash);

    cJSON_Delete(body);
    w_enroll_request_destroy(&request);
}

static void test_build_request_reads_password_from_file(void **state) {
    (void)state;
    const char *path = "test_enrollment_password.tmp";
    FILE *fp = fopen(path, "w");
    assert_non_null(fp);
    fprintf(fp, "s3cr3tpass\n");
    fclose(fp);

    os_strdup(path, agt->enrollment.authorization_pass_path);

    expect_string(__wrap__minfo, formatted_msg, "Using password specified on file: test_enrollment_password.tmp");

    w_enroll_request_t request;
    assert_int_equal(w_enrollment_build_request(&request), 0);
    assert_string_equal(request.password, "s3cr3tpass");

    cJSON *body = parse_body(&request);
    cJSON_Delete(body);
    w_enroll_request_destroy(&request);
    remove(path);
}

static void test_build_request_no_password_file_yields_null_password(void **state) {
    (void)state;
    os_strdup("/nonexistent/authd.pass", agt->enrollment.authorization_pass_path);

    expect_string(__wrap__minfo, formatted_msg, "No authentication password provided");

    w_enroll_request_t request;
    assert_int_equal(w_enrollment_build_request(&request), 0);
    assert_null(request.password);

    cJSON *body = parse_body(&request);
    cJSON_Delete(body);
    w_enroll_request_destroy(&request);
}

/* w_enrollment_process_response */

static void test_process_response_no_http_status_is_transport_error(void **state) {
    (void)state;
    hc_enroll_result_t result = {0};
    result.http_code = 0;

    /* No transport_error: the attempt never reached libcurl, so the module has
     * already logged the real reason and the coarse wording is all that is left. */
    expect_string(__wrap__merror, formatted_msg,
                  "Enrollment request could not be sent: transport or configuration error.");

    assert_int_equal(w_enrollment_process_response(&result), W_ENROLL_ERR_TRANSPORT);
}

static void test_process_response_transport_error_names_the_cause(void **state) {
    (void)state;
    hc_enroll_result_t result = {0};
    result.http_code = 0;
    strncpy(result.transport_error, "(60) SSL peer certificate or SSH remote key was not OK",
            sizeof(result.transport_error) - 1);

    /* The whole point: a misconfigured CA and an unreachable manager are both
     * http_code == 0, and only this string tells them apart. */
    expect_string(__wrap__merror, formatted_msg,
                  "Enrollment request could not be sent: (60) SSL peer certificate or SSH remote key was not OK.");

    assert_int_equal(w_enrollment_process_response(&result), W_ENROLL_ERR_TRANSPORT);
}

static void test_process_response_400_is_invalid_request(void **state) {
    (void)state;
    hc_enroll_result_t result = {0};
    result.http_code = 400;

    expect_string(__wrap__merror, formatted_msg, "Enrollment rejected by the manager: invalid request.");

    assert_int_equal(w_enrollment_process_response(&result), W_ENROLL_ERR_INVALID_REQUEST);
}

static void test_process_response_401_is_auth_error(void **state) {
    (void)state;
    hc_enroll_result_t result = {0};
    result.http_code = 401;

    expect_string(__wrap__merror, formatted_msg,
                  "Enrollment rejected by the manager: invalid or missing authentication.");

    assert_int_equal(w_enrollment_process_response(&result), W_ENROLL_ERR_AUTH);
}

static void test_process_response_403_is_disabled_not_an_error(void **state) {
    (void)state;
    hc_enroll_result_t result = {0};
    result.http_code = 403;

    /* Administratively disabled: logged at INFO, not ERROR -- the caller must
     * be able to tell this apart from a transport hiccup (#38465 R12). */
    expect_string(__wrap__minfo, formatted_msg, "Enrollment is disabled on the manager.");

    assert_int_equal(w_enrollment_process_response(&result), W_ENROLL_ERR_DISABLED);
}

static void test_process_response_409_is_duplicate(void **state) {
    (void)state;
    hc_enroll_result_t result = {0};
    result.http_code = 409;

    expect_string(__wrap__merror, formatted_msg, "Enrollment rejected by the manager: duplicate agent.");

    assert_int_equal(w_enrollment_process_response(&result), W_ENROLL_ERR_DUPLICATE);
}

static void test_process_response_unrecognized_status_is_server_error(void **state) {
    (void)state;
    hc_enroll_result_t result = {0};
    result.http_code = 500;

    expect_string(__wrap__merror, formatted_msg, "Enrollment failed with unexpected HTTP status 500.");

    assert_int_equal(w_enrollment_process_response(&result), W_ENROLL_ERR_SERVER);
}

static void test_process_response_200_with_malformed_json_is_server_error(void **state) {
    (void)state;
    hc_enroll_result_t result = {0};
    result.http_code = 200;
    strncpy(result.body, "not json", sizeof(result.body) - 1);

    expect_string(__wrap__merror, formatted_msg, "Enrollment response is not valid JSON.");

    assert_int_equal(w_enrollment_process_response(&result), W_ENROLL_ERR_SERVER);
}

static void test_process_response_200_missing_field_is_server_error(void **state) {
    (void)state;
    hc_enroll_result_t result = {0};
    result.http_code = 200;
    strncpy(result.body, "{\"id\":\"001\",\"name\":\"agent01\",\"ip\":\"10.0.0.1\"}", sizeof(result.body) - 1);

    expect_string(__wrap__merror, formatted_msg, "Enrollment response has a missing or invalid field.");

    assert_int_equal(w_enrollment_process_response(&result), W_ENROLL_ERR_SERVER);
}

/* ---- the 200 path: client.keys and the re-enrollment secret (#39064) ----
 *
 * KEYS_FILE and AGENT_REENROLL_SECRET are relative paths, so these run the real writers against
 * real files under etc/, the same way test_token_bootstrap.c does. The write ORDER is the point of
 * several of them, and a mocked filesystem would prove nothing about it.
 */

#define VALID_SECRET "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

static void remove_200_paths(void) {
    unlink(KEYS_FILE);
    unlink(AGENT_REENROLL_SECRET);
}

static int setup_200_test(void **state) {
    mkdir("etc", 0755);
    remove_200_paths();
    return setup_test(state);
}

/* Only the debug channel, and only for the 200-path tests: the two TempFile() calls (the secret
 * and client.keys) each log an FSTAT_ERROR mdebug1 when replacing a file that does not exist yet,
 * and the store logs one of its own. None of that is what these tests assert. Declared in the test
 * body, not the fixture: cmocka checks a setup function's queue when setup returns, and an
 * "always" entry left there is reported as an unchecked leftover. */
#define ignore_debug_lines() expect_any_always(__wrap__mdebug1, formatted_msg)
/* Used only by the tests that actually write a file: cmocka reports an "always" entry that never
 * matched a call as a leftover, so the tests that refuse the response before anything is written
 * must not declare one. */

static int teardown_200_test(void **state) {
    remove_200_paths();
    return teardown_test(state);
}

/* The key HKDF-SHA256 derives from VALID_SECRET under the label WAZUH-REENROLL-KEY. Frozen: it
 * must equal what deriveReenrollKey() produces on the manager side. */
#define DERIVED_FROM_VALID_SECRET "c0e0fa3373094b56e0465367044a0126c4bd82329868053b8f063b9badd20b1e"

static void write_text_file(const char *path, const char *contents) {
    FILE *fp = fopen(path, "w");
    assert_non_null(fp);
    fputs(contents, fp);
    fclose(fp);
}

static void set_key_entry(const char *id, const char *name, const char *raw_key) {
    os_calloc(1, sizeof(keyentry *), keys.keyentries);
    os_calloc(1, sizeof(keyentry), keys.keyentries[0]);
    os_strdup(id, keys.keyentries[0]->id);
    os_strdup(name, keys.keyentries[0]->name);
    os_strdup(raw_key, keys.keyentries[0]->raw_key);
    keys.keysize = 1;
}

static void set_body(hc_enroll_result_t *result, const char *body) {
    result->http_code = 200;
    strncpy(result->body, body, sizeof(result->body) - 1);
}

static char *read_file_line(const char *path) {
    static char buffer[512];
    FILE *fp = fopen(path, "r");
    assert_non_null(fp);
    memset(buffer, 0, sizeof(buffer));
    assert_non_null(fgets(buffer, sizeof(buffer), fp));
    fclose(fp);
    return buffer;
}

/* ---- build_request: the credential it chooses (#39064) ---- */

/* The agent's own secret beats the fleet-wide password. Both are on disk here, and the request
 * must carry the keyed credential and no password at all -- signing with both would misreport to
 * the manager, and to any audit trail, what actually authenticated the request. */
static void test_build_request_prefers_the_reenroll_secret_over_the_password(void **state) {
    (void)state;
    w_enroll_request_t request;

    ignore_debug_lines();
    assert_int_equal(w_reenroll_secret_store("001", VALID_SECRET), 0);
    os_strdup("etc/authd.pass", agt->enrollment.authorization_pass_path);
    write_text_file("etc/authd.pass", "fleet-secret\n");

    expect_string(__wrap__minfo, formatted_msg, "Re-enrolling with this agent's own re-enrollment secret.");

    assert_int_equal(w_enrollment_build_request(&request), 0);
    assert_null(request.password);
    assert_string_equal(request.enroll_kid, "001");
    /* The frozen vector: HKDF of the stored secret under WAZUH-REENROLL-KEY. Asserted as a value,
     * not just as non-empty, because this is the one place the agent's derivation has to agree
     * with authd's -- jwt/testVectors.hpp holds the same pair. */
    assert_string_equal(request.enroll_key_hex, DERIVED_FROM_VALID_SECRET);

    w_enroll_request_destroy(&request);
    unlink("etc/authd.pass");
}

/* With no secret stored, nothing changes: the password path is exactly as it was. */
static void test_build_request_without_a_secret_uses_the_password(void **state) {
    (void)state;
    w_enroll_request_t request;

    os_strdup("etc/authd.pass", agt->enrollment.authorization_pass_path);
    write_text_file("etc/authd.pass", "fleet-secret\n");

    expect_string(__wrap__minfo, formatted_msg, "Using password specified on file: etc/authd.pass");

    assert_int_equal(w_enrollment_build_request(&request), 0);
    assert_string_equal(request.password, "fleet-secret");
    assert_null(request.enroll_kid);
    assert_null(request.enroll_key_hex);

    w_enroll_request_destroy(&request);
    unlink("etc/authd.pass");
}

/* The `kid` comes from the STORE, not from client.keys: the store is what the manager verifies
 * the secret against, and the case this credential exists for is the one where client.keys is
 * gone or stale. A disagreement is a warning, not a reason to present the other id. */
static void test_build_request_kid_comes_from_the_store_not_client_keys(void **state) {
    (void)state;
    w_enroll_request_t request;

    ignore_debug_lines();
    assert_int_equal(w_reenroll_secret_store("007", VALID_SECRET), 0);
    set_key_entry("001", "agent01", "abc123");

    expect_string(__wrap__mwarn, formatted_msg,
                  "The re-enrollment secret is stored for agent '007' but client.keys holds '001'; "
                  "re-enrolling as '007', which is the id the manager verifies the secret against.");
    expect_string(__wrap__minfo, formatted_msg, "Re-enrolling with this agent's own re-enrollment secret.");

    assert_int_equal(w_enrollment_build_request(&request), 0);
    assert_string_equal(request.enroll_kid, "007");

    w_enroll_request_destroy(&request);
}

static void test_process_response_200_stores_the_reenroll_secret(void **state) {
    (void)state;
    ignore_debug_lines();
    hc_enroll_result_t result = {0};
    char id[W_REENROLL_ID_SIZE];
    char secret[W_REENROLL_SECRET_SIZE];

    set_body(&result,
             "{\"id\":\"001\",\"name\":\"agent01\",\"ip\":\"10.0.0.1\",\"key\":\"abc123\","
             "\"reenroll_secret\":\"" VALID_SECRET "\"}");
    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");

    assert_int_equal(w_enrollment_process_response(&result), W_ENROLL_OK);

    assert_int_equal(w_reenroll_secret_load(id, sizeof(id), secret, sizeof(secret)), 1);
    assert_string_equal(id, "001");
    assert_string_equal(secret, VALID_SECRET);
    assert_string_equal(read_file_line(KEYS_FILE), "001 agent01 10.0.0.1 abc123\n");
}

/* An older manager, or a path that mints none: the four required fields still enroll the agent.
 * Absent is not malformed. */
static void test_process_response_200_without_a_secret_still_enrolls(void **state) {
    (void)state;
    ignore_debug_lines();
    hc_enroll_result_t result = {0};

    set_body(&result, "{\"id\":\"001\",\"name\":\"agent01\",\"ip\":\"10.0.0.1\",\"key\":\"abc123\"}");
    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");

    assert_int_equal(w_enrollment_process_response(&result), W_ENROLL_OK);
    assert_int_equal(IsFile(AGENT_REENROLL_SECRET), -1);
    assert_string_equal(read_file_line(KEYS_FILE), "001 agent01 10.0.0.1 abc123\n");
}

/* A secret that arrives unusable fails the WHOLE response. The manager rotated its own copy before
 * answering, so a secret we cannot store is one nobody holds any more -- and accepting the key
 * alone is exactly how an agent ends up enrolled but unrecoverable. */
static void test_process_response_200_malformed_secret_is_server_error(void **state) {
    (void)state;
    hc_enroll_result_t result = {0};

    set_body(&result,
             "{\"id\":\"001\",\"name\":\"agent01\",\"ip\":\"10.0.0.1\",\"key\":\"abc123\","
             "\"reenroll_secret\":\"tooshort\"}");
    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg, "Enrollment response carries a malformed re-enrollment secret.");

    assert_int_equal(w_enrollment_process_response(&result), W_ENROLL_ERR_SERVER);

    /* And client.keys was never written: the refusal has to come BEFORE the key lands, or the
     * agent is left holding a key whose secret it rejected. */
    assert_int_equal(IsFile(KEYS_FILE), -1);
    assert_int_equal(IsFile(AGENT_REENROLL_SECRET), -1);
}

/* A `reenroll_secret` of the wrong JSON type is refused the same way -- not silently skipped as
 * though it were absent. */
static void test_process_response_200_non_string_secret_is_server_error(void **state) {
    (void)state;
    hc_enroll_result_t result = {0};

    set_body(&result,
             "{\"id\":\"001\",\"name\":\"agent01\",\"ip\":\"10.0.0.1\",\"key\":\"abc123\","
             "\"reenroll_secret\":42}");
    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg, "Enrollment response carries a malformed re-enrollment secret.");

    assert_int_equal(w_enrollment_process_response(&result), W_ENROLL_ERR_SERVER);
    assert_int_equal(IsFile(KEYS_FILE), -1);
}

/* The DoD's interrupted-rotation guarantee, asserted through the observable order rather than
 * assumed: with the store already holding the previous secret, a response whose secret is refused
 * must leave that previous secret intact and write no key. */
static void test_process_response_200_refusal_leaves_the_previous_secret_usable(void **state) {
    (void)state;
    ignore_debug_lines();
    hc_enroll_result_t result = {0};
    char id[W_REENROLL_ID_SIZE];
    char secret[W_REENROLL_SECRET_SIZE];

    assert_int_equal(w_reenroll_secret_store("001", VALID_SECRET), 0);

    set_body(&result,
             "{\"id\":\"001\",\"name\":\"agent01\",\"ip\":\"10.0.0.1\",\"key\":\"abc123\","
             "\"reenroll_secret\":\"nothex\"}");
    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg, "Enrollment response carries a malformed re-enrollment secret.");

    assert_int_equal(w_enrollment_process_response(&result), W_ENROLL_ERR_SERVER);

    assert_int_equal(w_reenroll_secret_load(id, sizeof(id), secret, sizeof(secret)), 1);
    assert_string_equal(secret, VALID_SECRET);
    assert_int_equal(IsFile(KEYS_FILE), -1);
}

/* Rotation: the second enrollment's secret replaces the first, keyed to the same id. */
static void test_process_response_200_rotates_the_stored_secret(void **state) {
    (void)state;
    ignore_debug_lines();
    hc_enroll_result_t result = {0};
    char id[W_REENROLL_ID_SIZE];
    char secret[W_REENROLL_SECRET_SIZE];
    const char *rotated = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    assert_int_equal(w_reenroll_secret_store("001", VALID_SECRET), 0);

    set_body(&result,
             "{\"id\":\"001\",\"name\":\"agent01\",\"ip\":\"10.0.0.1\",\"key\":\"def456\","
             "\"reenroll_secret\":\"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\"}");
    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__minfo, formatted_msg, "Valid key received");

    assert_int_equal(w_enrollment_process_response(&result), W_ENROLL_OK);

    assert_int_equal(w_reenroll_secret_load(id, sizeof(id), secret, sizeof(secret)), 1);
    assert_string_equal(secret, rotated);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_build_request_minimal_body, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_build_request_includes_groups, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_build_request_explicit_agent_address, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_build_request_use_source_ip_sends_src_literal, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_build_request_rejects_incompatible_address_and_source_ip, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_build_request_rejects_invalid_agent_address, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_build_request_rejects_invalid_agent_name, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_build_request_includes_key_hash_when_a_key_exists, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_build_request_reads_password_from_file, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_build_request_no_password_file_yields_null_password, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_process_response_no_http_status_is_transport_error, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_process_response_transport_error_names_the_cause, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_process_response_400_is_invalid_request, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_process_response_401_is_auth_error, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_process_response_403_is_disabled_not_an_error, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_process_response_409_is_duplicate, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_process_response_unrecognized_status_is_server_error, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_process_response_200_with_malformed_json_is_server_error, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_process_response_200_missing_field_is_server_error, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_build_request_prefers_the_reenroll_secret_over_the_password, setup_200_test, teardown_200_test),
        cmocka_unit_test_setup_teardown(test_build_request_without_a_secret_uses_the_password, setup_200_test, teardown_200_test),
        cmocka_unit_test_setup_teardown(test_build_request_kid_comes_from_the_store_not_client_keys, setup_200_test, teardown_200_test),
        cmocka_unit_test_setup_teardown(test_process_response_200_stores_the_reenroll_secret, setup_200_test, teardown_200_test),
        cmocka_unit_test_setup_teardown(test_process_response_200_without_a_secret_still_enrolls, setup_200_test, teardown_200_test),
        cmocka_unit_test_setup_teardown(test_process_response_200_malformed_secret_is_server_error, setup_200_test, teardown_200_test),
        cmocka_unit_test_setup_teardown(test_process_response_200_non_string_secret_is_server_error, setup_200_test, teardown_200_test),
        cmocka_unit_test_setup_teardown(test_process_response_200_refusal_leaves_the_previous_secret_usable, setup_200_test, teardown_200_test),
        cmocka_unit_test_setup_teardown(test_process_response_200_rotates_the_stored_secret, setup_200_test, teardown_200_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
