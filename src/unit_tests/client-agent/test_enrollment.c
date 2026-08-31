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

#include "shared.h"
#include "agentd.h"
#include "enrollment.h"
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
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
