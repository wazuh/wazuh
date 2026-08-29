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

#include "auth.h"
#include "shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../external/cJSON/cJSON.h"


int Read_Authd_JSON(const cJSON *auth, void *d1);


/* setup/teardown */


/* wraps */


/* tests */

static void test_w_authd_validate_ciphers_single_valid(void **state) {
    assert_int_equal(w_authd_validate_ciphers("TLS_AES_256_GCM_SHA384"), 0);
}

static void test_w_authd_validate_ciphers_multiple_valid(void **state) {
    assert_int_equal(w_authd_validate_ciphers(DEFAULT_CIPHERS), 0);
}

static void test_w_authd_validate_ciphers_invalid_token(void **state) {
    expect_string(__wrap__merror, formatted_msg, "Invalid TLS 1.3 cipher suite 'NOT_A_SUITE' in 'ciphers' option");
    assert_int_equal(w_authd_validate_ciphers("TLS_AES_256_GCM_SHA384:NOT_A_SUITE"), OS_INVALID);
}

static void test_w_authd_validate_ciphers_empty(void **state) {
    assert_int_equal(w_authd_validate_ciphers(""), OS_INVALID);
}

static void test_w_authd_validate_ciphers_null(void **state) {
    assert_int_equal(w_authd_validate_ciphers(NULL), OS_INVALID);
}

static void test_w_authd_validate_ciphers_colon_only(void **state) {
    expect_string(__wrap__merror, formatted_msg, "Invalid TLS 1.3 cipher suite list: ':'");
    assert_int_equal(w_authd_validate_ciphers(":"), OS_INVALID);
}

static void test_w_authd_validate_ciphers_multiple_colons_only(void **state) {
    expect_string(__wrap__merror, formatted_msg, "Invalid TLS 1.3 cipher suite list: ':::'");
    assert_int_equal(w_authd_validate_ciphers(":::"), OS_INVALID);
}

/* Read_Authd_JSON(): the effective `auth` section of etc/wazuh-manager.yml */

static void free_authd_strings(authd_config_t *c) {
    os_free(c->ciphers);
    os_free(c->agent_ca);
    os_free(c->manager_cert);
    os_free(c->manager_key);
}

static void test_Read_Authd_JSON_effective_defaults(void **state) {
    authd_config_t local_config = {0};
    /* What the loader returns for the generated manager file (E1b vector) */
    cJSON *auth = cJSON_Parse(
        "{\"disabled\":false,\"port\":1515,\"ipv6\":false,\"use_source_ip\":false,\"purge\":true,\"use_password\":true,"
        "\"ciphers\":\"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256\","
        "\"ssl_agent_ca\":\"\",\"ssl_verify_host\":false,\"ssl_manager_cert\":\"etc/certs/remoted.pem\","
        "\"ssl_manager_key\":\"etc/certs/remoted-key.pem\",\"remote_enrollment\":true,\"legacy_enrollment\":true,"
        "\"force\":{\"enabled\":true,\"key_mismatch\":true,\"disconnected_time\":{\"enabled\":true,\"value\":\"1h\"},"
        "\"after_registration_time\":\"1h\"},\"agents\":{\"allow_higher_versions\":false}}");
    assert_non_null(auth);

    assert_int_equal(Read_Authd_JSON(auth, &local_config), 0);

    assert_int_equal(local_config.flags.disabled, 0);
    assert_int_equal(local_config.port, 1515);
    assert_false(local_config.ipv6);
    assert_int_equal(local_config.flags.use_source_ip, 0);
    assert_int_equal(local_config.flags.clear_removed, 1);
    assert_int_equal(local_config.flags.use_password, 1);
    assert_string_equal(local_config.ciphers, DEFAULT_CIPHERS);
    assert_null(local_config.agent_ca);
    assert_int_equal(local_config.flags.verify_host, 0);
    assert_string_equal(local_config.manager_cert, "etc/certs/remoted.pem");
    assert_string_equal(local_config.manager_key, "etc/certs/remoted-key.pem");
    assert_int_equal(local_config.flags.remote_enrollment, 1);
    assert_int_equal(local_config.flags.legacy_enrollment, 1);
    assert_true(local_config.force_options.enabled);
    assert_true(local_config.force_options.key_mismatch);
    assert_true(local_config.force_options.disconnected_time_enabled);
    assert_int_equal(local_config.force_options.disconnected_time, 3600);
    assert_int_equal(local_config.force_options.after_registration_time, 3600);
    assert_false(local_config.allow_higher_versions);

    cJSON_Delete(auth);
    free_authd_strings(&local_config);
}

static void test_Read_Authd_JSON_force_times_int_or_string(void **state) {
    authd_config_t local_config = {0};
    cJSON *auth = cJSON_Parse(
        "{\"force\":{\"enabled\":false,\"disconnected_time\":{\"enabled\":false,\"value\":7200},\"after_registration_time\":\"2h\"},"
        "\"agents\":{\"allow_higher_versions\":true}}");
    assert_non_null(auth);

    assert_int_equal(Read_Authd_JSON(auth, &local_config), 0);
    assert_false(local_config.force_options.enabled);
    assert_true(local_config.force_options.key_mismatch); // default kept
    assert_false(local_config.force_options.disconnected_time_enabled);
    assert_int_equal(local_config.force_options.disconnected_time, 7200);
    assert_int_equal(local_config.force_options.after_registration_time, 7200);
    assert_true(local_config.allow_higher_versions);

    cJSON_Delete(auth);
    free_authd_strings(&local_config);
}

static void test_Read_Authd_JSON_empty_agent_ca_is_null(void **state) {
    authd_config_t local_config = {0};
    cJSON *empty = cJSON_Parse("{\"ssl_agent_ca\":\"\"}");
    cJSON *set = cJSON_Parse("{\"ssl_agent_ca\":\"etc/certs/ca.pem\",\"ssl_verify_host\":true}");

    assert_int_equal(Read_Authd_JSON(empty, &local_config), 0);
    assert_null(local_config.agent_ca);

    assert_int_equal(Read_Authd_JSON(set, &local_config), 0);
    assert_string_equal(local_config.agent_ca, "etc/certs/ca.pem");
    assert_int_equal(local_config.flags.verify_host, 1);

    cJSON_Delete(empty);
    cJSON_Delete(set);
    free_authd_strings(&local_config);
}

static void test_Read_Authd_JSON_disabled_true_and_invalid_port(void **state) {
    authd_config_t local_config = {0};
    cJSON *disabled = cJSON_Parse("{\"disabled\":true,\"use_password\":false}");
    cJSON *bad_port = cJSON_Parse("{\"port\":0}");

    assert_int_equal(Read_Authd_JSON(disabled, &local_config), 0);
    assert_int_equal(local_config.flags.disabled, 1);
    assert_int_equal(local_config.flags.use_password, 0);

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'port': 0.");
    assert_int_equal(Read_Authd_JSON(bad_port, &local_config), OS_INVALID);

    cJSON_Delete(disabled);
    cJSON_Delete(bad_port);
    free_authd_strings(&local_config);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests
        cmocka_unit_test(test_Read_Authd_JSON_effective_defaults),
        cmocka_unit_test(test_Read_Authd_JSON_force_times_int_or_string),
        cmocka_unit_test(test_Read_Authd_JSON_empty_agent_ca_is_null),
        cmocka_unit_test(test_Read_Authd_JSON_disabled_true_and_invalid_port),
        cmocka_unit_test(test_w_authd_validate_ciphers_single_valid),
        cmocka_unit_test(test_w_authd_validate_ciphers_multiple_valid),
        cmocka_unit_test(test_w_authd_validate_ciphers_invalid_token),
        cmocka_unit_test(test_w_authd_validate_ciphers_empty),
        cmocka_unit_test(test_w_authd_validate_ciphers_null),
        cmocka_unit_test(test_w_authd_validate_ciphers_colon_only),
        cmocka_unit_test(test_w_authd_validate_ciphers_multiple_colons_only),

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
