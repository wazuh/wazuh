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


void w_authd_parse_agents(XML_NODE node, authd_config_t * config);
int Read_Authd(const OS_XML *xml, XML_NODE node, void *d1, void *d2);
int Read_Authd_JSON(const cJSON *auth, void *d1);


/* setup/teardown */


/* wraps */


/* tests */

// Test w_authd_parse_agents

authd_config_t config = {0};

static void test_w_authd_parse_agents_no(void **state) {
    config.allow_higher_versions = AUTHD_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT;

    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("allow_higher_versions", node[0]->element);
    os_strdup("no", node[0]->content);
    node[1] = NULL;

    w_authd_parse_agents(node, &config);
    assert_false(config.allow_higher_versions);

    os_free(node[0]->element);
    os_free(node[0]->content);
    os_free(node[0]);
    os_free(node);
}

static void test_w_authd_parse_agents_yes(void **state) {
    config.allow_higher_versions = AUTHD_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT;

    XML_NODE node;

    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("allow_higher_versions", node[0]->element);
    os_strdup("yes", node[0]->content);
    node[1] = NULL;

    w_authd_parse_agents(node, &config);
    assert_true(config.allow_higher_versions);

    os_free(node[0]->element);
    os_free(node[0]->content);
    os_free(node[0]);
    os_free(node);
}

static void test_w_authd_parse_agents_invalid_value(void **state) {
    config.allow_higher_versions = AUTHD_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT;

    XML_NODE node;

    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("allow_higher_versions", node[0]->element);
    os_strdup("invalid_value", node[0]->content);
    node[1] = NULL;

    expect_string(__wrap__mwarn, formatted_msg,
                 "(9001): Ignored invalid value 'invalid_value' for 'allow_higher_versions'.");
    w_authd_parse_agents(node, &config);
    assert_int_equal(config.allow_higher_versions, AUTHD_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT);

    os_free(node[0]->element);
    os_free(node[0]->content);
    os_free(node[0]);
    os_free(node);
}

static void test_w_authd_parse_agents_invalid_element(void **state) {
    config.allow_higher_versions = AUTHD_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT;

    XML_NODE node;

    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("invalid_element", node[0]->element); // Use an invalid element name
    os_strdup("no", node[0]->content);
    node[1] = NULL;

    expect_string(__wrap__mwarn, formatted_msg,
                  "(1230): Invalid element in the configuration: 'invalid_element'.");
    w_authd_parse_agents(node, &config);
    assert_int_equal(config.allow_higher_versions, AUTHD_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT);

    os_free(node[0]->element);
    os_free(node[0]->content);
    os_free(node[0]);
    os_free(node);
}

// Test Read_Authd defaults

static void test_authd_use_password_default(void **state) {
    authd_config_t local_config = {0};

    /* With no <auth> children, only the defaults are applied */
    assert_int_equal(Read_Authd(NULL, NULL, &local_config, NULL), 0);

    /* Binary default is disabled when <use_password> is omitted; the shipped
     * configuration enables it via the template (issue #36705). */
    assert_int_equal(local_config.flags.use_password, 0);

    os_free(local_config.ciphers);
    os_free(local_config.manager_cert);
    os_free(local_config.manager_key);
}

static void test_authd_ciphers_default_is_tls13(void **state) {
    authd_config_t local_config = {0};

    assert_int_equal(Read_Authd(NULL, NULL, &local_config, NULL), 0);
    assert_string_equal(local_config.ciphers, DEFAULT_CIPHERS);

    os_free(local_config.ciphers);
    os_free(local_config.manager_cert);
    os_free(local_config.manager_key);
}

// Test <legacy_enrollment> parsing/defaults

static void test_authd_legacy_enrollment_default(void **state) {
    authd_config_t local_config = {0};

    /* With no <auth> children, legacy_enrollment defaults to enabled -- unlike use_password,
     * nothing should change for a deployment that never touches this new setting. */
    assert_int_equal(Read_Authd(NULL, NULL, &local_config, NULL), 0);
    assert_int_equal(local_config.flags.legacy_enrollment, 1);

    os_free(local_config.ciphers);
    os_free(local_config.manager_cert);
    os_free(local_config.manager_key);
}

static void test_read_authd_legacy_enrollment_yes(void **state) {
    authd_config_t local_config = {0};

    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("legacy_enrollment", node[0]->element);
    os_strdup("yes", node[0]->content);
    node[1] = NULL;

    assert_int_equal(Read_Authd(NULL, node, &local_config, NULL), 0);
    assert_int_equal(local_config.flags.legacy_enrollment, 1);

    os_free(node[0]->element);
    os_free(node[0]->content);
    os_free(node[0]);
    os_free(node);
    os_free(local_config.ciphers);
    os_free(local_config.manager_cert);
    os_free(local_config.manager_key);
}

static void test_read_authd_legacy_enrollment_no(void **state) {
    authd_config_t local_config = {0};

    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("legacy_enrollment", node[0]->element);
    os_strdup("no", node[0]->content);
    node[1] = NULL;

    assert_int_equal(Read_Authd(NULL, node, &local_config, NULL), 0);
    assert_int_equal(local_config.flags.legacy_enrollment, 0);

    os_free(node[0]->element);
    os_free(node[0]->content);
    os_free(node[0]);
    os_free(node);
    os_free(local_config.ciphers);
    os_free(local_config.manager_cert);
    os_free(local_config.manager_key);
}

static void test_read_authd_legacy_enrollment_invalid(void **state) {
    authd_config_t local_config = {0};

    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("legacy_enrollment", node[0]->element);
    os_strdup("invalid_value", node[0]->content);
    node[1] = NULL;

    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'legacy_enrollment': invalid_value.");
    assert_int_equal(Read_Authd(NULL, node, &local_config, NULL), OS_INVALID);

    os_free(node[0]->element);
    os_free(node[0]->content);
    os_free(node[0]);
    os_free(node);
    os_free(local_config.ciphers);
    os_free(local_config.manager_cert);
    os_free(local_config.manager_key);
}

// Test ssl_auto_negotiate removal (issue #38091)

static void test_read_authd_ssl_auto_negotiate_removed(void **state) {
    authd_config_t local_config = {0};

    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ssl_auto_negotiate", node[0]->element);
    os_strdup("yes", node[0]->content);
    node[1] = NULL;

    expect_string(__wrap__merror, formatted_msg, "(1230): Invalid element in the configuration: 'ssl_auto_negotiate'.");
    assert_int_equal(Read_Authd(NULL, node, &local_config, NULL), OS_INVALID);

    os_free(node[0]->element);
    os_free(node[0]->content);
    os_free(node[0]);
    os_free(node);
    os_free(local_config.ciphers);
    os_free(local_config.manager_cert);
    os_free(local_config.manager_key);
}

// Test <ciphers> parsing/validation

static void test_read_authd_ciphers_valid(void **state) {
    authd_config_t local_config = {0};

    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ciphers", node[0]->element);
    os_strdup("TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256", node[0]->content);
    node[1] = NULL;

    assert_int_equal(Read_Authd(NULL, node, &local_config, NULL), 0);
    assert_string_equal(local_config.ciphers, "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256");

    os_free(node[0]->element);
    os_free(node[0]->content);
    os_free(node[0]);
    os_free(node);
    os_free(local_config.ciphers);
    os_free(local_config.manager_cert);
    os_free(local_config.manager_key);
}

static void test_read_authd_ciphers_invalid(void **state) {
    authd_config_t local_config = {0};

    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ciphers", node[0]->element);
    os_strdup("HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH", node[0]->content);
    node[1] = NULL;

    expect_string(__wrap__merror, formatted_msg, "Invalid TLS 1.3 cipher suite 'HIGH' in 'ciphers' option");
    assert_int_equal(Read_Authd(NULL, node, &local_config, NULL), OS_INVALID);

    os_free(node[0]->element);
    os_free(node[0]->content);
    os_free(node[0]);
    os_free(node);
    os_free(local_config.ciphers);
    os_free(local_config.manager_cert);
    os_free(local_config.manager_key);
}

// Test w_authd_validate_ciphers directly

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

/* Read_Authd_JSON(): the effective `auth` section of etc/wazuh-manager.conf */

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
        cmocka_unit_test(test_w_authd_parse_agents_no),
        cmocka_unit_test(test_w_authd_parse_agents_yes),
        cmocka_unit_test(test_w_authd_parse_agents_invalid_value),
        cmocka_unit_test(test_w_authd_parse_agents_invalid_element),
        cmocka_unit_test(test_authd_use_password_default),
        cmocka_unit_test(test_authd_ciphers_default_is_tls13),
        cmocka_unit_test(test_authd_legacy_enrollment_default),
        cmocka_unit_test(test_read_authd_legacy_enrollment_yes),
        cmocka_unit_test(test_read_authd_legacy_enrollment_no),
        cmocka_unit_test(test_read_authd_legacy_enrollment_invalid),
        cmocka_unit_test(test_read_authd_ssl_auto_negotiate_removed),
        cmocka_unit_test(test_read_authd_ciphers_valid),
        cmocka_unit_test(test_read_authd_ciphers_invalid),
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
