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

#include "../../os_auth/auth.h"
#include "../../headers/shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"


void w_authd_parse_agents(XML_NODE node, authd_config_t * config);


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

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests
        cmocka_unit_test(test_w_authd_parse_agents_no),
        cmocka_unit_test(test_w_authd_parse_agents_yes),
        cmocka_unit_test(test_w_authd_parse_agents_invalid_value),
        cmocka_unit_test(test_w_authd_parse_agents_invalid_element),

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
