/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* cluster_utils.c over the mconf hook: the test registers its own provider (no libconfig, no files). */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "cluster_utils.h"
#include "mconf_hook.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../external/cJSON/cJSON.h"

/* The `cluster` section the provider answers with; NULL = no document. */
static const char *s_cluster_json = NULL;

static cJSON *test_provider(const char *section) {
    assert_string_equal(section, "cluster");
    return s_cluster_json != NULL ? cJSON_Parse(s_cluster_json) : NULL;
}

static int setup_provider(void **state) {
    (void) state;
    s_cluster_json = NULL;
    w_mconf_hook_set(test_provider);
    return 0;
}

static int teardown_provider(void **state) {
    (void) state;
    w_mconf_hook_set(NULL);
    return 0;
}

static void test_w_is_worker_master_worker_and_no_section(void **state) {
    (void) state;

    s_cluster_json = "{\"name\":\"wazuh\",\"node_name\":\"node01\",\"node_type\":\"master\"}";
    assert_int_equal(w_is_worker(), 0);

    s_cluster_json = "{\"node_type\":\"worker\"}";
    assert_int_equal(w_is_worker(), 1);

    s_cluster_json = NULL;
    assert_int_equal(w_is_worker(), OS_INVALID);
}

static void test_w_is_single_node_follows_node_type(void **state) {
    (void) state;
    int is_worker = 7;

    s_cluster_json = "{\"node_type\":\"worker\"}";
    assert_int_equal(w_is_single_node(&is_worker), 0);
    assert_int_equal(is_worker, 1);

    s_cluster_json = "{\"node_type\":\"master\"}";
    assert_int_equal(w_is_single_node(&is_worker), 0);
    assert_int_equal(is_worker, 0);

    s_cluster_json = "{\"name\":\"wazuh\"}"; // no node_type
    assert_int_equal(w_is_single_node(NULL), 1);

    s_cluster_json = NULL;
    assert_int_equal(w_is_single_node(&is_worker), OS_INVALID);
    assert_int_equal(is_worker, OS_INVALID);
}

static void test_get_names_from_section_and_undefined(void **state) {
    (void) state;

    s_cluster_json = "{\"name\":\"wazuh-xml\",\"node_name\":\"node07\",\"node_type\":\"master\"}";
    char *cluster_name = get_cluster_name();
    char *node_name = get_node_name();
    assert_string_equal(cluster_name, "wazuh-xml");
    assert_string_equal(node_name, "node07");
    free(cluster_name);
    free(node_name);

    s_cluster_json = NULL;
    cluster_name = get_cluster_name();
    node_name = get_node_name();
    assert_string_equal(cluster_name, "undefined");
    assert_string_equal(node_name, "undefined");
    free(cluster_name);
    free(node_name);
}

static void test_hook_without_provider_is_null(void **state) {
    (void) state;

    w_mconf_hook_set(NULL);
    assert_null(w_mconf_hook_section("cluster"));
    assert_int_equal(w_is_worker(), OS_INVALID);

    char *node_name = get_node_name();
    assert_string_equal(node_name, "undefined");
    free(node_name);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_w_is_worker_master_worker_and_no_section, setup_provider, teardown_provider),
        cmocka_unit_test_setup_teardown(test_w_is_single_node_follows_node_type, setup_provider, teardown_provider),
        cmocka_unit_test_setup_teardown(test_get_names_from_section_and_undefined, setup_provider, teardown_provider),
        cmocka_unit_test_setup_teardown(test_hook_without_provider_is_null, setup_provider, teardown_provider),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
