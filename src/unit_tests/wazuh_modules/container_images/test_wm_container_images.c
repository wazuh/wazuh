/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Tests for the container_images module configuration parser.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "shared.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "wmodules.h"
#include "wm_container_images.h"
#include "../scheduling/wmodules_scheduling_helpers.h"

static void wmodule_cleanup(wmodule *module) {
    if (module) {
        wm_container_images_t *data = (wm_container_images_t *)module->data;

        if (data && data->local_paths) {
            for (int i = 0; i < data->local_paths_count; i++) {
                os_free(data->local_paths[i]);
            }
            os_free(data->local_paths);
        }

        os_free(module->data);
        os_free(module->tag);
        os_free(module);
    }
}

static int setup_test_read(void **state) {
    test_structure *test = calloc(1, sizeof(test_structure));
    test->module = calloc(1, sizeof(wmodule));
    *state = test;
    return 0;
}

static int teardown_test_read(void **state) {
    test_structure *test = *state;
    OS_ClearNode(test->nodes);
    OS_ClearXML(&(test->xml));
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}

void test_read_defaults(void **state) {
    const char *string = "";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->enabled, 1);
    assert_int_equal(data->scan_on_start, 1);
    assert_int_equal(data->interval, WM_CONTAINER_IMAGES_DEFAULT_INTERVAL);
    assert_int_equal(data->local_paths_count, 0);
}

void test_read_full_configuration(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<scan_on_start>no</scan_on_start>\n"
        "<interval>30m</interval>\n"
        "<references>\n"
        "  <local>/var/lib/containers</local>\n"
        "</references>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->enabled, 1);
    assert_int_equal(data->scan_on_start, 0);
    assert_int_equal(data->interval, 1800);
    assert_int_equal(data->local_paths_count, 1);
    assert_string_equal(data->local_paths[0], "/var/lib/containers");
}

void test_read_multiple_local_references(void **state) {
    const char *string =
        "<references>\n"
        "  <local>/opt/a</local>\n"
        "  <local>/opt/b</local>\n"
        "</references>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->local_paths_count, 2);
    assert_string_equal(data->local_paths[0], "/opt/a");
    assert_string_equal(data->local_paths[1], "/opt/b");
}

void test_read_unsupported_reference_type(void **state) {
    const char *string =
        "<references>\n"
        "  <ref>nginx:1.27</ref>\n"
        "</references>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg, "Reference type 'ref' is not supported yet at module 'container_images', ignoring it.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->local_paths_count, 0);
}

void test_read_empty_local_reference(void **state) {
    const char *string =
        "<references>\n"
        "  <local></local>\n"
        "</references>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mterror, tag);
    expect_string(__wrap__mterror, formatted_msg, "Empty 'local' reference at module 'container_images'.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), OS_INVALID);
}

void test_read_disabled(void **state) {
    const char *string = "<enabled>no</enabled>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->enabled, 0);
}

void test_read_interval_hours(void **state) {
    const char *string = "<interval>2h</interval>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->interval, 7200);
}

void test_read_invalid_interval(void **state) {
    const char *string = "<interval>abc</interval>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mterror, tag);
    expect_string(__wrap__mterror, formatted_msg, "Invalid interval at module 'container_images'.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), OS_INVALID);
}

void test_read_invalid_enabled(void **state) {
    const char *string = "<enabled>maybe</enabled>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mterror, tag);
    expect_string(__wrap__mterror, formatted_msg, "Invalid content for tag 'enabled' at module 'container_images'.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), OS_INVALID);
}

void test_read_unknown_tag(void **state) {
    const char *string = "<unknown>value</unknown>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg, "No such tag 'unknown' at module 'container_images'.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_read_defaults, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_full_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_multiple_local_references, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_unsupported_reference_type, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_empty_local_reference, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_disabled, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_hours, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_invalid_interval, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_invalid_enabled, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_unknown_tag, setup_test_read, teardown_test_read),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
