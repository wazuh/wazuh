/*
 * Wazuh manager service control - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the Free Software Foundation.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#undef fail
#define main wazuh_manager_service_control_main
#include "../../util/manager_service_control/main.c"
#undef main

static void test_help_option_succeeds(void **state)
{
    (void)state;
    char *argv[] = {"wazuh-manager-service-control", "-h", NULL};

    assert_int_equal(wazuh_manager_service_control_main(2, argv), EXIT_SUCCESS);
}

static void test_actions_are_strictly_allowlisted(void **state)
{
    (void)state;
    assert_true(valid_action("restart"));
    assert_true(valid_action("reload"));
    assert_false(valid_action("status"));
    assert_false(valid_action("restart extra"));
    assert_false(valid_action(""));
}

static void test_caller_requires_allowed_real_uid_and_root_effective_uid(void **state)
{
    (void)state;
    const uid_t manager = 1000;

    assert_true(authorized_caller(manager, manager, 0));
    assert_true(authorized_caller(manager, 0, 0));
    assert_false(authorized_caller(manager, 1001, 0));
    assert_false(authorized_caller(manager, manager, manager));
    assert_false(authorized_caller((uid_t)-1, manager, 0));
}

static void test_privileged_path_policy(void **state)
{
    (void)state;
    struct stat info = {.st_mode = S_IFREG | 04750, .st_uid = 0};

    assert_true(path_is_safe(&info, S_IFREG, true));

    info.st_mode = S_IFREG | 0750;
    assert_false(path_is_safe(&info, S_IFREG, true));
    assert_true(path_is_safe(&info, S_IFREG, false));

    info.st_mode = S_IFREG | 0770;
    assert_false(path_is_safe(&info, S_IFREG, false));

    info.st_mode = S_IFREG | 0752;
    assert_false(path_is_safe(&info, S_IFREG, false));

    info.st_mode = S_IFDIR | 0750;
    assert_true(path_is_safe(&info, S_IFDIR, false));
    assert_false(path_is_safe(&info, S_IFREG, false));

    info.st_uid = 1000;
    assert_false(path_is_safe(&info, S_IFDIR, false));
}

static void test_service_states(void **state)
{
    (void)state;
    assert_int_equal(parse_service_state("active"), SERVICE_ACTIVE);
    assert_int_equal(parse_service_state("activating"), SERVICE_TRANSITIONAL);
    assert_int_equal(parse_service_state("reloading"), SERVICE_TRANSITIONAL);
    assert_int_equal(parse_service_state("deactivating"), SERVICE_TRANSITIONAL);
    assert_int_equal(parse_service_state("inactive"), SERVICE_INACTIVE);
    assert_int_equal(parse_service_state("failed"), SERVICE_INACTIVE);
    assert_int_equal(parse_service_state("unknown"), SERVICE_QUERY_FAILED);
    assert_int_equal(parse_service_state(""), SERVICE_QUERY_FAILED);
}

static void test_install_paths_are_derived_independently(void **state)
{
    (void)state;
    char bin_path[PATH_MAX];
    char home_path[PATH_MAX];
    char control_path[PATH_MAX];
    char process_list_path[PATH_MAX];

    assert_true(derive_install_paths("/var/wazuh-manager/bin/wazuh-manager-service-control",
                                     bin_path,
                                     home_path,
                                     control_path,
                                     process_list_path));
    assert_string_equal(bin_path, "/var/wazuh-manager/bin");
    assert_string_equal(home_path, "/var/wazuh-manager");
    assert_string_not_equal(bin_path, home_path);
    assert_string_equal(control_path, "/var/wazuh-manager/bin/wazuh-manager-control");
    assert_string_equal(process_list_path, "/var/wazuh-manager/bin/.process_list");

    assert_false(derive_install_paths("/var/wazuh-manager/bin/unexpected-control",
                                      bin_path,
                                      home_path,
                                      control_path,
                                      process_list_path));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_help_option_succeeds),
        cmocka_unit_test(test_actions_are_strictly_allowlisted),
        cmocka_unit_test(test_caller_requires_allowed_real_uid_and_root_effective_uid),
        cmocka_unit_test(test_privileged_path_policy),
        cmocka_unit_test(test_service_states),
        cmocka_unit_test(test_install_paths_are_derived_independently),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
