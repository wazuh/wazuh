/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "macos_log_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

void __wrap_w_macos_create_log_env(logreader * lf, w_sysinfo_helpers_t * global_sysinfo) {

    check_expected_ptr(lf);
    check_expected(global_sysinfo);
}

void __wrap_w_macos_set_last_log_timestamp(char * timestamp) {

    check_expected(timestamp);
}

void __wrap_w_macos_set_log_settings(char * settings) {

    check_expected(settings);
}

char * __wrap_w_macos_get_last_log_timestamp(void) {

    return mock_ptr_type(char *);
}

char * __wrap_w_macos_get_log_settings(void) {

    return mock_ptr_type(char *);
}

cJSON * __wrap_w_macos_get_status_as_JSON(void) {

    return mock_ptr_type(cJSON *);
}

void __wrap_w_macos_set_status_from_JSON(cJSON * global_json) {

    check_expected(global_json);
}

bool __wrap_w_is_macos_sierra() {

    return mock_type(bool);
}

pid_t __wrap_w_get_first_child(pid_t parent_pid) {

    check_expected(parent_pid);
    return mock_type(pid_t);
}

bool __wrap_w_macos_get_is_valid_data() {
    return mock_type(bool);
}

void __wrap_w_macos_set_is_valid_data(bool is_valid) {
    check_expected(is_valid);
}
