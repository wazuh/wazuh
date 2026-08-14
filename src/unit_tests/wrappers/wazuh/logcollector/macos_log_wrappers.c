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
#include <stdint.h>
#include <cmocka.h>

void __wrap_w_macos_set_last_log_timestamp(char * timestamp) {

    check_expected(timestamp);
}

void __wrap_w_macos_set_log_settings(char * settings) {

    check_expected(settings);
}

bool __wrap_w_is_macos_sierra() {

    return mock_type(bool);
}

pid_t __wrap_w_get_first_child(pid_t parent_pid) {

    check_expected(parent_pid);
    return mock_type(pid_t);
}

void __wrap_w_macos_set_is_valid_data(bool is_valid) {
    check_expected(is_valid);
}
