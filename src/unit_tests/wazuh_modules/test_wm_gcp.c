/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "../../wazuh_modules/wm_gcp.h"

void wm_gcp_run(const wm_gcp *data);

/* tests */
static void test_wm_gcp_run_full_command(void **state) {}
static void test_wm_gcp_run_error_running_command(void **state) {}
static void test_wm_gcp_run_unknown_error(void **state) {}
static void test_wm_gcp_run_error_parsing_args(void **state) {}
static void test_wm_gcp_run_generic_error(void **state) {}
static void test_wm_gcp_run_logging_disabled(void **state) {}
static void test_wm_gcp_run_logging_debug_message_debug(void **state) {}
static void test_wm_gcp_run_logging_debug_message_not_debug(void **state) {}
static void test_wm_gcp_run_logging_debug_message_invalid(void **state) {}
static void test_wm_gcp_run_logging_info_message_info(void **state) {}
static void test_wm_gcp_run_logging_info_message_debug(void **state) {}
static void test_wm_gcp_run_logging_info_message_warning(void **state) {}
static void test_wm_gcp_run_logging_warning_message_warning(void **state) {}
static void test_wm_gcp_run_logging_warning_message_debug(void **state) {}
static void test_wm_gcp_run_logging_warning_message_error(void **state) {}
static void test_wm_gcp_run_logging_error_message_error(void **state) {}
static void test_wm_gcp_run_logging_error_message_info(void **state) {}
static void test_wm_gcp_run_logging_error_message_critical(void **state) {}
static void test_wm_gcp_run_logging_critical_message_critical(void **state) {}
static void test_wm_gcp_run_logging_critical_message_debug(void **state) {}

int main(void) {
    const struct CMUnitTest tests[] = {
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
