/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the scheduling capacities
 * for azure Module
 * */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>

#include "shared.h"
#include "../../../wazuh_modules/wmodules.h"

#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_exec_wrappers.h"

int msg_to_print_according_to_debugLevel (char *buff_output, char * tokenized_line, char *str_level, char* service_title);

/* wraps */
int __wrap_isDebug() {
    return mock();
}

static void tmp_Dlevel0 (const char *logtag) {
    expect_string(__wrap__mtinfo, tag, logtag);
    expect_string(__wrap__mtinfo, formatted_msg, "Received and acknowledged 0 messages");

    expect_string(__wrap__mterror, tag, logtag);
    expect_string(__wrap__mterror, formatted_msg, "This is an Error");

    expect_string(__wrap__mtwarn, tag, logtag);
    expect_string(__wrap__mtwarn, formatted_msg, "This is a Warning");

    expect_string(__wrap__mterror, tag, logtag);
    expect_string(__wrap__mterror, formatted_msg, "This is a Critical");
}

static void test_wm_parse_output_Dlevel0(void **state) {
    char * output_module = {
        ":azure_wodle: - DEBUG - Setting 1 thread to pull 100 messages in total\n"
        ":azure_wodle: - INFO - Received and acknowledged 0 messages\n"
        ":azure_wodle: - ERROR - This is an Error\n"
        ":azure_wodle: - WARNING - This is a Warning\n"
        ":azure_wodle: - CRITICAL - This is a Critical\n"
        };

    will_return(__wrap_isDebug, 0);
    tmp_Dlevel0(WM_AZURE_LOGTAG);

    wm_parse_output(output_module, WM_AZURE_LOGGING_TOKEN, WM_AZURE_LOGTAG, NULL);

}

static void test_wm_parse_output_Dlevel1(void **state) {
    char * output_module = {
        ":azure_wodle: - DEBUG - Setting 1 thread to pull 100 messages in total\n"
        ":azure_wodle: - INFO - Received and acknowledged 0 messages\n"
        ":azure_wodle: - ERROR - This is an Error\n"
        ":azure_wodle: - WARNING - This is a Warning\n"
        ":azure_wodle: - CRITICAL - This is a Critical\n"
        };

    will_return(__wrap_isDebug, 1);
    expect_string(__wrap__mtdebug1, tag, WM_AZURE_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Setting 1 thread to pull 100 messages in total");

    tmp_Dlevel0(WM_AZURE_LOGTAG);

    wm_parse_output(output_module, WM_AZURE_LOGGING_TOKEN, WM_AZURE_LOGTAG, NULL);

}

static void test_wm_parse_output_all_with_error(void **state) {
    char * output_module = {
        ":azure_wodlxxxx: - DEBUG - Setting 1 thread to pull 100 messages in total\n"
        ":azure_wodlexxx: - INFO - Received and acknowledged 0 messages\n"
        ":azure_wodlexxx: - ERROR - This is an Error\n"
        ":azure_wodlexxx: - WARNING - This is a Warning\n"
        ":azure_wodlexxx: - CRITICAL - This is a Critical\n"
        };

    will_return(__wrap_isDebug, 1);

    wm_parse_output(output_module, WM_AZURE_LOGGING_TOKEN, WM_AZURE_LOGTAG, NULL);

}

static void test_msg_to_print_according_to_debugLevel(void **state) {
    char * tokenized_line = {
        "- DEBUG - Setting 1 thread to pull 100 messages in total"
        };

    char buff[65535] ={0};
    char * service_title = "az-title";

    if(msg_to_print_according_to_debugLevel(buff, tokenized_line, W_STR_DEBUG, NULL)) {
        assert_string_equal(buff, "Setting 1 thread to pull 100 messages in total");
    }

    memset(buff, 0, 65535);
    tokenized_line = "- DEBUG - Setting 1 thread to pull 100 messages in total";
    if(msg_to_print_according_to_debugLevel(buff, tokenized_line, W_STR_DEBUG, service_title)) {
        assert_string_equal(buff, "az-title Setting 1 thread to pull 100 messages in total");
    }
}

static void test_msg_to_print_according_to_debugLevel_error(void **state) {
    char * tokenized_line = {
        "- DEBUGXXXX - Setting 1 thread to pull 100 messages in total"
        };

    char buff[65535] = {0};

    if(0 == msg_to_print_according_to_debugLevel(buff, tokenized_line, W_STR_DEBUG, NULL)) {
        assert_string_equal(buff, "");
    }
}

int main(void) {
    const struct CMUnitTest tests_parser_output[] = {
        /*wm_parser_output  */
        cmocka_unit_test(test_wm_parse_output_Dlevel0),
        cmocka_unit_test(test_wm_parse_output_Dlevel1),
        cmocka_unit_test(test_wm_parse_output_all_with_error),
        cmocka_unit_test(test_msg_to_print_according_to_debugLevel),
        cmocka_unit_test(test_msg_to_print_according_to_debugLevel_error)
    };

    int result;
    result = cmocka_run_group_tests(tests_parser_output, NULL, NULL);
    return result;
}