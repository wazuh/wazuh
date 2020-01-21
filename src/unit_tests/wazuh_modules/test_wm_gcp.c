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
#include <stdio.h>
#include <stdlib.h>

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/wm_gcp.h"
#include "../../headers/defs.h"

#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);

void wm_gcp_run(const wm_gcp *data);

/* wrappers */

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path) {
    check_expected(command);
    check_expected(secs);
    check_expected(add_path);

    *output = mock_type(char*);
    *exitcode = mock();

    return mock();
}

void __wrap__mtdebug1(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mtinfo(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mtwarn(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mterror(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

/* setup/teardown */
static int setup_group(void **state) {
    wm_gcp *gcp_config = calloc(1, sizeof(wm_gcp));

    if(gcp_config == NULL)
        return -1;

    if(gcp_config->project_id = calloc(OS_SIZE_1024, sizeof(char)), gcp_config->project_id == NULL)
        return -1;

    if(gcp_config->subscription_name = calloc(OS_SIZE_1024, sizeof(char)), gcp_config->subscription_name == NULL)
        return -1;

    if(gcp_config->credentials_file = calloc(OS_SIZE_1024, sizeof(char)), gcp_config->credentials_file == NULL)
        return -1;

    *state = gcp_config;

    return 0;
}

static int teardown_group(void **state) {
    wm_gcp *gcp_config = *state;

    free(gcp_config->project_id);
    free(gcp_config->subscription_name);
    free(gcp_config->credentials_file);

    free(gcp_config);

    return 0;
}

/* tests */
/* wm_gcp_run */
static void test_wm_gcp_run_success_log_disabled(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 0;    // disabled

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtinfo, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Logging disabled.");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_error_running_command(void **state)  {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 0;    // disabled

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 1);

    expect_string(__wrap__mterror, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "Internal error. Exiting...");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_unknown_error(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 0;    // disabled

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Unknown error - This is an unknown error."));
    will_return(__wrap_wm_exec, 1);
    will_return(__wrap_wm_exec, 0);

    expect_string_count(__wrap__mtwarn, tag, WM_GCP_LOGTAG, 2);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 1");
    expect_string(__wrap__mtwarn, formatted_msg, "Unknown error - This is an unknown error.");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "OUTPUT: Unknown error - This is an unknown error.");

    expect_string(__wrap__mtinfo, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Logging disabled.");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_unknown_error_no_description(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 0;    // disabled

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("This description does not match the criteria"));
    will_return(__wrap_wm_exec, 1);
    will_return(__wrap_wm_exec, 0);

    expect_string_count(__wrap__mtwarn, tag, WM_GCP_LOGTAG, 2);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 1");
    expect_string(__wrap__mtwarn, formatted_msg, "Unknown error.");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "OUTPUT: This description does not match the criteria");

    expect_string(__wrap__mtinfo, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Logging disabled.");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_error_parsing_args(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 0;    // disabled

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Error!! integration.py: error: unable to parse"));
    will_return(__wrap_wm_exec, 2);
    will_return(__wrap_wm_exec, 0);

    expect_string_count(__wrap__mtwarn, tag, WM_GCP_LOGTAG, 2);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 2");
    expect_string(__wrap__mtwarn, formatted_msg, "Error parsing arguments: error: unable to parse");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "OUTPUT: Error!! integration.py: error: unable to parse");

    expect_string(__wrap__mtinfo, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Logging disabled.");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_error_parsing_args_no_description(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 0;    // disabled

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Error!! But won't trigger a specific message"));
    will_return(__wrap_wm_exec, 2);
    will_return(__wrap_wm_exec, 0);

    expect_string_count(__wrap__mtwarn, tag, WM_GCP_LOGTAG, 2);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 2");
    expect_string(__wrap__mtwarn, formatted_msg, "Error parsing arguments.");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "OUTPUT: Error!! But won't trigger a specific message");

    expect_string(__wrap__mtinfo, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Logging disabled.");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_generic_error(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 0;    // disabled

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("ERROR: A specific error message."));
    will_return(__wrap_wm_exec, 3);
    will_return(__wrap_wm_exec, 0);

    expect_string_count(__wrap__mtwarn, tag, WM_GCP_LOGTAG, 2);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 3");
    expect_string(__wrap__mtwarn, formatted_msg, "A specific error message.");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "OUTPUT: ERROR: A specific error message.");

    expect_string(__wrap__mtinfo, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Logging disabled.");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_generic_error_no_description(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 0;    // disabled

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("A specific error message."));
    will_return(__wrap_wm_exec, 3);
    will_return(__wrap_wm_exec, 0);

    expect_string_count(__wrap__mtwarn, tag, WM_GCP_LOGTAG, 2);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 3");
    expect_string(__wrap__mtwarn, formatted_msg, "A specific error message.");

    expect_string(__wrap__mtinfo, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Logging disabled.");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_debug_message_debug(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 1;    // debug

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - DEBUG - This is a debug message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Test output - DEBUG - This is a debug message");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_debug_message_not_debug(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 1;    // debug

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - This is a message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Test output - This is a message");

    wm_gcp_run(gcp_config);
}


static void test_wm_gcp_run_logging_debug_message_not_debug_discarded(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 1;    // debug

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - INFO - This is a dicarded message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_info_message_info(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 2;    // info

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 2");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - INFO - This is an info message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtinfo, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "- INFO - This is an info message");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_info_message_debug(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 2;    // info

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 2");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - DEBUG - This is an info message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_info_message_warning(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 2;    // info

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 2");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - WARNING - This is a warning message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Test output - WARNING - This is a warning message");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_warning_message_warning(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 3;    // warning

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 3");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 3");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - WARNING - This is a warning message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "- WARNING - This is a warning message");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_warning_message_debug(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 3;    // warning

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 3");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 3");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - DEBUG - This is a debug message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_warning_message_error(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 3;    // warning

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 3");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 3");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - ERROR - This is an error message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mterror, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "- ERROR - This is an error message");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_error_message_error(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 4;    // error

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 4");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 4");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - ERROR - This is an error message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mterror, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "- ERROR - This is an error message");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_error_message_info(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 4;    // error

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 4");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 4");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - INFO - This is an info message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_error_message_critical(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 4;    // error

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 4");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 4");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - CRITICAL - This is a critical message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mterror, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "- CRITICAL - This is a critical message");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_critical_message_critical(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 5;    // critical

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 5");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 5");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - CRITICAL - This is a critical message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mterror, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "- CRITICAL - This is a critical message");

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_critical_message_debug(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 5;    // critical

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 5");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud.py --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 5");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - DEBUG - This is a debug message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    wm_gcp_run(gcp_config);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_wm_gcp_run_success_log_disabled),
        cmocka_unit_test(test_wm_gcp_run_error_running_command),
        cmocka_unit_test(test_wm_gcp_run_unknown_error),
        cmocka_unit_test(test_wm_gcp_run_unknown_error_no_description),
        cmocka_unit_test(test_wm_gcp_run_error_parsing_args),
        cmocka_unit_test(test_wm_gcp_run_error_parsing_args_no_description),
        cmocka_unit_test(test_wm_gcp_run_generic_error),
        cmocka_unit_test(test_wm_gcp_run_logging_debug_message_debug),
        cmocka_unit_test(test_wm_gcp_run_logging_debug_message_not_debug),
        cmocka_unit_test(test_wm_gcp_run_logging_debug_message_not_debug_discarded),
        cmocka_unit_test(test_wm_gcp_run_logging_info_message_info),
        cmocka_unit_test(test_wm_gcp_run_logging_info_message_debug),
        cmocka_unit_test(test_wm_gcp_run_logging_info_message_warning),
        cmocka_unit_test(test_wm_gcp_run_logging_warning_message_warning),
        cmocka_unit_test(test_wm_gcp_run_logging_warning_message_debug),
        cmocka_unit_test(test_wm_gcp_run_logging_warning_message_error),
        cmocka_unit_test(test_wm_gcp_run_logging_error_message_error),
        cmocka_unit_test(test_wm_gcp_run_logging_error_message_info),
        cmocka_unit_test(test_wm_gcp_run_logging_error_message_critical),
        cmocka_unit_test(test_wm_gcp_run_logging_critical_message_critical),
        cmocka_unit_test(test_wm_gcp_run_logging_critical_message_debug),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
