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
#include "../../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/schedule_scan_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_exec_wrappers.h"

void wm_gcp_run(const wm_gcp *data);
cJSON *wm_gcp_dump(const wm_gcp *data);
void wm_gcp_destroy(wm_gcp * data);
void* wm_gcp_main(wm_gcp *data);

/* Auxiliar structs */
typedef struct __gcp_dump_s {
    wm_gcp *config;
    cJSON *dump;
    cJSON *root;
    cJSON *wm_wd;
}gcp_dump_t;

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

static int setup_gcp_dump(void **state) {
    gcp_dump_t *dump_data = calloc(1, sizeof(gcp_dump_t));

    if(dump_data == NULL)
        return -1;

    if(dump_data->root = __real_cJSON_CreateObject(), dump_data->root == NULL)
        return -1;

    if(dump_data->wm_wd = __real_cJSON_CreateObject(), dump_data->wm_wd == NULL)
        return -1;

    // Move some pointers around in order to add some info for these tests
    dump_data->config = *state;
    *state = dump_data;

    return 0;
}

static int teardown_gcp_dump(void **state) {
    gcp_dump_t *dump_data = *state;

    // Make sure to keep the group information.
    *state = dump_data->config;

    // Free/delete everything else
    cJSON_Delete(dump_data->dump);
    free(dump_data);

    return 0;
}

static int setup_gcp_destroy(void **state) {
    wm_gcp **gcp_config;

    if(gcp_config = calloc(2, sizeof(wm_gcp*)), gcp_config == NULL)
        return -1;

    // Save the globally used gcp_config
    gcp_config[1] = *state;

    // And create a new one to be destroyed by tests
    if(gcp_config[0] = calloc(1, sizeof(wm_gcp)), gcp_config[0] == NULL)
        return -1;

    if(gcp_config[0]->project_id = calloc(OS_SIZE_1024, sizeof(char)), gcp_config[0]->project_id == NULL)
        return -1;

    if(gcp_config[0]->subscription_name = calloc(OS_SIZE_1024, sizeof(char)), gcp_config[0]->subscription_name == NULL)
        return -1;

    if(gcp_config[0]->credentials_file = calloc(OS_SIZE_1024, sizeof(char)), gcp_config[0]->credentials_file == NULL)
        return -1;

    *state = gcp_config;

    return 0;
}

static int teardown_gcp_destroy(void **state) {
    wm_gcp **gcp_config;

    gcp_config = *state;

    // gcp_config[0] was destroyed by the test, restore the original into state
    *state = gcp_config[1];

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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("A specific error message."));
    will_return(__wrap_wm_exec, 3);
    will_return(__wrap_wm_exec, 0);

    expect_string_count(__wrap__mtwarn, tag, WM_GCP_LOGTAG, 2);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 3");
    expect_string(__wrap__mtwarn, formatted_msg, "A specific error message.");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "OUTPUT: A specific error message.");

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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 2");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 2");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 2");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - WARNING - This is a warning message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_warning_message_warning(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 3;    // warning

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 3");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 3");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 3");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 3");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - ERROR - This is an error message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_error_message_error(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 4;    // error

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 4");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 4");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 4");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 4");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - CRITICAL - This is a critical message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    wm_gcp_run(gcp_config);
}

static void test_wm_gcp_run_logging_critical_message_critical(void **state) {
    wm_gcp *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 5;    // critical

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 5");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
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

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 5");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --log_level 5");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output - DEBUG - This is a debug message"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    wm_gcp_run(gcp_config);
}

/* wm_gcp_dump */
static void test_wm_gcp_dump_success_logging_disabled(void **state) {
    gcp_dump_t *gcp_dump_data = *state;

    gcp_dump_data->config->enabled = 1;
    gcp_dump_data->config->pull_on_start = 1;
    gcp_dump_data->config->logging = 0;    // disabled
    gcp_dump_data->config->max_messages = 10;

    snprintf(gcp_dump_data->config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_dump_data->config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_dump_data->config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    will_return(__wrap_cJSON_CreateObject, gcp_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_dump_data->wm_wd);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_dump_data->wm_wd);

    gcp_dump_data->dump = wm_gcp_dump(gcp_dump_data->config);

    assert_non_null(gcp_dump_data->dump);
    assert_ptr_equal(gcp_dump_data->dump, gcp_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_dump_data->dump), 1);

    cJSON *gcp_pubsub = cJSON_GetObjectItem(gcp_dump_data->dump, "gcp-pubsub");
    assert_non_null(gcp_pubsub);
    assert_int_equal(cJSON_GetArraySize(gcp_pubsub), 7);

    cJSON *enabled = cJSON_GetObjectItem(gcp_pubsub, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "yes");
    cJSON *pull_on_start = cJSON_GetObjectItem(gcp_pubsub, "pull_on_start");
    assert_string_equal(cJSON_GetStringValue(pull_on_start), "yes");
    cJSON *max_messages = cJSON_GetObjectItem(gcp_pubsub, "max_messages");
    assert_non_null(max_messages);
    assert_int_equal(max_messages->valueint, 10);
    cJSON *project_id = cJSON_GetObjectItem(gcp_pubsub, "project_id");
    assert_string_equal(cJSON_GetStringValue(project_id), "wazuh-gcp-test");
    cJSON *subscription_name = cJSON_GetObjectItem(gcp_pubsub, "subscription_name");
    assert_string_equal(cJSON_GetStringValue(subscription_name), "wazuh-subscription-test");
    cJSON *credentials_file = cJSON_GetObjectItem(gcp_pubsub, "credentials_file");
    assert_string_equal(cJSON_GetStringValue(credentials_file), "/wazuh/credentials/test.json");
    cJSON *logging = cJSON_GetObjectItem(gcp_pubsub, "logging");
    assert_string_equal(cJSON_GetStringValue(logging), "disabled");
}

static void test_wm_gcp_dump_success_logging_debug(void **state) {
    gcp_dump_t *gcp_dump_data = *state;

    gcp_dump_data->config->enabled = 0;
    gcp_dump_data->config->pull_on_start = 0;
    gcp_dump_data->config->logging = 1;    // debug
    gcp_dump_data->config->max_messages = 100;

    snprintf(gcp_dump_data->config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_dump_data->config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_dump_data->config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    will_return(__wrap_cJSON_CreateObject, gcp_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_dump_data->wm_wd);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_dump_data->wm_wd);

    gcp_dump_data->dump = wm_gcp_dump(gcp_dump_data->config);

    assert_non_null(gcp_dump_data->dump);
    assert_ptr_equal(gcp_dump_data->dump, gcp_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_dump_data->dump), 1);

    cJSON *gcp_pubsub = cJSON_GetObjectItem(gcp_dump_data->dump, "gcp-pubsub");
    assert_non_null(gcp_pubsub);
    assert_int_equal(cJSON_GetArraySize(gcp_pubsub), 7);

    cJSON *enabled = cJSON_GetObjectItem(gcp_pubsub, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "no");
    cJSON *pull_on_start = cJSON_GetObjectItem(gcp_pubsub, "pull_on_start");
    assert_string_equal(cJSON_GetStringValue(pull_on_start), "no");
    cJSON *max_messages = cJSON_GetObjectItem(gcp_pubsub, "max_messages");
    assert_non_null(max_messages);
    assert_int_equal(max_messages->valueint, 100);
    cJSON *project_id = cJSON_GetObjectItem(gcp_pubsub, "project_id");
    assert_string_equal(cJSON_GetStringValue(project_id), "wazuh-gcp-test");
    cJSON *subscription_name = cJSON_GetObjectItem(gcp_pubsub, "subscription_name");
    assert_string_equal(cJSON_GetStringValue(subscription_name), "wazuh-subscription-test");
    cJSON *credentials_file = cJSON_GetObjectItem(gcp_pubsub, "credentials_file");
    assert_string_equal(cJSON_GetStringValue(credentials_file), "/wazuh/credentials/test.json");
    cJSON *logging = cJSON_GetObjectItem(gcp_pubsub, "logging");
    assert_string_equal(cJSON_GetStringValue(logging), "debug");
}


static void test_wm_gcp_dump_success_logging_info(void **state) {
    gcp_dump_t *gcp_dump_data = *state;

    gcp_dump_data->config->enabled = 1;
    gcp_dump_data->config->pull_on_start = 0;
    gcp_dump_data->config->logging = 2;    // info
    gcp_dump_data->config->max_messages = 100;

    snprintf(gcp_dump_data->config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_dump_data->config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_dump_data->config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    will_return(__wrap_cJSON_CreateObject, gcp_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_dump_data->wm_wd);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_dump_data->wm_wd);

    gcp_dump_data->dump = wm_gcp_dump(gcp_dump_data->config);

    assert_non_null(gcp_dump_data->dump);
    assert_ptr_equal(gcp_dump_data->dump, gcp_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_dump_data->dump), 1);

    cJSON *gcp_pubsub = cJSON_GetObjectItem(gcp_dump_data->dump, "gcp-pubsub");
    assert_non_null(gcp_pubsub);
    assert_int_equal(cJSON_GetArraySize(gcp_pubsub), 7);

    cJSON *enabled = cJSON_GetObjectItem(gcp_pubsub, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "yes");
    cJSON *pull_on_start = cJSON_GetObjectItem(gcp_pubsub, "pull_on_start");
    assert_string_equal(cJSON_GetStringValue(pull_on_start), "no");
    cJSON *max_messages = cJSON_GetObjectItem(gcp_pubsub, "max_messages");
    assert_non_null(max_messages);
    assert_int_equal(max_messages->valueint, 100);
    cJSON *project_id = cJSON_GetObjectItem(gcp_pubsub, "project_id");
    assert_string_equal(cJSON_GetStringValue(project_id), "wazuh-gcp-test");
    cJSON *subscription_name = cJSON_GetObjectItem(gcp_pubsub, "subscription_name");
    assert_string_equal(cJSON_GetStringValue(subscription_name), "wazuh-subscription-test");
    cJSON *credentials_file = cJSON_GetObjectItem(gcp_pubsub, "credentials_file");
    assert_string_equal(cJSON_GetStringValue(credentials_file), "/wazuh/credentials/test.json");
    cJSON *logging = cJSON_GetObjectItem(gcp_pubsub, "logging");
    assert_string_equal(cJSON_GetStringValue(logging), "info");
}

static void test_wm_gcp_dump_success_logging_warning(void **state) {
    gcp_dump_t *gcp_dump_data = *state;

    gcp_dump_data->config->enabled = 0;
    gcp_dump_data->config->pull_on_start = 1;
    gcp_dump_data->config->logging = 3;    // warning
    gcp_dump_data->config->max_messages = 100;

    snprintf(gcp_dump_data->config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_dump_data->config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_dump_data->config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    will_return(__wrap_cJSON_CreateObject, gcp_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_dump_data->wm_wd);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_dump_data->wm_wd);

    gcp_dump_data->dump = wm_gcp_dump(gcp_dump_data->config);

    assert_non_null(gcp_dump_data->dump);
    assert_ptr_equal(gcp_dump_data->dump, gcp_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_dump_data->dump), 1);

    cJSON *gcp_pubsub = cJSON_GetObjectItem(gcp_dump_data->dump, "gcp-pubsub");
    assert_non_null(gcp_pubsub);
    assert_int_equal(cJSON_GetArraySize(gcp_pubsub), 7);

    cJSON *enabled = cJSON_GetObjectItem(gcp_pubsub, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "no");
    cJSON *pull_on_start = cJSON_GetObjectItem(gcp_pubsub, "pull_on_start");
    assert_string_equal(cJSON_GetStringValue(pull_on_start), "yes");
    cJSON *max_messages = cJSON_GetObjectItem(gcp_pubsub, "max_messages");
    assert_non_null(max_messages);
    assert_int_equal(max_messages->valueint, 100);
    cJSON *project_id = cJSON_GetObjectItem(gcp_pubsub, "project_id");
    assert_string_equal(cJSON_GetStringValue(project_id), "wazuh-gcp-test");
    cJSON *subscription_name = cJSON_GetObjectItem(gcp_pubsub, "subscription_name");
    assert_string_equal(cJSON_GetStringValue(subscription_name), "wazuh-subscription-test");
    cJSON *credentials_file = cJSON_GetObjectItem(gcp_pubsub, "credentials_file");
    assert_string_equal(cJSON_GetStringValue(credentials_file), "/wazuh/credentials/test.json");
    cJSON *logging = cJSON_GetObjectItem(gcp_pubsub, "logging");
    assert_string_equal(cJSON_GetStringValue(logging), "warning");
}

static void test_wm_gcp_dump_success_logging_error(void **state) {
    gcp_dump_t *gcp_dump_data = *state;

    gcp_dump_data->config->enabled = 0;
    gcp_dump_data->config->pull_on_start = 0;
    gcp_dump_data->config->logging = 4;    // error
    gcp_dump_data->config->max_messages = 100;

    snprintf(gcp_dump_data->config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_dump_data->config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_dump_data->config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    will_return(__wrap_cJSON_CreateObject, gcp_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_dump_data->wm_wd);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_dump_data->wm_wd);

    gcp_dump_data->dump = wm_gcp_dump(gcp_dump_data->config);

    assert_non_null(gcp_dump_data->dump);
    assert_ptr_equal(gcp_dump_data->dump, gcp_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_dump_data->dump), 1);

    cJSON *gcp_pubsub = cJSON_GetObjectItem(gcp_dump_data->dump, "gcp-pubsub");
    assert_non_null(gcp_pubsub);
    assert_int_equal(cJSON_GetArraySize(gcp_pubsub), 7);

    cJSON *enabled = cJSON_GetObjectItem(gcp_pubsub, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "no");
    cJSON *pull_on_start = cJSON_GetObjectItem(gcp_pubsub, "pull_on_start");
    assert_string_equal(cJSON_GetStringValue(pull_on_start), "no");
    cJSON *max_messages = cJSON_GetObjectItem(gcp_pubsub, "max_messages");
    assert_non_null(max_messages);
    assert_int_equal(max_messages->valueint, 100);
    cJSON *project_id = cJSON_GetObjectItem(gcp_pubsub, "project_id");
    assert_string_equal(cJSON_GetStringValue(project_id), "wazuh-gcp-test");
    cJSON *subscription_name = cJSON_GetObjectItem(gcp_pubsub, "subscription_name");
    assert_string_equal(cJSON_GetStringValue(subscription_name), "wazuh-subscription-test");
    cJSON *credentials_file = cJSON_GetObjectItem(gcp_pubsub, "credentials_file");
    assert_string_equal(cJSON_GetStringValue(credentials_file), "/wazuh/credentials/test.json");
    cJSON *logging = cJSON_GetObjectItem(gcp_pubsub, "logging");
    assert_string_equal(cJSON_GetStringValue(logging), "error");
}

static void test_wm_gcp_dump_success_logging_critical(void **state) {
    gcp_dump_t *gcp_dump_data = *state;

    gcp_dump_data->config->enabled = 0;
    gcp_dump_data->config->pull_on_start = 0;
    gcp_dump_data->config->logging = 5;    // critical
    gcp_dump_data->config->max_messages = 100;

    snprintf(gcp_dump_data->config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_dump_data->config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_dump_data->config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    will_return(__wrap_cJSON_CreateObject, gcp_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_dump_data->wm_wd);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_dump_data->wm_wd);

    gcp_dump_data->dump = wm_gcp_dump(gcp_dump_data->config);

    assert_non_null(gcp_dump_data->dump);
    assert_ptr_equal(gcp_dump_data->dump, gcp_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_dump_data->dump), 1);

    cJSON *gcp_pubsub = cJSON_GetObjectItem(gcp_dump_data->dump, "gcp-pubsub");
    assert_non_null(gcp_pubsub);
    assert_int_equal(cJSON_GetArraySize(gcp_pubsub), 7);

    cJSON *enabled = cJSON_GetObjectItem(gcp_pubsub, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "no");
    cJSON *pull_on_start = cJSON_GetObjectItem(gcp_pubsub, "pull_on_start");
    assert_string_equal(cJSON_GetStringValue(pull_on_start), "no");
    cJSON *max_messages = cJSON_GetObjectItem(gcp_pubsub, "max_messages");
    assert_non_null(max_messages);
    assert_int_equal(max_messages->valueint, 100);
    cJSON *project_id = cJSON_GetObjectItem(gcp_pubsub, "project_id");
    assert_string_equal(cJSON_GetStringValue(project_id), "wazuh-gcp-test");
    cJSON *subscription_name = cJSON_GetObjectItem(gcp_pubsub, "subscription_name");
    assert_string_equal(cJSON_GetStringValue(subscription_name), "wazuh-subscription-test");
    cJSON *credentials_file = cJSON_GetObjectItem(gcp_pubsub, "credentials_file");
    assert_string_equal(cJSON_GetStringValue(credentials_file), "/wazuh/credentials/test.json");
    cJSON *logging = cJSON_GetObjectItem(gcp_pubsub, "logging");
    assert_string_equal(cJSON_GetStringValue(logging), "critical");
}

static void test_wm_gcp_dump_success_logging_default(void **state) {
    gcp_dump_t *gcp_dump_data = *state;

    gcp_dump_data->config->enabled = 0;
    gcp_dump_data->config->pull_on_start = 0;
    gcp_dump_data->config->logging = 256;    // default
    gcp_dump_data->config->max_messages = 100;

    snprintf(gcp_dump_data->config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_dump_data->config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_dump_data->config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    will_return(__wrap_cJSON_CreateObject, gcp_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_dump_data->wm_wd);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_dump_data->wm_wd);

    gcp_dump_data->dump = wm_gcp_dump(gcp_dump_data->config);

    assert_non_null(gcp_dump_data->dump);
    assert_ptr_equal(gcp_dump_data->dump, gcp_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_dump_data->dump), 1);

    cJSON *gcp_pubsub = cJSON_GetObjectItem(gcp_dump_data->dump, "gcp-pubsub");
    assert_non_null(gcp_pubsub);
    assert_int_equal(cJSON_GetArraySize(gcp_pubsub), 7);

    cJSON *enabled = cJSON_GetObjectItem(gcp_pubsub, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "no");
    cJSON *pull_on_start = cJSON_GetObjectItem(gcp_pubsub, "pull_on_start");
    assert_string_equal(cJSON_GetStringValue(pull_on_start), "no");
    cJSON *max_messages = cJSON_GetObjectItem(gcp_pubsub, "max_messages");
    assert_non_null(max_messages);
    assert_int_equal(max_messages->valueint, 100);
    cJSON *project_id = cJSON_GetObjectItem(gcp_pubsub, "project_id");
    assert_string_equal(cJSON_GetStringValue(project_id), "wazuh-gcp-test");
    cJSON *subscription_name = cJSON_GetObjectItem(gcp_pubsub, "subscription_name");
    assert_string_equal(cJSON_GetStringValue(subscription_name), "wazuh-subscription-test");
    cJSON *credentials_file = cJSON_GetObjectItem(gcp_pubsub, "credentials_file");
    assert_string_equal(cJSON_GetStringValue(credentials_file), "/wazuh/credentials/test.json");
    cJSON *logging = cJSON_GetObjectItem(gcp_pubsub, "logging");
    assert_string_equal(cJSON_GetStringValue(logging), "info");
}

static void test_wm_gcp_dump_error_allocating_wm_wd(void **state) {
    gcp_dump_t *gcp_dump_data = *state;

    gcp_dump_data->config->enabled = 0;
    gcp_dump_data->config->pull_on_start = 0;
    gcp_dump_data->config->logging = 256;    // default
    gcp_dump_data->config->max_messages = 100;

    snprintf(gcp_dump_data->config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_dump_data->config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_dump_data->config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    // Since we won't use wm_wd, we can just free it to prevent memory leaks.
    free(gcp_dump_data->wm_wd);
    gcp_dump_data->wm_wd = NULL;

    will_return(__wrap_cJSON_CreateObject, gcp_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, NULL);

    gcp_dump_data->dump = wm_gcp_dump(gcp_dump_data->config);

    assert_non_null(gcp_dump_data->dump);
    assert_ptr_equal(gcp_dump_data->dump, gcp_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_dump_data->dump), 0);
}

static void test_wm_gcp_dump_error_allocating_root(void **state) {
    gcp_dump_t *gcp_dump_data = *state;

    gcp_dump_data->config->enabled = 0;
    gcp_dump_data->config->pull_on_start = 0;
    gcp_dump_data->config->logging = 256;    // default
    gcp_dump_data->config->max_messages = 100;

    snprintf(gcp_dump_data->config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_dump_data->config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_dump_data->config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    // Since we won't use wm_wd or root, we can just free them to prevent memory leaks.
    free(gcp_dump_data->wm_wd);
    gcp_dump_data->wm_wd = NULL;

    free(gcp_dump_data->root);
    gcp_dump_data->root = NULL;

    will_return(__wrap_cJSON_CreateObject, NULL);
    will_return(__wrap_cJSON_CreateObject, NULL);   // If we cannot alloc root, wm_wd won't be alloced either.

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, NULL);

    gcp_dump_data->dump = wm_gcp_dump(gcp_dump_data->config);

    assert_null(gcp_dump_data->dump);
}

/* wm_gcp_destroy */
static void test_wm_gcp_destroy(void **state) {
    wm_gcp **gcp_config = *state;

    // gcp_config[0] is to be destroyed by the test
    wm_gcp_destroy(gcp_config[0]);

    // No assertions are possible on this test, it's meant to be used along valgrind to check memory leaks.
}

/* wm_gcp_main */
static void test_wm_gcp_main_disabled(void **state) {
    wm_gcp *gcp_config = *state;

    gcp_config->enabled = 0;

    expect_string(__wrap__mtinfo, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Module disabled. Exiting.");

    wm_gcp_main(gcp_config);
}

static void test_wm_gcp_main_pull_on_start(void **state) {
    wm_gcp *gcp_config = *state;
    void *ret;

    gcp_config->enabled = 1;
    gcp_config->pull_on_start = 1;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->logging = 0;    // disabled

    expect_string(__wrap__mtinfo, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Module started.");

    expect_value(__wrap_sched_scan_get_time_until_next_scan, config, &gcp_config->scan_config);
    expect_string(__wrap_sched_scan_get_time_until_next_scan, MODULE_TAG, WM_GCP_LOGTAG);
    expect_value(__wrap_sched_scan_get_time_until_next_scan, run_on_start, 1);
    will_return(__wrap_sched_scan_get_time_until_next_scan, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Starting fetching of logs.");

    expect_string(__wrap__mtdebug2, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");

    expect_string(__wrap_wm_exec, command,
        "/var/ossec/wodles/gcloud/gcloud --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, strdup("Test output"));
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtinfo, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Logging disabled.");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Fetching logs finished.");

    will_return(__wrap_FOREVER, 0);

    ret = wm_gcp_main(gcp_config);

    assert_null(ret);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        /* wm_gcp_run */
        cmocka_unit_test(test_wm_gcp_run_success_log_disabled),
        cmocka_unit_test(test_wm_gcp_run_error_running_command),
        cmocka_unit_test(test_wm_gcp_run_unknown_error),
        cmocka_unit_test(test_wm_gcp_run_unknown_error_no_description),
        cmocka_unit_test(test_wm_gcp_run_error_parsing_args),
        cmocka_unit_test(test_wm_gcp_run_error_parsing_args_no_description),
        cmocka_unit_test(test_wm_gcp_run_generic_error),
        cmocka_unit_test(test_wm_gcp_run_generic_error_no_description),
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

        /* wm_gcp_dump */
        cmocka_unit_test_setup_teardown(test_wm_gcp_dump_success_logging_disabled, setup_gcp_dump, teardown_gcp_dump),
        cmocka_unit_test_setup_teardown(test_wm_gcp_dump_success_logging_debug, setup_gcp_dump, teardown_gcp_dump),
        cmocka_unit_test_setup_teardown(test_wm_gcp_dump_success_logging_info, setup_gcp_dump, teardown_gcp_dump),
        cmocka_unit_test_setup_teardown(test_wm_gcp_dump_success_logging_warning, setup_gcp_dump, teardown_gcp_dump),
        cmocka_unit_test_setup_teardown(test_wm_gcp_dump_success_logging_error, setup_gcp_dump, teardown_gcp_dump),
        cmocka_unit_test_setup_teardown(test_wm_gcp_dump_success_logging_critical, setup_gcp_dump, teardown_gcp_dump),
        cmocka_unit_test_setup_teardown(test_wm_gcp_dump_success_logging_default, setup_gcp_dump, teardown_gcp_dump),
        cmocka_unit_test_setup_teardown(test_wm_gcp_dump_error_allocating_wm_wd, setup_gcp_dump, teardown_gcp_dump),
        cmocka_unit_test_setup_teardown(test_wm_gcp_dump_error_allocating_root, setup_gcp_dump, teardown_gcp_dump),

        /* wm_gcp_destroy */
        cmocka_unit_test_setup_teardown(test_wm_gcp_destroy, setup_gcp_destroy, teardown_gcp_destroy),

        /* wm_gcp_main */
        cmocka_unit_test(test_wm_gcp_main_disabled),
        cmocka_unit_test(test_wm_gcp_main_pull_on_start),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
