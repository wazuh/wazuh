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

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/wm_gcp.h"
#include "../../headers/defs.h"
#include "../../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/schedule_scan_wrappers.h"
#include "../../wrappers/wazuh/shared/time_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_exec_wrappers.h"

void wm_gcp_pubsub_run(const wm_gcp_pubsub *data);
cJSON *wm_gcp_pubsub_dump(const wm_gcp_pubsub *data);
void wm_gcp_pubsub_destroy(wm_gcp_pubsub * data);
void* wm_gcp_pubsub_main(wm_gcp_pubsub *data);

void wm_gcp_bucket_run(wm_gcp_bucket *exec_bucket);
cJSON *wm_gcp_bucket_dump(const wm_gcp_bucket_base *data);
void wm_gcp_bucket_destroy(wm_gcp_bucket_base *data);
void* wm_gcp_bucket_main(wm_gcp_bucket_base *data);

/* Generic setup/teardown */
static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

/* Auxiliar structs for pubsub*/
typedef struct __gcp_pubsub_dump_s {
    wm_gcp_pubsub *config;
    cJSON *dump;
    cJSON *root;
    cJSON *wm_wd;
}gcp_pubsub_dump_t;

/* wraps */
int __wrap_isDebug() {
    return mock();
}

/* setup/teardown for pubsub*/
static int setup_group_pubsub(void **state) {
    wm_gcp_pubsub *gcp_config;
    os_calloc(1, sizeof(wm_gcp_pubsub), gcp_config);

    if(gcp_config == NULL)
        return -1;

    os_calloc(OS_SIZE_1024, sizeof(char), gcp_config->project_id);
    if(gcp_config->project_id == NULL)
        return -1;

    os_calloc(OS_SIZE_1024, sizeof(char), gcp_config->subscription_name);
    if(gcp_config->subscription_name == NULL)
        return -1;
    os_calloc(OS_SIZE_1024, sizeof(char), gcp_config->credentials_file);
    if(gcp_config->credentials_file == NULL)
        return -1;

    *state = gcp_config;

    return 0;
}

static int teardown_group_pubsub(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    if (gcp_config->project_id) os_free(gcp_config->project_id);
    if (gcp_config->subscription_name) os_free(gcp_config->subscription_name);
    if (gcp_config->credentials_file) os_free(gcp_config->credentials_file);

    os_free(gcp_config);

    return 0;
}

static int setup_gcp_pubsub_dump(void **state) {
    setup_group_pubsub(state);

    gcp_pubsub_dump_t *dump_data = calloc(1, sizeof(gcp_pubsub_dump_t));

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

static int teardown_gcp_pubsub_dump(void **state) {
    gcp_pubsub_dump_t *dump_data = *state;

    // Make sure to keep the group information.
    *state = dump_data->config;

    teardown_group_pubsub(state);

    // Free/delete everything else
    cJSON_Delete(dump_data->dump);
    os_free(dump_data);

    return 0;
}

static int setup_gcp_pubsub_destroy(void **state) {
    setup_group_pubsub(state);

    wm_gcp_pubsub **gcp_config;

    if(gcp_config = calloc(2, sizeof(wm_gcp_pubsub*)), gcp_config == NULL)
        return -1;

    // Save the globally used gcp_config
    gcp_config[1] = *state;

    // And create a new one to be destroyed by tests
    if(gcp_config[0] = calloc(1, sizeof(wm_gcp_pubsub)), gcp_config[0] == NULL)
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

static int teardown_gcp_pubsub_destroy(void **state) {
    wm_gcp_pubsub **gcp_config;

    gcp_config = *state;

    // gcp_config[0] was destroyed by the test, restore the original into state
    *state = gcp_config[1];

    teardown_group_pubsub(state);

    os_free(gcp_config);

    return 0;
}

/* Auxiliar structs for buckets*/
typedef struct __gcp_bucket_dump_s {
    wm_gcp_bucket_base *config;
    cJSON *dump;
    cJSON *root;
    cJSON *wm_wd;
    cJSON *cur_bucket;
}gcp_bucket_dump_t;

/* setup/teardown for buckets*/
static int setup_group_bucket(void **state) {
    wm_gcp_bucket_base *gcp_config;
    wm_gcp_bucket *gcp_bucket;

    os_calloc(OS_SIZE_1024, sizeof(wm_gcp_bucket_base), gcp_config);
    os_calloc(OS_SIZE_1024, sizeof(wm_gcp_bucket), gcp_bucket);

    if(gcp_config == NULL)
        return -1;

    if(gcp_bucket == NULL)
        return -1;

    os_calloc(OS_SIZE_1024, sizeof(char), gcp_bucket->bucket);
    if(gcp_bucket->bucket == NULL)
        return -1;

    os_calloc(OS_SIZE_1024, sizeof(char), gcp_bucket->type);
    if(gcp_bucket->type == NULL)
        return -1;

    os_calloc(OS_SIZE_1024, sizeof(char), gcp_bucket->credentials_file);
    if(gcp_bucket->credentials_file == NULL)
        return -1;

    os_calloc(OS_SIZE_1024, sizeof(char), gcp_bucket->prefix);
    if(gcp_bucket->prefix == NULL)
        return -1;

    os_calloc(OS_SIZE_1024, sizeof(char), gcp_bucket->only_logs_after);
    if(gcp_bucket->only_logs_after == NULL)
        return -1;

    gcp_bucket->remove_from_bucket = 1;

    gcp_config->buckets = gcp_bucket;
    *state = gcp_config;

    return 0;
}

static int teardown_group_bucket(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *gcp_bucket = gcp_config->buckets;

    if (gcp_bucket->bucket) os_free(gcp_bucket->bucket);
    if (gcp_bucket->type) os_free(gcp_bucket->type);
    if (gcp_bucket->credentials_file) os_free(gcp_bucket->credentials_file);
    if (gcp_bucket->prefix) os_free(gcp_bucket->prefix);
    if (gcp_bucket->only_logs_after) os_free(gcp_bucket->only_logs_after);

    os_free(gcp_bucket);
    os_free(gcp_config);

    return 0;
}

static int setup_gcp_bucket_dump(void **state) {
    setup_group_bucket(state);

    gcp_bucket_dump_t *dump_data;
    os_calloc(1, sizeof(gcp_bucket_dump_t), dump_data);

    if(dump_data == NULL)
        return -1;

    if(dump_data->root = __real_cJSON_CreateObject(), dump_data->root == NULL)
        return -1;

    if(dump_data->wm_wd = __real_cJSON_CreateObject(), dump_data->wm_wd == NULL)
        return -1;

    if(dump_data->cur_bucket = __real_cJSON_CreateObject(), dump_data->cur_bucket == NULL)
        return -1;

    // Move some pointers around in order to add some info for these tests
    dump_data->config = *state;
    *state = dump_data;

    return 0;
}

static int teardown_gcp_bucket_dump(void **state) {
    gcp_bucket_dump_t *dump_data = *state;

    // Make sure to keep the group information.
    *state = dump_data->config;

    // Free/delete everything else
    cJSON_Delete(dump_data->dump);

    teardown_group_bucket(state);
    os_free(dump_data);

    return 0;
}

static int setup_gcp_bucket_destroy(void **state) {
    setup_group_bucket(state);
    wm_gcp_bucket_base **gcp_config;
    wm_gcp_bucket *gcp_bucket;

    os_calloc(OS_SIZE_1024, sizeof(wm_gcp_bucket_base*), gcp_config);
    os_calloc(OS_SIZE_1024, sizeof(wm_gcp_bucket), gcp_bucket);

    if(gcp_config == NULL)
        return -1;

    if(gcp_bucket == NULL)
        return -1;

    // Save the globally used gcp_config
    gcp_config[1] = *state;

    // And create a new one to be destroyed by tests
    os_calloc(1, sizeof(wm_gcp_bucket_base), gcp_config[0]);
    if(gcp_config[0] == NULL)
        return -1;

    os_calloc(OS_SIZE_1024, sizeof(char), gcp_bucket->bucket);
    if(gcp_bucket->bucket == NULL)
        return -1;

    os_calloc(OS_SIZE_1024, sizeof(char), gcp_bucket->type);
    if(gcp_bucket->type == NULL)
        return -1;

    os_calloc(OS_SIZE_1024, sizeof(char), gcp_bucket->credentials_file);
    if(gcp_bucket->credentials_file == NULL)
        return -1;

    os_calloc(OS_SIZE_1024, sizeof(char), gcp_bucket->prefix);
    if(gcp_bucket->prefix == NULL)
        return -1;

    os_calloc(OS_SIZE_1024, sizeof(char), gcp_bucket->only_logs_after);
    if(gcp_bucket->only_logs_after == NULL)
        return -1;

    gcp_bucket->remove_from_bucket = 1;

    gcp_config[0]->buckets = gcp_bucket;
    *state = gcp_config;

    return 0;
}

static int teardown_gcp_bucket_destroy(void **state) {
    wm_gcp_bucket_base **gcp_config;

    gcp_config = *state;

    // gcp_config[0] was destroyed by the test, restore the original into state
    *state = gcp_config[1];

    teardown_group_bucket(state);

    os_free(gcp_config);

    return 0;
}


/* tests */
/* wm_gcp_pubsub_run */
static void test_wm_gcp_pubsub_run_error_running_command(void **state)  {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    will_return(__wrap_isDebug, 1);
    will_return(__wrap_isDebug, 1);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Test output");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 1);

    expect_string(__wrap__mterror, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "Internal error. Exiting...");

    wm_gcp_pubsub_run(gcp_config);
}

static void test_wm_gcp_pubsub_run_unknown_error(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    will_return(__wrap_isDebug, 1);
    will_return(__wrap_isDebug, 1);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Unknown error - This is an unknown error.");
    will_return(__wrap_wm_exec, 1);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 1");

    will_return(__wrap_isDebug, 1);

    wm_gcp_pubsub_run(gcp_config);
}

static void test_wm_gcp_pubsub_run_unknown_error_no_description(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    will_return(__wrap_isDebug, 1);
    will_return(__wrap_isDebug, 1);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Unknown error - This is an unknown error.");
    will_return(__wrap_wm_exec, 1);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 1");

    will_return(__wrap_isDebug, 1);
    wm_gcp_pubsub_run(gcp_config);
}

static void test_wm_gcp_pubsub_run_error_parsing_args(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    will_return(__wrap_isDebug, 1);
    will_return(__wrap_isDebug, 1);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Error!! integration.py: error: unable to parse");
    will_return(__wrap_wm_exec, 2);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 2");

    will_return(__wrap_isDebug, 1);
    wm_gcp_pubsub_run(gcp_config);
}

static void test_wm_gcp_pubsub_run_error_parsing_args_no_description(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    will_return(__wrap_isDebug, 1);
    will_return(__wrap_isDebug, 1);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Error!! But won't trigger a specific message");
    will_return(__wrap_wm_exec, 2);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 2");

    will_return(__wrap_isDebug, 1);

    wm_gcp_pubsub_run(gcp_config);
}

static void test_wm_gcp_pubsub_run_generic_error(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "ERROR: A specific error message.");
    will_return(__wrap_wm_exec, 3);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 3");

    will_return(__wrap_isDebug, 0);

    wm_gcp_pubsub_run(gcp_config);
}

static void test_wm_gcp_pubsub_run_generic_error_no_description(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "A specific error message.");
    will_return(__wrap_wm_exec, 3);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 3");

    wm_gcp_pubsub_run(gcp_config);
}

static void test_wm_gcp_pubsub_run_logging_warning_message_warning(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - WARNING - This is a warning message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "This is a warning message");

    wm_gcp_pubsub_run(gcp_config);
}

static void test_wm_gcp_pubsub_run_logging_debug_message_not_debug_discarded(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 2);
    will_return(__wrap_isDebug, 2);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 2");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Test output - This is a message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 2);

    wm_gcp_pubsub_run(gcp_config);
}


static void test_wm_gcp_pubsub_run_logging_debug_message_not_debug(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 2);
    will_return(__wrap_isDebug, 2);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 2");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - INFO - This is an info message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 2);

    expect_string(__wrap__mtinfo, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "This is an info message");

    wm_gcp_pubsub_run(gcp_config);
}

static void test_wm_gcp_pubsub_run_logging_info_message_info(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 1);
    will_return(__wrap_isDebug, 1);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - INFO - This is an info message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 1);

    expect_string(__wrap__mtinfo, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "This is an info message");

    wm_gcp_pubsub_run(gcp_config);
}

static void test_wm_gcp_pubsub_run_logging_info_message_debug(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 1);
    will_return(__wrap_isDebug, 1);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - DEBUG - This is an info message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 1);

    wm_gcp_pubsub_run(gcp_config);
}

static void test_wm_gcp_pubsub_run_logging_info_message_warning(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 1);
    will_return(__wrap_isDebug, 1);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - WARNING - This is a warning message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 1);

    expect_string(__wrap__mtwarn, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "This is a warning message");
    wm_gcp_pubsub_run(gcp_config);
}

static void test_wm_gcp_pubsub_run_logging_warning_message_error(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - ERROR - This is an error message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mterror, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "This is an error message");
    wm_gcp_pubsub_run(gcp_config);
}

static void test_wm_gcp_pubsub_run_logging_warning_multiline_message_error(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - ERROR - This is a \nmultiline\nerror message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mterror, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "This is a \nmultiline\nerror message");
    wm_gcp_pubsub_run(gcp_config);
}

static void test_wm_gcp_pubsub_run_logging_warning_multimessage_message_error(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - ERROR - This is a \nmultiline\nerror message\n"
		":gcloud_wodle:Test output - ERROR - This is the second message\n"
		":gcloud_wodle:Test output - CRITICAL - This is a critical message\n");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mterror, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "This is a \nmultiline\nerror message");
    expect_string(__wrap__mterror, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "This is the second message");
    expect_string(__wrap__mterror, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "This is a critical message");
    wm_gcp_pubsub_run(gcp_config);
}

static void test_wm_gcp_pubsub_run_logging_default_message_debug(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 6");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 6");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Test output - DEBUG - This is an info message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    wm_gcp_pubsub_run(gcp_config);
}

/* wm_gcp_pubsub_dump */
static void test_wm_gcp_pubsub_dump_success_logging_debug(void **state) {
    gcp_pubsub_dump_t *gcp_pubsub_dump_data = *state;

    gcp_pubsub_dump_data->config->enabled = 0;
    gcp_pubsub_dump_data->config->pull_on_start = 0;
    gcp_pubsub_dump_data->config->max_messages = 100;
    gcp_pubsub_dump_data->config->num_threads = 2;

    snprintf(gcp_pubsub_dump_data->config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_pubsub_dump_data->config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_pubsub_dump_data->config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    will_return(__wrap_cJSON_CreateObject, gcp_pubsub_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_pubsub_dump_data->wm_wd);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_pubsub_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_pubsub_dump_data->wm_wd);
    will_return(__wrap_isDebug, 2);

    gcp_pubsub_dump_data->dump = wm_gcp_pubsub_dump(gcp_pubsub_dump_data->config);

    assert_non_null(gcp_pubsub_dump_data->dump);
    assert_ptr_equal(gcp_pubsub_dump_data->dump, gcp_pubsub_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_pubsub_dump_data->dump), 1);

    cJSON *gcp_pubsub = cJSON_GetObjectItem(gcp_pubsub_dump_data->dump, "gcp-pubsub");
    assert_non_null(gcp_pubsub);
    assert_int_equal(cJSON_GetArraySize(gcp_pubsub), 8);

    cJSON *enabled = cJSON_GetObjectItem(gcp_pubsub, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "no");
    cJSON *pull_on_start = cJSON_GetObjectItem(gcp_pubsub, "pull_on_start");
    assert_string_equal(cJSON_GetStringValue(pull_on_start), "no");
    cJSON *max_messages = cJSON_GetObjectItem(gcp_pubsub, "max_messages");
    assert_non_null(max_messages);
    assert_int_equal(max_messages->valueint, 100);
    cJSON *num_threads = cJSON_GetObjectItem(gcp_pubsub, "num_threads");
    assert_non_null(num_threads);
    assert_int_equal(num_threads->valueint, 2);
    cJSON *project_id = cJSON_GetObjectItem(gcp_pubsub, "project_id");
    assert_string_equal(cJSON_GetStringValue(project_id), "wazuh-gcp-test");
    cJSON *subscription_name = cJSON_GetObjectItem(gcp_pubsub, "subscription_name");
    assert_string_equal(cJSON_GetStringValue(subscription_name), "wazuh-subscription-test");
    cJSON *credentials_file = cJSON_GetObjectItem(gcp_pubsub, "credentials_file");
    assert_string_equal(cJSON_GetStringValue(credentials_file), "/wazuh/credentials/test.json");
}


static void test_wm_gcp_pubsub_dump_success_logging_info(void **state) {
    gcp_pubsub_dump_t *gcp_pubsub_dump_data = *state;

    gcp_pubsub_dump_data->config->enabled = 1;
    gcp_pubsub_dump_data->config->pull_on_start = 0;
    gcp_pubsub_dump_data->config->max_messages = 100;
    gcp_pubsub_dump_data->config->num_threads = 2;

    snprintf(gcp_pubsub_dump_data->config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_pubsub_dump_data->config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_pubsub_dump_data->config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    will_return(__wrap_cJSON_CreateObject, gcp_pubsub_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_pubsub_dump_data->wm_wd);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_pubsub_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_pubsub_dump_data->wm_wd);
    will_return(__wrap_isDebug, 1);

    gcp_pubsub_dump_data->dump = wm_gcp_pubsub_dump(gcp_pubsub_dump_data->config);

    assert_non_null(gcp_pubsub_dump_data->dump);
    assert_ptr_equal(gcp_pubsub_dump_data->dump, gcp_pubsub_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_pubsub_dump_data->dump), 1);

    cJSON *gcp_pubsub = cJSON_GetObjectItem(gcp_pubsub_dump_data->dump, "gcp-pubsub");
    assert_non_null(gcp_pubsub);
    assert_int_equal(cJSON_GetArraySize(gcp_pubsub), 8);

    cJSON *enabled = cJSON_GetObjectItem(gcp_pubsub, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "yes");
    cJSON *pull_on_start = cJSON_GetObjectItem(gcp_pubsub, "pull_on_start");
    assert_string_equal(cJSON_GetStringValue(pull_on_start), "no");
    cJSON *max_messages = cJSON_GetObjectItem(gcp_pubsub, "max_messages");
    assert_non_null(max_messages);
    assert_int_equal(max_messages->valueint, 100);
    cJSON *num_threads = cJSON_GetObjectItem(gcp_pubsub, "num_threads");
    assert_non_null(num_threads);
    assert_int_equal(num_threads->valueint, 2);
    cJSON *project_id = cJSON_GetObjectItem(gcp_pubsub, "project_id");
    assert_string_equal(cJSON_GetStringValue(project_id), "wazuh-gcp-test");
    cJSON *subscription_name = cJSON_GetObjectItem(gcp_pubsub, "subscription_name");
    assert_string_equal(cJSON_GetStringValue(subscription_name), "wazuh-subscription-test");
    cJSON *credentials_file = cJSON_GetObjectItem(gcp_pubsub, "credentials_file");
    assert_string_equal(cJSON_GetStringValue(credentials_file), "/wazuh/credentials/test.json");
}

static void test_wm_gcp_pubsub_dump_success_logging_warning(void **state) {
    gcp_pubsub_dump_t *gcp_pubsub_dump_data = *state;

    gcp_pubsub_dump_data->config->enabled = 0;
    gcp_pubsub_dump_data->config->pull_on_start = 1;
    gcp_pubsub_dump_data->config->max_messages = 100;
    gcp_pubsub_dump_data->config->num_threads = 2;

    snprintf(gcp_pubsub_dump_data->config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_pubsub_dump_data->config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_pubsub_dump_data->config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    will_return(__wrap_cJSON_CreateObject, gcp_pubsub_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_pubsub_dump_data->wm_wd);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_pubsub_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_pubsub_dump_data->wm_wd);
    will_return(__wrap_isDebug, 0);

    gcp_pubsub_dump_data->dump = wm_gcp_pubsub_dump(gcp_pubsub_dump_data->config);

    assert_non_null(gcp_pubsub_dump_data->dump);
    assert_ptr_equal(gcp_pubsub_dump_data->dump, gcp_pubsub_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_pubsub_dump_data->dump), 1);

    cJSON *gcp_pubsub = cJSON_GetObjectItem(gcp_pubsub_dump_data->dump, "gcp-pubsub");
    assert_non_null(gcp_pubsub);
    assert_int_equal(cJSON_GetArraySize(gcp_pubsub), 8);

    cJSON *enabled = cJSON_GetObjectItem(gcp_pubsub, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "no");
    cJSON *pull_on_start = cJSON_GetObjectItem(gcp_pubsub, "pull_on_start");
    assert_string_equal(cJSON_GetStringValue(pull_on_start), "yes");
    cJSON *max_messages = cJSON_GetObjectItem(gcp_pubsub, "max_messages");
    assert_non_null(max_messages);
    assert_int_equal(max_messages->valueint, 100);
    cJSON *num_threads = cJSON_GetObjectItem(gcp_pubsub, "num_threads");
    assert_non_null(num_threads);
    assert_int_equal(num_threads->valueint, 2);
    cJSON *project_id = cJSON_GetObjectItem(gcp_pubsub, "project_id");
    assert_string_equal(cJSON_GetStringValue(project_id), "wazuh-gcp-test");
    cJSON *subscription_name = cJSON_GetObjectItem(gcp_pubsub, "subscription_name");
    assert_string_equal(cJSON_GetStringValue(subscription_name), "wazuh-subscription-test");
    cJSON *credentials_file = cJSON_GetObjectItem(gcp_pubsub, "credentials_file");
    assert_string_equal(cJSON_GetStringValue(credentials_file), "/wazuh/credentials/test.json");
}

static void test_wm_gcp_pubsub_dump_error_allocating_wm_wd(void **state) {
    gcp_pubsub_dump_t *gcp_pubsub_dump_data = *state;

    gcp_pubsub_dump_data->config->enabled = 0;
    gcp_pubsub_dump_data->config->pull_on_start = 0;
    gcp_pubsub_dump_data->config->max_messages = 100;
    gcp_pubsub_dump_data->config->num_threads = 2;

    snprintf(gcp_pubsub_dump_data->config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_pubsub_dump_data->config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_pubsub_dump_data->config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    // Since we won't use wm_wd, we can just free it to prevent memory leaks.
    os_free(gcp_pubsub_dump_data->wm_wd);
    gcp_pubsub_dump_data->wm_wd = NULL;

    will_return(__wrap_cJSON_CreateObject, gcp_pubsub_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_pubsub_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, NULL);
    will_return(__wrap_isDebug, 0);

    gcp_pubsub_dump_data->dump = wm_gcp_pubsub_dump(gcp_pubsub_dump_data->config);

    assert_non_null(gcp_pubsub_dump_data->dump);
    assert_ptr_equal(gcp_pubsub_dump_data->dump, gcp_pubsub_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_pubsub_dump_data->dump), 0);
}

static void test_wm_gcp_pubsub_dump_error_allocating_root(void **state) {
    gcp_pubsub_dump_t *gcp_pubsub_dump_data = *state;

    gcp_pubsub_dump_data->config->enabled = 0;
    gcp_pubsub_dump_data->config->pull_on_start = 0;
    gcp_pubsub_dump_data->config->max_messages = 100;

    snprintf(gcp_pubsub_dump_data->config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_pubsub_dump_data->config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_pubsub_dump_data->config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    // Since we won't use wm_wd or root, we can just free them to prevent memory leaks.
    os_free(gcp_pubsub_dump_data->wm_wd);
    gcp_pubsub_dump_data->wm_wd = NULL;

    os_free(gcp_pubsub_dump_data->root);
    gcp_pubsub_dump_data->root = NULL;

    will_return(__wrap_cJSON_CreateObject, NULL);
    will_return(__wrap_cJSON_CreateObject, NULL);   // If we cannot alloc root, wm_wd won't be alloced either.

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_pubsub_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, NULL);
    will_return(__wrap_isDebug, 0);

    gcp_pubsub_dump_data->dump = wm_gcp_pubsub_dump(gcp_pubsub_dump_data->config);

    assert_null(gcp_pubsub_dump_data->dump);
}

/* wm_gcp_pubsub_destroy */
static void test_wm_gcp_pubsub_destroy(void **state) {
    wm_gcp_pubsub **gcp_config = *state;

    // gcp_config[0] is to be destroyed by the test
    wm_gcp_pubsub_destroy(gcp_config[0]);

    // No assertions are possible on this test, it's meant to be used along valgrind to check memory leaks.
}

/* wm_gcp_pubsub_main */
static void test_wm_gcp_pubsub_main_disabled(void **state) {
    wm_gcp_pubsub *gcp_config = *state;

    gcp_config->enabled = 0;

    expect_string(__wrap__mtinfo, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Module disabled. Exiting.");

    wm_gcp_pubsub_main(gcp_config);
}

static void test_wm_gcp_pubsub_main_pull_on_start(void **state) {
    wm_gcp_pubsub *gcp_config = *state;
    void *ret;

    gcp_config->enabled = 1;
    gcp_config->pull_on_start = 1;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    expect_string(__wrap__mtinfo, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Module started.");

    expect_value(__wrap_sched_scan_get_time_until_next_scan, config, &gcp_config->scan_config);
    expect_string(__wrap_sched_scan_get_time_until_next_scan, MODULE_TAG, WM_GCP_PUBSUB_LOGTAG);
    expect_value(__wrap_sched_scan_get_time_until_next_scan, run_on_start, 1);
    will_return(__wrap_sched_scan_get_time_until_next_scan, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Starting fetching of logs.");

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 1);
    will_return(__wrap_isDebug, 1);
    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Test output");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Fetching logs finished.");

    will_return(__wrap_FOREVER, 0);
    will_return(__wrap_isDebug, 1);

    ret = wm_gcp_pubsub_main(gcp_config);

    assert_null(ret);
}

static void test_wm_gcp_pubsub_main_sleep_then_run(void **state) {
    wm_gcp_pubsub *gcp_config = *state;
    void *ret;

    gcp_config->enabled = 1;
    gcp_config->pull_on_start = 1;

    snprintf(gcp_config->project_id, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(gcp_config->subscription_name, OS_SIZE_1024, "wazuh-subscription-test");
    snprintf(gcp_config->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");

    gcp_config->max_messages = 10;
    gcp_config->num_threads = 2;

    int create_time = 123456789;
    gcp_config->scan_config.next_scheduled_scan_time = create_time; // sleep 10 seconds

    char *create_time_timestamp = NULL;
    os_strdup("20/10/21 15:35:48.111", create_time_timestamp);

    expect_string(__wrap__mtinfo, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Module started.");

    expect_value(__wrap_sched_scan_get_time_until_next_scan, config, &gcp_config->scan_config);
    expect_string(__wrap_sched_scan_get_time_until_next_scan, MODULE_TAG, WM_GCP_PUBSUB_LOGTAG);
    expect_value(__wrap_sched_scan_get_time_until_next_scan, run_on_start, 1);
    will_return(__wrap_sched_scan_get_time_until_next_scan, create_time);

    expect_value(__wrap_w_get_timestamp, time, create_time);
    will_return(__wrap_w_get_timestamp, create_time_timestamp);

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Sleeping until: 20/10/21 15:35:48.111");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Starting fetching of logs.");

    expect_string(__wrap__mtdebug2, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    will_return(__wrap_isDebug, 2);
    will_return(__wrap_isDebug, 2);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 2");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type pubsub --project wazuh-gcp-test --subscription_id wazuh-subscription-test "
        "--credentials_file /wazuh/credentials/test.json --max_messages 10 --num_threads 2 --log_level 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Test output");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_PUBSUB_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Fetching logs finished.");

    will_return(__wrap_FOREVER, 0);
    will_return(__wrap_isDebug, 2);

    ret = wm_gcp_pubsub_main(gcp_config);

    assert_null(ret);
}

/* wm_gcp_bucket_run */
static void test_wm_gcp_bucket_run_success(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Test output");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 0);

    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_error_running_command(void **state)  {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Test output");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 1);

    expect_string(__wrap__mterror, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "Internal error. Exiting...");

    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_error(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Unknown error - This is an unknown error.");
    will_return(__wrap_wm_exec, 1);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 1");

    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_error_no_description(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "This description does not match the criteria");
    will_return(__wrap_wm_exec, 1);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 1");

    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_error_parsing_args(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Error!! integration.py: error: unable to parse");
    will_return(__wrap_wm_exec, 2);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 2");

    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_error_parsing_args_no_description(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Error!! But won't trigger a specific message");
    will_return(__wrap_wm_exec, 2);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 2");

    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_generic_error(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 0);
    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "ERROR: A specific error message.");
    will_return(__wrap_wm_exec, 3);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 3");

    will_return(__wrap_isDebug, 0);

    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_generic_error_no_description(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test "
        "--credentials_file /wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "A specific error message.");
    will_return(__wrap_wm_exec, 3);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 3");

    will_return(__wrap_isDebug, 0);

    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_logging_debug_message_debug(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    will_return(__wrap_isDebug, 2);
    will_return(__wrap_isDebug, 2);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 2");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - DEBUG - This is a debug message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 2);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "This is a debug message");

    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_logging_debug_message_not_debug_discarded(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 2);
    will_return(__wrap_isDebug, 2);
    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 2");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - This is a discarded message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 2);

    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_logging_debug_message_not_debug(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 2);
    will_return(__wrap_isDebug, 2);
    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 2");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 2");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - INFO - This is an info message\n");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 2);

    expect_string(__wrap__mtinfo, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "This is an info message");
    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_logging_info_message_info(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 1);
    will_return(__wrap_isDebug, 1);
    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - INFO - This is an info message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 1);

    expect_string(__wrap__mtinfo, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "This is an info message");

    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_logging_info_message_debug(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    will_return(__wrap_isDebug, 1);
    will_return(__wrap_isDebug, 1);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Test output - DEBUG - This is an info message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 1);

    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_logging_info_message_warning(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 1);
    will_return(__wrap_isDebug, 1);
    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - WARNING - This is a warning message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 1);

    expect_string(__wrap__mtwarn, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "This is a warning message");

    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_logging_warning_message_warning(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 0);
    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - WARNING - This is a warning message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtwarn, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "This is a warning message");
    will_return(__wrap_isDebug, 1);
    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_logging_warning_message_debug(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");
    will_return(__wrap_isDebug, 0);
    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Test output - DEBUG - This is a debug message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 0);

    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_logging_warning_message_error(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - ERROR - This is an error message");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mterror, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "This is an error message");
    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_logging_warning_multiline_message_error(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - ERROR - This is a\nmultiline\n error message\n");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 0);

    expect_string(__wrap__mterror, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "This is a\nmultiline\n error message");
    wm_gcp_bucket_run(cur_bucket);
}

static void test_wm_gcp_bucket_run_logging_warning_multimessage_message_error(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    will_return(__wrap_isDebug, 1);
    will_return(__wrap_isDebug, 1);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, ":gcloud_wodle:Test output - ERROR - This is a\nmultimessage\n error message\n"
		":gcloud_wodle:Test critical - CRITICAL - This is another error message\n"
		":gcloud_wodle:Test info - INFO - This is a test info message\n");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 1);

    expect_string(__wrap__mterror, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "This is a\nmultimessage\n error message");
    expect_string(__wrap__mterror, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "This is another error message");
    expect_string(__wrap__mtinfo, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "This is a test info message");
    wm_gcp_bucket_run(cur_bucket);
}

/* wm_gcp_bucket_dump */

static void test_wm_gcp_bucket_dump_success_logging_debug(void **state) {
    gcp_bucket_dump_t *gcp_bucket_dump_data = *state;
    wm_gcp_bucket *cur_bucket = gcp_bucket_dump_data->config->buckets;

    gcp_bucket_dump_data->config->enabled = 0;
    gcp_bucket_dump_data->config->run_on_start = 0;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->wm_wd);
    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->cur_bucket);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_bucket_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_bucket_dump_data->wm_wd);

    gcp_bucket_dump_data->dump = wm_gcp_bucket_dump(gcp_bucket_dump_data->config);

    assert_non_null(gcp_bucket_dump_data->dump);
    assert_ptr_equal(gcp_bucket_dump_data->dump, gcp_bucket_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_bucket_dump_data->dump), 1);
    cJSON *gcp_bucket_base = cJSON_GetObjectItem(gcp_bucket_dump_data->dump, "gcp-bucket");
    assert_non_null(gcp_bucket_base);
    assert_int_equal(cJSON_GetArraySize(gcp_bucket_base), 4);
    cJSON *enabled = cJSON_GetObjectItem(gcp_bucket_base, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "no");
    cJSON *run_on_start = cJSON_GetObjectItem(gcp_bucket_base, "run_on_start");
    assert_string_equal(cJSON_GetStringValue(run_on_start), "no");
    cJSON *gcp_bucket = cJSON_GetObjectItem(gcp_bucket_dump_data->dump->child, "buckets");
    assert_non_null(gcp_bucket);
    cJSON *bucket = cJSON_GetObjectItem(gcp_bucket->child, "bucket");
    assert_string_equal(cJSON_GetStringValue(bucket), "wazuh-gcp-test");
    cJSON *type = cJSON_GetObjectItem(gcp_bucket->child, "type");
    assert_string_equal(cJSON_GetStringValue(type), "access_logs");
    cJSON *credentials_file = cJSON_GetObjectItem(gcp_bucket->child, "credentials_file");
    assert_string_equal(cJSON_GetStringValue(credentials_file), "/wazuh/credentials/test.json");
}


static void test_wm_gcp_bucket_dump_success_logging_info(void **state) {
    gcp_bucket_dump_t *gcp_bucket_dump_data = *state;
    wm_gcp_bucket *cur_bucket = gcp_bucket_dump_data->config->buckets;

    gcp_bucket_dump_data->config->enabled = 1;
    gcp_bucket_dump_data->config->run_on_start = 0;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->wm_wd);
    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->cur_bucket);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_bucket_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_bucket_dump_data->wm_wd);

    gcp_bucket_dump_data->dump = wm_gcp_bucket_dump(gcp_bucket_dump_data->config);

    assert_non_null(gcp_bucket_dump_data->dump);
    assert_ptr_equal(gcp_bucket_dump_data->dump, gcp_bucket_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_bucket_dump_data->dump), 1);

    cJSON *gcp_bucket_base = cJSON_GetObjectItem(gcp_bucket_dump_data->dump, "gcp-bucket");
    assert_non_null(gcp_bucket_base);
    assert_int_equal(cJSON_GetArraySize(gcp_bucket_base), 4);

    cJSON *enabled = cJSON_GetObjectItem(gcp_bucket_base, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "yes");
    cJSON *run_on_start = cJSON_GetObjectItem(gcp_bucket_base, "run_on_start");
    assert_string_equal(cJSON_GetStringValue(run_on_start), "no");

    cJSON *gcp_bucket = cJSON_GetObjectItem(gcp_bucket_dump_data->dump->child, "buckets");
    assert_non_null(gcp_bucket);
    cJSON *bucket = cJSON_GetObjectItem(gcp_bucket->child, "bucket");
    assert_string_equal(cJSON_GetStringValue(bucket), "wazuh-gcp-test");
    cJSON *type = cJSON_GetObjectItem(gcp_bucket->child, "type");
    assert_string_equal(cJSON_GetStringValue(type), "access_logs");
    cJSON *credentials_file = cJSON_GetObjectItem(gcp_bucket->child, "credentials_file");
    assert_string_equal(cJSON_GetStringValue(credentials_file), "/wazuh/credentials/test.json");
}

static void test_wm_gcp_bucket_dump_success(void **state) {
    gcp_bucket_dump_t *gcp_bucket_dump_data = *state;
    wm_gcp_bucket *cur_bucket = gcp_bucket_dump_data->config->buckets;

    gcp_bucket_dump_data->config->enabled = 0;
    gcp_bucket_dump_data->config->run_on_start = 1;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->wm_wd);
    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->cur_bucket);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_bucket_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_bucket_dump_data->wm_wd);

    will_return(__wrap_isDebug, 0);

    gcp_bucket_dump_data->dump = wm_gcp_bucket_dump(gcp_bucket_dump_data->config);

    assert_non_null(gcp_bucket_dump_data->dump);
    assert_ptr_equal(gcp_bucket_dump_data->dump, gcp_bucket_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_bucket_dump_data->dump), 1);

    cJSON *gcp_bucket_base = cJSON_GetObjectItem(gcp_bucket_dump_data->dump, "gcp-bucket");
    assert_non_null(gcp_bucket_base);
    assert_int_equal(cJSON_GetArraySize(gcp_bucket_base), 4);

    cJSON *enabled = cJSON_GetObjectItem(gcp_bucket_base, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "no");
    cJSON *run_on_start = cJSON_GetObjectItem(gcp_bucket_base, "run_on_start");
    assert_string_equal(cJSON_GetStringValue(run_on_start), "yes");
    cJSON *gcp_bucket = cJSON_GetObjectItem(gcp_bucket_dump_data->dump->child, "buckets");
    assert_non_null(gcp_bucket);
    cJSON *bucket = cJSON_GetObjectItem(gcp_bucket->child, "bucket");
    assert_string_equal(cJSON_GetStringValue(bucket), "wazuh-gcp-test");
    cJSON *type = cJSON_GetObjectItem(gcp_bucket->child, "type");
    assert_string_equal(cJSON_GetStringValue(type), "access_logs");
    cJSON *credentials_file = cJSON_GetObjectItem(gcp_bucket->child, "credentials_file");
    assert_string_equal(cJSON_GetStringValue(credentials_file), "/wazuh/credentials/test.json");
}

static void test_wm_gcp_bucket_dump_success_logging_critical(void **state) {
    gcp_bucket_dump_t *gcp_bucket_dump_data = *state;
    wm_gcp_bucket *cur_bucket = gcp_bucket_dump_data->config->buckets;

    gcp_bucket_dump_data->config->enabled = 0;
    gcp_bucket_dump_data->config->run_on_start = 0;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->wm_wd);
    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->cur_bucket);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_bucket_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_bucket_dump_data->wm_wd);

    gcp_bucket_dump_data->dump = wm_gcp_bucket_dump(gcp_bucket_dump_data->config);

    assert_non_null(gcp_bucket_dump_data->dump);
    assert_ptr_equal(gcp_bucket_dump_data->dump, gcp_bucket_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_bucket_dump_data->dump), 1);

    cJSON *gcp_bucket_base = cJSON_GetObjectItem(gcp_bucket_dump_data->dump, "gcp-bucket");
    assert_non_null(gcp_bucket_base);
    assert_int_equal(cJSON_GetArraySize(gcp_bucket_base), 4);

    cJSON *enabled = cJSON_GetObjectItem(gcp_bucket_base, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "no");
    cJSON *run_on_start = cJSON_GetObjectItem(gcp_bucket_base, "run_on_start");
    assert_string_equal(cJSON_GetStringValue(run_on_start), "no");
    cJSON *gcp_bucket = cJSON_GetObjectItem(gcp_bucket_dump_data->dump->child, "buckets");
    assert_non_null(gcp_bucket);
    cJSON *bucket = cJSON_GetObjectItem(gcp_bucket->child, "bucket");
    assert_string_equal(cJSON_GetStringValue(bucket), "wazuh-gcp-test");
    cJSON *type = cJSON_GetObjectItem(gcp_bucket->child, "type");
    assert_string_equal(cJSON_GetStringValue(type), "access_logs");
    cJSON *credentials_file = cJSON_GetObjectItem(gcp_bucket->child, "credentials_file");
    assert_string_equal(cJSON_GetStringValue(credentials_file), "/wazuh/credentials/test.json");
}

static void test_wm_gcp_bucket_dump_success_logging_default(void **state) {
    gcp_bucket_dump_t *gcp_bucket_dump_data = *state;
    wm_gcp_bucket *cur_bucket = gcp_bucket_dump_data->config->buckets;

    gcp_bucket_dump_data->config->enabled = 0;
    gcp_bucket_dump_data->config->run_on_start = 0;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->wm_wd);
    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->cur_bucket);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_bucket_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_bucket_dump_data->wm_wd);

    gcp_bucket_dump_data->dump = wm_gcp_bucket_dump(gcp_bucket_dump_data->config);

    assert_non_null(gcp_bucket_dump_data->dump);
    assert_ptr_equal(gcp_bucket_dump_data->dump, gcp_bucket_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_bucket_dump_data->dump), 1);

    cJSON *gcp_bucket_base = cJSON_GetObjectItem(gcp_bucket_dump_data->dump, "gcp-bucket");
    assert_non_null(gcp_bucket_base);
    assert_int_equal(cJSON_GetArraySize(gcp_bucket_base), 4);

    cJSON *enabled = cJSON_GetObjectItem(gcp_bucket_base, "enabled");
    assert_string_equal(cJSON_GetStringValue(enabled), "no");
    cJSON *run_on_start = cJSON_GetObjectItem(gcp_bucket_base, "run_on_start");
    assert_string_equal(cJSON_GetStringValue(run_on_start), "no");
    cJSON *gcp_bucket = cJSON_GetObjectItem(gcp_bucket_dump_data->dump->child, "buckets");
    assert_non_null(gcp_bucket);
    cJSON *bucket = cJSON_GetObjectItem(gcp_bucket->child, "bucket");
    assert_string_equal(cJSON_GetStringValue(bucket), "wazuh-gcp-test");
    cJSON *type = cJSON_GetObjectItem(gcp_bucket->child, "type");
    assert_string_equal(cJSON_GetStringValue(type), "access_logs");
    cJSON *credentials_file = cJSON_GetObjectItem(gcp_bucket->child, "credentials_file");
    assert_string_equal(cJSON_GetStringValue(credentials_file), "/wazuh/credentials/test.json");
}

static void test_wm_gcp_bucket_dump_error_allocating_wm_wd(void **state) {
    gcp_bucket_dump_t *gcp_bucket_dump_data = *state;
    wm_gcp_bucket *cur_bucket = gcp_bucket_dump_data->config->buckets;

    gcp_bucket_dump_data->config->enabled = 0;
    gcp_bucket_dump_data->config->run_on_start = 0;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->root);
    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->wm_wd);
    will_return(__wrap_cJSON_CreateObject, gcp_bucket_dump_data->cur_bucket);

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_bucket_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, gcp_bucket_dump_data->wm_wd);

    will_return(__wrap_isDebug, 1);
    gcp_bucket_dump_data->dump = wm_gcp_bucket_dump(gcp_bucket_dump_data->config);

    assert_non_null(gcp_bucket_dump_data->dump);
    assert_ptr_equal(gcp_bucket_dump_data->dump, gcp_bucket_dump_data->root);
    assert_int_equal(cJSON_GetArraySize(gcp_bucket_dump_data->dump), 1);
}

static void test_wm_gcp_bucket_dump_error_allocating_root(void **state) {
    gcp_bucket_dump_t *gcp_bucket_dump_data = *state;
    wm_gcp_bucket *cur_bucket = gcp_bucket_dump_data->config->buckets;

    gcp_bucket_dump_data->config->enabled = 0;
    gcp_bucket_dump_data->config->run_on_start = 0;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    // Since we won't use wm_wd or root, we can just free them to prevent memory leaks.
    os_free(gcp_bucket_dump_data->wm_wd);
    gcp_bucket_dump_data->wm_wd = NULL;

    os_free(gcp_bucket_dump_data->root);
    gcp_bucket_dump_data->root = NULL;

    os_free(gcp_bucket_dump_data->cur_bucket);
    gcp_bucket_dump_data->cur_bucket = NULL;

    will_return(__wrap_cJSON_CreateObject, NULL);
    will_return(__wrap_cJSON_CreateObject, NULL);
    will_return(__wrap_cJSON_CreateObject, NULL);   // If we cannot alloc root, wm_wd won't be alloced either.

    expect_value(__wrap_sched_scan_dump, scan_config, &gcp_bucket_dump_data->config->scan_config);
    expect_value(__wrap_sched_scan_dump, cjson_object, NULL);

    will_return(__wrap_isDebug, 1);
    gcp_bucket_dump_data->dump = wm_gcp_bucket_dump(gcp_bucket_dump_data->config);

    assert_null(gcp_bucket_dump_data->dump);
}

/* wm_gcp_bucket_destroy */
static void test_wm_gcp_bucket_destroy(void **state) {
    wm_gcp_bucket_base **gcp_config = *state;

    // gcp_config[0] is to be destroyed by the test
    wm_gcp_bucket_destroy(gcp_config[0]);

    // No assertions are possible on this test, it's meant to be used along valgrind to check memory leaks.
}

/* wm_gcp_bucket_main */
static void test_wm_gcp_bucket_main_disabled(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;

    gcp_config->enabled = 0;

    expect_string(__wrap__mtinfo, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Module disabled. Exiting.");

    wm_gcp_bucket_main(gcp_config);
}

static void test_wm_gcp_bucket_main_run_on_start(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;
    void *ret;

    snprintf(cur_bucket->bucket, OS_SIZE_1024, "wazuh-gcp-test");
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled
    gcp_config->enabled = 1;
    gcp_config->run_on_start = 1;

    expect_string(__wrap__mtinfo, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Module started.");

    expect_value(__wrap_sched_scan_get_time_until_next_scan, config, &gcp_config->scan_config);
    expect_string(__wrap_sched_scan_get_time_until_next_scan, MODULE_TAG, WM_GCP_BUCKET_LOGTAG);
    expect_value(__wrap_sched_scan_get_time_until_next_scan, run_on_start, 1);
    will_return(__wrap_sched_scan_get_time_until_next_scan, 0);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Starting fetching of logs.");

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    will_return(__wrap_isDebug, 1);
    will_return(__wrap_isDebug, 1);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name wazuh-gcp-test --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Test output");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_isDebug, 1);

    expect_string(__wrap__mtinfo, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Executing Bucket Analysis: (Bucket: wazuh-gcp-test, "
        "Path: access_logs/, Type: access_logs, Credentials file: /wazuh/credentials/test.json)");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Fetching logs finished.");

    will_return(__wrap_FOREVER, 0);
    

    ret = wm_gcp_bucket_main(gcp_config);

    assert_null(ret);
}

static void test_wm_gcp_bucket_main_sleep_then_run(void **state) {
    wm_gcp_bucket_base *gcp_config = *state;
    wm_gcp_bucket *cur_bucket = gcp_config->buckets;
    void *ret;

    os_free(cur_bucket->bucket);
    snprintf(cur_bucket->type, OS_SIZE_1024, "access_logs");
    snprintf(cur_bucket->credentials_file, OS_SIZE_1024, "/wazuh/credentials/test.json");
    snprintf(cur_bucket->prefix, OS_SIZE_1024, "access_logs/");
    snprintf(cur_bucket->only_logs_after, OS_SIZE_1024, "2021-JAN-01");

    cur_bucket->remove_from_bucket = 1; // enabled
    gcp_config->enabled = 1;
    gcp_config->run_on_start = 1;

    int create_time = 123456789;
    gcp_config->scan_config.next_scheduled_scan_time = create_time; // sleep 10 seconds

    char *create_time_timestamp = NULL;
    os_strdup("20/10/21 15:35:48.111", create_time_timestamp);

    expect_string(__wrap__mtinfo, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Module started.");

    expect_value(__wrap_sched_scan_get_time_until_next_scan, config, &gcp_config->scan_config);
    expect_string(__wrap_sched_scan_get_time_until_next_scan, MODULE_TAG, WM_GCP_BUCKET_LOGTAG);
    expect_value(__wrap_sched_scan_get_time_until_next_scan, run_on_start, 1);
    will_return(__wrap_sched_scan_get_time_until_next_scan, create_time);

    expect_value(__wrap_w_get_timestamp, time, create_time);
    will_return(__wrap_w_get_timestamp, create_time_timestamp);

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Sleeping until: 20/10/21 15:35:48.111");

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Starting fetching of logs.");

    expect_string(__wrap__mtdebug2, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug2, formatted_msg, "Create argument list");

    will_return(__wrap_isDebug, 1);
    will_return(__wrap_isDebug, 1);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Launching command: "
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 1");

    expect_string(__wrap_wm_exec, command,
        "wodles/gcloud/gcloud --integration_type access_logs --bucket_name --credentials_file "
        "/wazuh/credentials/test.json --prefix access_logs/ --only_logs_after 2021-JAN-01 --remove --log_level 1");
    expect_value(__wrap_wm_exec, secs, 0);
    expect_value(__wrap_wm_exec, add_path, NULL);

    will_return(__wrap_wm_exec, "Test output");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtinfo, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Executing Bucket Analysis: (Bucket: unknown_bucket, "
        "Path: access_logs/, Type: access_logs, Credentials file: /wazuh/credentials/test.json)");

    will_return(__wrap_isDebug, 1);

    expect_string(__wrap__mtdebug1, tag, WM_GCP_BUCKET_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Fetching logs finished.");

    will_return(__wrap_FOREVER, 0);

    ret = wm_gcp_bucket_main(gcp_config);

    assert_null(ret);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        /* wm_gcp_pubsub_run */
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_error_running_command, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_unknown_error, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_unknown_error_no_description, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_error_parsing_args, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_error_parsing_args_no_description, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_generic_error, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_generic_error_no_description, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_logging_warning_message_warning, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_logging_warning_multiline_message_error, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_logging_warning_multimessage_message_error, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_logging_debug_message_not_debug, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_logging_debug_message_not_debug_discarded, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_logging_info_message_info, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_logging_info_message_debug, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_logging_info_message_warning, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_logging_warning_message_warning, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_run_logging_warning_message_error, setup_group_pubsub, teardown_group_pubsub),

        /* wm_gcp_pubsub_dump */
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_dump_success_logging_debug, setup_gcp_pubsub_dump, teardown_gcp_pubsub_dump),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_dump_success_logging_info, setup_gcp_pubsub_dump, teardown_gcp_pubsub_dump),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_dump_success_logging_warning, setup_gcp_pubsub_dump, teardown_gcp_pubsub_dump),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_dump_error_allocating_wm_wd, setup_gcp_pubsub_dump, teardown_gcp_pubsub_dump),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_dump_error_allocating_root, setup_gcp_pubsub_dump, teardown_gcp_pubsub_dump),

        /* wm_gcp_pubsub_destroy */
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_destroy, setup_gcp_pubsub_destroy, teardown_gcp_pubsub_destroy),

        /* wm_gcp_pubsub_main */
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_main_disabled, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_main_pull_on_start, setup_group_pubsub, teardown_group_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_main_sleep_then_run, setup_group_pubsub, teardown_group_pubsub),

        /* wm_gcp_bucket_run */
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_success, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_error_running_command, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_error, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_error_no_description, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_error_parsing_args, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_error_parsing_args_no_description, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_generic_error, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_generic_error_no_description, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_logging_debug_message_debug, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_logging_debug_message_not_debug, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_logging_debug_message_not_debug_discarded, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_logging_info_message_info, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_logging_info_message_debug, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_logging_info_message_warning, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_logging_warning_message_warning, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_logging_warning_message_debug, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_logging_warning_message_error, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_logging_warning_multiline_message_error, setup_group_bucket, teardown_group_bucket),
	cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_run_logging_warning_multimessage_message_error, setup_group_bucket, teardown_group_bucket),

        /* wm_gcp_bucket_dump */
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_dump_success, setup_gcp_bucket_dump, teardown_gcp_bucket_dump),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_dump_error_allocating_wm_wd, setup_gcp_bucket_dump, teardown_gcp_bucket_dump),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_dump_error_allocating_root, setup_gcp_bucket_dump, teardown_gcp_bucket_dump),

        /* wm_gcp_bucket_destroy */
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_destroy, setup_gcp_bucket_destroy, teardown_gcp_bucket_destroy),

        /* wm_gcp_bucket_main */
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_main_disabled, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_main_run_on_start, setup_group_bucket, teardown_group_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_main_sleep_then_run, setup_group_bucket, teardown_group_bucket),
    };
    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
