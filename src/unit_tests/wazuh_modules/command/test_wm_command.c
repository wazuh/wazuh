/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the scheduling capacities
 * for command Module
 * */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>
#include <string.h>

#include "shared.h"
#include "wmodules.h"
#include "wm_command.h"
#include "cJSON.h"

#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_exec_wrappers.h"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wmodules_wrappers.h"

#define TEST_MAX_DATES 5

#define WM_COMMAND_TEST_LOGTAG "wazuh-modulesd:command"

static wmodule *command_module;
static OS_XML *lxml;
extern int test_mode;

typedef enum wm_command_payload_case {
    WM_PAYLOAD_CASE_NORMAL = 0,
    WM_PAYLOAD_CASE_EMPTY,
    WM_PAYLOAD_CASE_TRUNCATED,
    WM_PAYLOAD_CASE_METADATA_ONLY,
} wm_command_payload_case;

typedef struct wm_command_payload_expectation {
    wm_command_payload_case payload_case;
    const char *command_line;
    const char *tag;
    int exit_code;
    const char *raw_output;
    const char *expected_output;   // For NORMAL/EMPTY/METADATA_ONLY expects exact; for TRUNCATED expects prefix match.
} wm_command_payload_expectation;

static wm_command_payload_expectation g_payload_expectation;

static size_t wm_command_max_json_payload_len(void) {
    const char *extag = WM_COMMAND_CONTEXT.name;
    const size_t header_len = 3 + strlen(extag); // "1:" + extag + ":"
    return header_len < OS_MAXSTR ? (OS_MAXSTR - header_len - 1) : 0;
}

static const char *wm_command_json_get_string(const cJSON *obj, const char *key) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive((cJSON *)obj, key);
    if (!cJSON_IsString(item) || !item->valuestring) {
        return NULL;
    }
    return item->valuestring;
}

static const cJSON *wm_command_json_get_object(const cJSON *obj, const char *key) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive((cJSON *)obj, key);
    return cJSON_IsObject(item) ? item : NULL;
}

static const cJSON *wm_command_json_get_array(const cJSON *obj, const char *key) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive((cJSON *)obj, key);
    return cJSON_IsArray(item) ? item : NULL;
}

static int check_wm_sendmsg_message_is_valid_command_json(const LargestIntegralType value,
                                                          const LargestIntegralType check_data) {
    (void)check_data;
    const char *message = (const char *)value;
    const size_t max_len = wm_command_max_json_payload_len();

    assert_non_null(message);
    assert_true(max_len > 0);
    assert_true(strlen(message) <= max_len);

    cJSON *root = cJSON_Parse(message);
    assert_non_null(root);

    const char *event_module = wm_command_json_get_string(root, "event.module");
    assert_non_null(event_module);
    assert_string_equal(event_module, "wazuh-wodle-cmd");

    const char *event_start = wm_command_json_get_string(root, "event.start");
    assert_non_null(event_start);

    if (g_payload_expectation.tag) {
        const char *tags = wm_command_json_get_string(root, "tags");
        assert_non_null(tags);
        assert_string_equal(tags, g_payload_expectation.tag);
    }

    const cJSON *process = wm_command_json_get_object(root, "process");
    assert_non_null(process);

    const char *proc_name = wm_command_json_get_string(process, "name");
    assert_non_null(proc_name);
    assert_string_equal(proc_name, "echo");

    const char *proc_path = wm_command_json_get_string(process, "path");
    assert_non_null(proc_path);
    assert_true(strstr(proc_path, "echo") != NULL);

    const char *command_line = wm_command_json_get_string(process, "command_line");
    assert_non_null(command_line);
    assert_string_equal(command_line, g_payload_expectation.command_line);

    const cJSON *exit_code = cJSON_GetObjectItemCaseSensitive((cJSON *)process, "exit_code");
    assert_true(cJSON_IsNumber(exit_code));
    assert_int_equal(exit_code->valueint, g_payload_expectation.exit_code);

    const cJSON *args = wm_command_json_get_array(process, "args");
    assert_non_null(args);
    // Validate expected args for the default command line used in most tests.
    if (strcmp(g_payload_expectation.command_line, "/bin/echo arg1 arg2") == 0) {
        assert_int_equal(cJSON_GetArraySize((cJSON *)args), 2);
        const cJSON *arg0 = cJSON_GetArrayItem((cJSON *)args, 0);
        const cJSON *arg1 = cJSON_GetArrayItem((cJSON *)args, 1);
        assert_true(cJSON_IsString(arg0));
        assert_true(cJSON_IsString(arg1));
        assert_string_equal(arg0->valuestring, "arg1");
        assert_string_equal(arg1->valuestring, "arg2");
    }

    const cJSON *process_io = wm_command_json_get_object(process, "io");
    assert_non_null(process_io);
    const char *io_text = wm_command_json_get_string(process_io, "text");
    assert_non_null(io_text);

    switch (g_payload_expectation.payload_case) {
    case WM_PAYLOAD_CASE_NORMAL:
    case WM_PAYLOAD_CASE_EMPTY:
    case WM_PAYLOAD_CASE_METADATA_ONLY:
        assert_string_equal(io_text, g_payload_expectation.expected_output ? g_payload_expectation.expected_output : "");
        break;
    case WM_PAYLOAD_CASE_TRUNCATED:
        assert_non_null(g_payload_expectation.raw_output);
        assert_true(strlen(io_text) < strlen(g_payload_expectation.raw_output));
        if (g_payload_expectation.expected_output) {
            assert_true(strncmp(io_text, g_payload_expectation.expected_output, strlen(g_payload_expectation.expected_output)) == 0);
        }
        break;
    }

    cJSON_Delete(root);
    return 1;
}

static int setup_test_payload(void **state) {
    wm_command_t *command = calloc(1, sizeof(wm_command_t));
    assert_non_null(command);

    command->enabled = 1;
    command->run_on_start = 1;
    command->ignore_output = 0;
    command->agent_cfg = 0;
    command->timeout = 0;

    command->tag = strdup("test");
    command->command = strdup("/bin/echo arg1 arg2");
    assert_non_null(command->tag);
    assert_non_null(command->command);

    command->scan_config = init_config_from_string("<interval>10s</interval>\n");

    wm_max_eps = 1000000; // Avoid division by zero; wm_sendmsg is wrapped in these tests.
    *state = command;
    return 0;
}

static int teardown_test_payload(void **state) {
    wm_command_t *command = (wm_command_t *)*state;
    if (command) {
        sched_scan_free(&(command->scan_config));
        free(command->tag);
        free(command->command);
        free(command->full_command);
        free(command);
    }
    return 0;
}

static void wm_command_prepare_single_iteration(void) {
    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);
}

static void wm_command_expect_sendmsg_json(void) {
    expect_any(__wrap_wm_sendmsg, usec);
    expect_any(__wrap_wm_sendmsg, queue);
    expect_check(__wrap_wm_sendmsg, message, check_wm_sendmsg_message_is_valid_command_json, 0);
    expect_string(__wrap_wm_sendmsg, locmsg, WM_COMMAND_CONTEXT.name);
    expect_value(__wrap_wm_sendmsg, loc, LOCALFILE_MQ);
    will_return(__wrap_wm_sendmsg, 0);
}

static size_t wm_command_build_base_len_for_test(const char *event_start,
                                                 const char *tag,
                                                 const char *command_line,
                                                 const char *proc_name,
                                                 const char *proc_path,
                                                 char **proc_argv,
                                                 int status) {
    cJSON *json_event = cJSON_CreateObject();
    assert_non_null(json_event);

    cJSON_AddStringToObject(json_event, "event.module", "wazuh-wodle-cmd");
    cJSON_AddStringToObject(json_event, "event.start", event_start ? event_start : "");
    if (tag) {
        cJSON_AddStringToObject(json_event, "tags", tag);
    }

    cJSON *process = cJSON_AddObjectToObject(json_event, "process");
    assert_non_null(process);

    cJSON *process_args = cJSON_AddArrayToObject(process, "args");
    if (process_args && proc_argv) {
        for (size_t i = 1; proc_argv[i]; ++i) {
            cJSON_AddItemToArray(process_args, cJSON_CreateString(proc_argv[i]));
        }
    }

    cJSON_AddStringToObject(process, "name", proc_name ? proc_name : "");
    cJSON_AddStringToObject(process, "path", proc_path ? proc_path : "");
    cJSON_AddStringToObject(process, "command_line", command_line ? command_line : "");
    cJSON_AddNumberToObject(process, "exit_code", status);

    cJSON *process_io = cJSON_AddObjectToObject(process, "io");
    assert_non_null(process_io);
    cJSON_AddStringToObject(process_io, "text", "");

    char *json_payload = cJSON_PrintUnformatted(json_event);
    cJSON_Delete(json_event);

    assert_non_null(json_payload);
    size_t len = strlen(json_payload);
    free(json_payload);
    return len;
}

static size_t wm_command_compute_metadata_only_command_filler_len(void) {
    const size_t max_len = wm_command_max_json_payload_len();
    assert_true(max_len > 0);

    const char *event_start = "2026-04-27T00:00:00Z";
    const char *tag = "test";
    const char *proc_path = "/bin/echo";
    const char *proc_name = "echo";
    const int status = 0;
    const char *prefix = "/bin/echo ";

    // Measure slope by comparing filler length 0 vs 1.
    char command0[64];
    snprintf(command0, sizeof(command0), "%s", prefix);
    char *command0_cpy = strdup(command0);
    assert_non_null(command0_cpy);
    char **argv0 = w_strtok(command0_cpy);
    size_t base0 = wm_command_build_base_len_for_test(event_start, tag, command0, proc_name, proc_path, argv0, status);
    free_strarray(argv0);
    free(command0_cpy);

    char command1[64];
    snprintf(command1, sizeof(command1), "%sA", prefix);
    char *command1_cpy = strdup(command1);
    assert_non_null(command1_cpy);
    char **argv1 = w_strtok(command1_cpy);
    size_t base1 = wm_command_build_base_len_for_test(event_start, tag, command1, proc_name, proc_path, argv1, status);
    free_strarray(argv1);
    free(command1_cpy);

    const size_t slope = base1 - base0;
    assert_true(slope > 0);

    // Target: leave ~1 byte for output before escaping pushes it over.
    const size_t target = max_len - 1;
    assert_true(base0 < target);

    size_t filler_len = (target - base0) / slope;

    // Adjust to the closest value where base_len is within [max_len-1, max_len-1].
    // (We just need base_len close enough so that a 1-char output that escapes will overflow.)
    for (int i = 0; i < 1024; ++i) {
        char *filler = calloc(filler_len + 1, 1);
        assert_non_null(filler);
        memset(filler, 'A', filler_len);
        filler[filler_len] = '\0';

        size_t cmd_len = strlen(prefix) + filler_len;
        char *cmdline = calloc(cmd_len + 1, 1);
        assert_non_null(cmdline);
        memcpy(cmdline, prefix, strlen(prefix));
        memcpy(cmdline + strlen(prefix), filler, filler_len);
        cmdline[cmd_len] = '\0';

        char *cmd_cpy = strdup(cmdline);
        assert_non_null(cmd_cpy);
        char **argv = w_strtok(cmd_cpy);
        size_t base_len = wm_command_build_base_len_for_test(event_start, tag, cmdline, proc_name, proc_path, argv, status);
        free_strarray(argv);
        free(cmd_cpy);

        free(cmdline);
        free(filler);

        if (base_len == target) {
            return filler_len;
        }
        if (base_len < target) {
            filler_len++;
        } else {
            if (filler_len == 0) {
                break;
            }
            filler_len--;
        }
    }

    fail_msg("Unable to compute filler length for metadata-only fallback");
    return 0;
}

/****************************************************************/
static void wmodule_cleanup(wmodule *module){
    wm_command_t* module_data = (wm_command_t *)module->data;
    free(module_data->sha256_hash);
    free(module_data->sha1_hash);
    free(module_data->full_command);
    free(module_data->command);
    free(module_data->tag);
    free(module_data);
    free(module->tag);
    free(module);
}

/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    command_module = calloc(1, sizeof(wmodule));
    const char *string =
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<interval>1d</interval>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<interval>10m</interval>\n"
        "<skip_verification>yes</skip_verification>"
    ;
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);

    int ret = wm_command_read(nodes, command_module, 0);
    OS_ClearNode(nodes);
    test_mode = 1;
    return ret;
}

static int teardown_module(){
    test_mode = 0;
    wmodule_cleanup(command_module);
    OS_ClearXML(lxml);
    return 0;
}

static int setup_test_executions(void **state){
    wm_max_eps = 1;
    return 0;
}

static int teardown_test_executions(void **state){
    wm_command_t* module_data = (wm_command_t *) *state;
    sched_scan_free(&(module_data->scan_config));
    return 0;
}

static int setup_test_read(void **state) {
    test_structure *test = calloc(1, sizeof(test_structure));
    test->module =  calloc(1, sizeof(wmodule));
    *state = test;
    return 0;
}

static int teardown_test_read(void **state) {
    test_structure *test = *state;
    OS_ClearNode(test->nodes);
    OS_ClearXML(&(test->xml));
    wm_command_t *module_data = (wm_command_t*)test->module->data;
    sched_scan_free(&(module_data->scan_config));
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}

static int setup_test_checksum(void **state) {
    wm_command_t *command = calloc(1, sizeof(wm_command_t));
    command->full_command = strdup("/test/file.sh --debug");
    command->md5_hash = strdup("d41d8cd98f00b204e9800998ecf8427e");
    command->sha1_hash = strdup("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    command->sha256_hash = strdup("e69ee96c1f3f6117391ce27b4656193e54b7b187d66c9920806eced9dd4a4129");
    *state = command;
    return 0;
}

static int teardown_test_checksum(void **state) {
    wm_command_t *command = *state;
    os_free(command->full_command);
    os_free(command->md5_hash);
    os_free(command->sha1_hash);
    os_free(command->sha256_hash);
    os_free(command);
    return 0;
}

/** Tests **/
void test_interval_execution(void **state) {
    wm_command_t* module_data = (wm_command_t *)command_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 60; // 1min
    module_data->scan_config.month_interval = false;

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);

    expect_any_always(__wrap_wm_exec, command);
    expect_any_always(__wrap_wm_exec, secs);
    expect_any_always(__wrap_wm_exec, add_path);

    will_return_always(__wrap_wm_exec, 0);

    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    expect_any_always(__wrap__mtinfo, tag);
    expect_any_always(__wrap__mtinfo, formatted_msg);
    expect_any_always(__wrap__mtdebug1, tag);
    expect_any_always(__wrap__mtdebug1, formatted_msg);

    expect_any_always(__wrap_wm_validate_command, command);
    expect_any_always(__wrap_wm_validate_command, digest);
    expect_any_always(__wrap_wm_validate_command, ctype);
    will_return_always(__wrap_wm_validate_command, 1);

    command_module->context->start(module_data);
}

static void test_command_payload_normal_output(void **state) {
    wm_command_t *command = (wm_command_t *)*state;
    const char *output = "hello \"world\"\\nsecond-line";

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);

    expect_any(__wrap_wm_exec, command);
    expect_any(__wrap_wm_exec, secs);
    expect_any(__wrap_wm_exec, add_path);
    will_return(__wrap_wm_exec, (char *)output);
    will_return(__wrap_wm_exec, 7);
    will_return(__wrap_wm_exec, 0);

    wm_command_prepare_single_iteration();
    wm_command_expect_sendmsg_json();

    g_payload_expectation.payload_case = WM_PAYLOAD_CASE_NORMAL;
    g_payload_expectation.command_line = command->command;
    g_payload_expectation.tag = command->tag;
    g_payload_expectation.exit_code = 7;
    g_payload_expectation.raw_output = output;
    g_payload_expectation.expected_output = output;

    WM_COMMAND_CONTEXT.start(command);
}

static void test_command_payload_empty_output(void **state) {
    wm_command_t *command = (wm_command_t *)*state;
    const char *output = "";

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);

    expect_any(__wrap_wm_exec, command);
    expect_any(__wrap_wm_exec, secs);
    expect_any(__wrap_wm_exec, add_path);
    will_return(__wrap_wm_exec, (char *)output);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    wm_command_prepare_single_iteration();
    wm_command_expect_sendmsg_json();

    g_payload_expectation.payload_case = WM_PAYLOAD_CASE_EMPTY;
    g_payload_expectation.command_line = command->command;
    g_payload_expectation.tag = command->tag;
    g_payload_expectation.exit_code = 0;
    g_payload_expectation.raw_output = output;
    g_payload_expectation.expected_output = "";

    WM_COMMAND_CONTEXT.start(command);
}

static void test_command_payload_long_output_truncates(void **state) {
    wm_command_t *command = (wm_command_t *)*state;
    const size_t max_len = wm_command_max_json_payload_len();
    assert_true(max_len > 0);

    // Make output far larger than OS_MAXSTR so truncation path is hit.
    const size_t output_len = max_len * 2;
    char *output = calloc(output_len + 1, 1);
    assert_non_null(output);
    memset(output, 'B', output_len);
    output[output_len] = '\0';

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);

    expect_any(__wrap_wm_exec, command);
    expect_any(__wrap_wm_exec, secs);
    expect_any(__wrap_wm_exec, add_path);
    will_return(__wrap_wm_exec, output);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    wm_command_prepare_single_iteration();
    wm_command_expect_sendmsg_json();

    g_payload_expectation.payload_case = WM_PAYLOAD_CASE_TRUNCATED;
    g_payload_expectation.command_line = command->command;
    g_payload_expectation.tag = command->tag;
    g_payload_expectation.exit_code = 0;
    g_payload_expectation.raw_output = output;
    g_payload_expectation.expected_output = "BBBB";

    WM_COMMAND_CONTEXT.start(command);
    free(output);
}

static void test_command_payload_metadata_only_fallback(void **state) {
    wm_command_t *command = (wm_command_t *)*state;
    const size_t filler_len = wm_command_compute_metadata_only_command_filler_len();
    const char *prefix = "/bin/echo ";

    // Replace the command line with a very long one that almost fills the max payload.
    free(command->command);
    size_t cmd_len = strlen(prefix) + filler_len;
    command->command = calloc(cmd_len + 1, 1);
    assert_non_null(command->command);
    memcpy(command->command, prefix, strlen(prefix));
    memset(command->command + strlen(prefix), 'A', filler_len);
    command->command[cmd_len] = '\0';

    const char *output = "\""; // Escapes to two bytes (\") so a 1-char allowance will still overflow.

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);

    expect_any(__wrap_wm_exec, command);
    expect_any(__wrap_wm_exec, secs);
    expect_any(__wrap_wm_exec, add_path);
    will_return(__wrap_wm_exec, (char *)output);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    wm_command_prepare_single_iteration();
    wm_command_expect_sendmsg_json();

    g_payload_expectation.payload_case = WM_PAYLOAD_CASE_METADATA_ONLY;
    g_payload_expectation.command_line = command->command;
    g_payload_expectation.tag = command->tag;
    g_payload_expectation.exit_code = 0;
    g_payload_expectation.raw_output = output;
    g_payload_expectation.expected_output = "";

    WM_COMMAND_CONTEXT.start(command);
}

void test_fake_tag(void **state) {
    const char *string =
        "<fake>True</fake>\n"
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<time>19:55</time>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<interval>10m</interval>\n"
        "<skip_verification>yes</skip_verification>";
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "No such tag 'fake' at module 'command'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_command_read(test->nodes, test->module, 0),-1);
}

void test_read_scheduling_monthday_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<time>12:05</time>\n"
        "<day>1</day>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<skip_verification>yes</skip_verification>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one month. New interval value: 1M");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_command_read(test->nodes, test->module, 0),0);
    wm_command_t *module_data = (wm_command_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 1);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "12:05");
}

void test_read_scheduling_weekday_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<time>10:59</time>\n"
        "<wday>Tuesday</wday>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<skip_verification>yes</skip_verification>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one week. New interval value: 1w");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_command_read(test->nodes, test->module, 0),0);
    wm_command_t *module_data = (wm_command_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 2);
    assert_string_equal(module_data->scan_config.scan_time, "10:59");
}

void test_read_scheduling_daytime_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<time>10:53</time>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<skip_verification>yes</skip_verification>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one day. New interval value: 1d");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_command_read(test->nodes, test->module, 0),0);
    wm_command_t *module_data = (wm_command_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "10:53");
}

void test_read_scheduling_interval_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<interval>10s</interval>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<skip_verification>yes</skip_verification>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_command_read(test->nodes, test->module, 0),0);
    wm_command_t *module_data = (wm_command_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 10); // 10 seconds
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
}

void test_validate_command_checksums_success(void **state) {
    wm_command_t *command = *state;

    expect_wm_validate_command("/test/file.sh", command->md5_hash, MD5SUM, 1);
    expect_wm_validate_command("/test/file.sh", command->sha1_hash, SHA1SUM, 1);
    expect_wm_validate_command("/test/file.sh", command->sha256_hash, SHA256SUM, 1);

    expect_string(__wrap__mtdebug1, tag, WM_COMMAND_TEST_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "MD5 checksum verification was successful for command '/test/file.sh --debug'.");
    expect_string(__wrap__mtdebug1, tag, WM_COMMAND_TEST_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "SHA1 checksum verification was successful for command '/test/file.sh --debug'.");
    expect_string(__wrap__mtdebug1, tag, WM_COMMAND_TEST_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "SHA256 checksum verification was successful for command '/test/file.sh --debug'.");

    assert_int_equal(validate_command_checksums(command, "/test/file.sh"), 0);
}

void test_validate_command_checksums_failure(void **state) {
    wm_command_t *command = *state;

    expect_wm_validate_command("/test/file.sh", command->md5_hash, MD5SUM, 1);
    expect_wm_validate_command("/test/file.sh", command->sha1_hash, SHA1SUM, 0);

    expect_string(__wrap__mtdebug1, tag, WM_COMMAND_TEST_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "MD5 checksum verification was successful for command '/test/file.sh --debug'.");
    expect_string(__wrap__mterror, tag, WM_COMMAND_TEST_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "SHA1 checksum verification failed for command '/test/file.sh --debug'.");

    assert_int_equal(validate_command_checksums(command, "/test/file.sh"), -1);
}

int main(void) {
    const struct CMUnitTest tests_with_startup[] = {
        cmocka_unit_test_setup_teardown(test_interval_execution, setup_test_executions, teardown_test_executions)
    };
    const struct CMUnitTest tests_without_startup[] = {
        cmocka_unit_test_setup_teardown(test_fake_tag, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_monthday_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_weekday_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_daytime_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_interval_configuration, setup_test_read, teardown_test_read)
    };
    const struct CMUnitTest tests_validate_command_checksums[] = {
        cmocka_unit_test_setup_teardown(test_validate_command_checksums_success, setup_test_checksum, teardown_test_checksum),
        cmocka_unit_test_setup_teardown(test_validate_command_checksums_failure, setup_test_checksum, teardown_test_checksum)
    };
    const struct CMUnitTest tests_payload_json[] = {
        cmocka_unit_test_setup_teardown(test_command_payload_normal_output, setup_test_payload, teardown_test_payload),
        cmocka_unit_test_setup_teardown(test_command_payload_empty_output, setup_test_payload, teardown_test_payload),
        cmocka_unit_test_setup_teardown(test_command_payload_long_output_truncates, setup_test_payload, teardown_test_payload),
        cmocka_unit_test_setup_teardown(test_command_payload_metadata_only_fallback, setup_test_payload, teardown_test_payload)
    };
    int result;
    result = cmocka_run_group_tests(tests_with_startup, setup_module, teardown_module);
    result += cmocka_run_group_tests(tests_without_startup, NULL, NULL);
    result += cmocka_run_group_tests(tests_validate_command_checksums, NULL, NULL);
    result += cmocka_run_group_tests(tests_payload_json, NULL, NULL);
    return result;
}
