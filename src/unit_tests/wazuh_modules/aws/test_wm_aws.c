/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the scheduling capacities
 * for aws Module
 * */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>
#include "shared.h"
#include "wmodules.h"
#include "wm_aws.h"
#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wmodules_wrappers.h"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"

#define TEST_MAX_DATES 5

#define WM_AWS_TEST_LOGTAG "wazuh-modulesd:aws-s3"

static wmodule *aws_module;
static OS_XML *lxml;
extern int test_mode;

extern void wm_aws_run_s3(wm_aws_bucket *bucket);

// Static in wm_aws.c, but visible here because WAZUH_UNIT_TESTING drops the qualifier.
extern void wm_aws_add_quoted_arg(char **command, const char *value);

// Not in wm_aws.h: the module only exposes it through WM_AWS_CONTEXT.dump.
cJSON *wm_aws_dump(const wm_aws *aws_config);

void wm_aws_run_s3(wm_aws_bucket *exec_bucket) {
    // Will wrap this function to check running times in order to check scheduling
    return;
}
/****************************************************************/

static void wmodule_cleanup(wmodule *module) {
    free( ((wm_aws*) module->data)->buckets->bucket);
    free( ((wm_aws*) module->data)->buckets->aws_profile);
    free( ((wm_aws*) module->data)->buckets->trail_prefix);
    free( ((wm_aws*) module->data)->buckets->type);
    free( ((wm_aws*) module->data)->buckets);
    free(module->data);
    free(module->tag);
    free(module);
}

/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    int ret;
    aws_module = calloc(1, sizeof(wmodule));
    const char *string =
        "<disabled>no</disabled>\n"
        "<interval>10m</interval>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>"
    ;
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);
    ret = wm_aws_read(lxml, nodes, aws_module);
    OS_ClearNode(nodes);
    test_mode = 1;
    return ret;
}

static int teardown_module() {
    test_mode = 0;
    wmodule_cleanup(aws_module);
    OS_ClearXML(lxml);
    return 0;
}

static int setup_test_executions(void **state) {
    wm_max_eps = 1;
    return 0;
}

static int teardown_test_executions(void **state) {
    wm_aws* module_data = (wm_aws *) *state;
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
    wm_aws *module_data = (wm_aws*)test->module->data;
    sched_scan_free(&(module_data->scan_config));
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}

/** Tests **/
void test_interval_execution(void **state) {
    wm_aws* module_data = (wm_aws *)aws_module->data;
    int i = 0;

    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 600; // 10min
    module_data->scan_config.month_interval = false;

    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);

    expect_string(__wrap_wm_state_io, tag, "aws-s3");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_value(__wrap_wm_state_io, state, &module_data->state);
    expect_value(__wrap_wm_state_io, size, sizeof(module_data->state));
    will_return(__wrap_wm_state_io, 1);

    for (i = 0; i < TEST_MAX_DATES + 1; i++) {
        expect_string(__wrap_wm_state_io, tag, "aws-s3");
        expect_value(__wrap_wm_state_io, op, WM_IO_WRITE);
        expect_value(__wrap_wm_state_io, state, &module_data->state);
        expect_value(__wrap_wm_state_io, size, sizeof(module_data->state));
        will_return(__wrap_wm_state_io, -1);
    }

    expect_string_count(__wrap__mterror, tag, WM_AWS_TEST_LOGTAG, TEST_MAX_DATES + 1);
    expect_string_count(__wrap__mterror, formatted_msg, "Couldn't save running state.", TEST_MAX_DATES + 1);
    expect_any_always(__wrap__mtinfo, tag);
    expect_any_always(__wrap__mtinfo, formatted_msg);

    aws_module->context->start(module_data);
}

void test_fake_tag(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<time>15:05</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>\n"
        "<fake-tag>ASD</fake-tag>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "No such tag 'fake-tag' at module 'aws-s3'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_aws_read(&(test->xml), test->nodes, test->module), -1);

}

void test_invalid_bucket_type(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<time>15:05</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"bogus\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "</bucket>\n"
    ;
    test_structure *test = *state;
    /* Every valid type is quoted on both sides. */
    expect_string(__wrap__mterror, tag, WM_AWS_TEST_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg,
                  "Invalid bucket type 'bogus'. Valid ones are 'cloudtrail', 'config', 'guardduty', 'vpcflow', "
                  "'waf', 'cisco_umbrella', 'custom', 'alb', 'clb', 'nlb' or 'server_access'");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_aws_read(&(test->xml), test->nodes, test->module), -1);
}

void test_read_scheduling_monthday_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<time>15:05</time>\n"
        "<day>6</day>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one month. New interval value: 1M");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_aws_read(&(test->xml), test->nodes, test->module), 0);
    wm_aws *module_data = (wm_aws*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 6);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "15:05");
}

void test_read_scheduling_weekday_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<time>13:03</time>\n"
        "<wday>Monday</wday>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one week. New interval value: 1w");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_aws_read(&(test->xml), test->nodes, test->module), 0);
    wm_aws *module_data = (wm_aws*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 1);
    assert_string_equal(module_data->scan_config.scan_time, "13:03");
}

void test_read_scheduling_daytime_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<time>01:11</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one day. New interval value: 1d");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_aws_read(&(test->xml), test->nodes, test->module), 0);
    wm_aws *module_data = (wm_aws*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "01:11");
}

void test_read_scheduling_interval_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<interval>10m</interval>\n"
        "<run_on_start>no</run_on_start>\n"
        "<skip_on_error>yes</skip_on_error>\n"
        "<bucket type=\"config\">\n"
        "    <name>wazuh-aws-wodle</name>\n"
        "    <path>config</path>\n"
        "   <aws_profile>default</aws_profile>\n"
        "</bucket>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_aws_read(&(test->xml), test->nodes, test->module), 0);
    wm_aws *module_data = (wm_aws*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 600);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
}

/* Tests for wm_aws_add_quoted_arg (quoting of the command-line values that may contain
   spaces: discard_regex, discard_field, aws_profile, aws_account_alias, trail_prefix
   and trail_suffix) */

// A value with spaces should end up quoted and, once w_strtok splits the command line
// the way wm_exec does, come back out as a single argument.
void test_add_quoted_arg_value_with_spaces(void **state) {
    char *command = NULL;
    wm_strcat(&command, "--discard-regex", ' ');
    wm_aws_add_quoted_arg(&command, "Security Hub Insight Results");

    assert_string_equal(command, "--discard-regex \"Security Hub Insight Results\"");

    char **argv = w_strtok(command);
    assert_string_equal(argv[0], "--discard-regex");
    assert_string_equal(argv[1], "Security Hub Insight Results");
    assert_null(argv[2]);

    free_strarray(argv);
    os_free(command);
}

// A value without spaces gets quoted too, and still comes back unchanged.
void test_add_quoted_arg_value_without_spaces(void **state) {
    char *command = NULL;
    wm_aws_add_quoted_arg(&command, "detail-type");

    assert_string_equal(command, "\"detail-type\"");

    char **argv = w_strtok(command);
    assert_string_equal(argv[0], "detail-type");
    assert_null(argv[1]);

    free_strarray(argv);
    os_free(command);
}

// Quotes and backslashes inside the value (think regexes like \d+ "value") have to be
// escaped so w_strtok hands the exact same string back.
void test_add_quoted_arg_value_with_special_chars(void **state) {
    char *command = NULL;
    wm_aws_add_quoted_arg(&command, "a\\d+ \"b\"");

    assert_string_equal(command, "\"a\\\\d+ \\\"b\\\"\"");

    char **argv = w_strtok(command);
    assert_string_equal(argv[0], "a\\d+ \"b\"");
    assert_null(argv[1]);

    free_strarray(argv);
    os_free(command);
}

// S3 object keys accept spaces, so a path prefix has to survive the split as one argument
// too. Same for the free-form account alias taken from the configuration.
void test_add_quoted_arg_bucket_values_with_spaces(void **state) {
    char *command = NULL;
    wm_strcat(&command, "--trail_prefix", ' ');
    wm_aws_add_quoted_arg(&command, "AWSLogs/my folder/");
    wm_strcat(&command, "--aws_account_alias", ' ');
    wm_aws_add_quoted_arg(&command, "Production Account");

    assert_string_equal(command,
        "--trail_prefix \"AWSLogs/my folder/\" --aws_account_alias \"Production Account\"");

    char **argv = w_strtok(command);
    assert_string_equal(argv[0], "--trail_prefix");
    assert_string_equal(argv[1], "AWSLogs/my folder/");
    assert_string_equal(argv[2], "--aws_account_alias");
    assert_string_equal(argv[3], "Production Account");
    assert_null(argv[4]);

    free_strarray(argv);
    os_free(command);
}

/* The dump only reads the configuration, so it is built on the stack: no
 * parser, no allocations to free. scan_wday -1 is what sched_scan_init leaves. */
static char *aws_dump_text(const wm_aws *aws_config) {
    cJSON *root = wm_aws_dump(aws_config);
    char *text = cJSON_PrintUnformatted(root);

    cJSON_Delete(root);
    return text;
}

void test_aws_dump_masks_bucket_and_service_keys(void **state) {
    wm_aws_bucket bucket = {
        .bucket = "wazuh-aws-wodle",
        .access_key = "AKIAFAKEBUCKETKEY001",
        .secret_key = "fakeBucketSecretKey001",
        .type = "cloudtrail",
    };
    wm_aws_service service = {
        .type = "inspector",
        .access_key = "AKIAFAKESERVICEKEY01",
        .secret_key = "fakeServiceSecretKey01",
        .regions = "us-east-1",
    };
    wm_aws aws_config = { .scan_config.scan_wday = -1, .enabled = 1, .buckets = &bucket, .services = &service };

    char *text = aws_dump_text(&aws_config);

    assert_string_equal(text, "{\"aws-s3\":{\"disabled\":\"no\",\"run_on_start\":\"no\",\"skip_on_error\":\"no\","
                              "\"buckets\":[{\"name\":\"wazuh-aws-wodle\",\"access_key\":\"*****\",\"secret_key\":\"*****\","
                              "\"type\":\"cloudtrail\",\"remove_from_bucket\":\"no\"}],"
                              "\"services\":[{\"type\":\"inspector\",\"access_key\":\"*****\",\"secret_key\":\"*****\","
                              "\"regions\":\"us-east-1\",\"remove_log_streams\":\"no\"}]}}");
    cJSON_free(text);
}

void test_aws_dump_never_prints_an_inline_key(void **state) {
    wm_aws_bucket second = { .bucket = "second-bucket", .access_key = "AKIAFAKESECONDKEY001", .secret_key = "fakeSecondSecret001" };
    wm_aws_bucket first = { .bucket = "first-bucket", .access_key = "AKIAFAKEFIRSTKEY0001", .secret_key = "fakeFirstSecret0001", .next = &second };
    wm_aws_service service = { .type = "cloudwatchlogs", .access_key = "AKIAFAKESERVICEKEY02", .secret_key = "fakeServiceSecret002" };
    wm_aws aws_config = { .scan_config.scan_wday = -1, .buckets = &first, .services = &service };
    const char *keys[] = { "AKIAFAKEFIRSTKEY0001", "fakeFirstSecret0001", "AKIAFAKESECONDKEY001",
                           "fakeSecondSecret001", "AKIAFAKESERVICEKEY02", "fakeServiceSecret002" };

    char *text = aws_dump_text(&aws_config);

    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        assert_null(strstr(text, keys[i]));
    }
    cJSON_free(text);
}

void test_aws_dump_reports_keys_in_clear_when_unmasked(void **state) {
    wm_aws_bucket bucket = { .bucket = "wazuh-aws-wodle", .access_key = "AKIAFAKEBUCKETKEY001", .secret_key = "fakeBucketSecretKey001" };
    wm_aws_service service = { .type = "inspector", .access_key = "AKIAFAKESERVICEKEY01", .secret_key = "fakeServiceSecretKey01" };
    wm_aws aws_config = { .scan_config.scan_wday = -1, .buckets = &bucket, .services = &service };

    wm_unmask_credentials = 1;
    char *text = aws_dump_text(&aws_config);
    wm_unmask_credentials = 0;

    assert_non_null(strstr(text, "\"access_key\":\"AKIAFAKEBUCKETKEY001\",\"secret_key\":\"fakeBucketSecretKey001\""));
    assert_non_null(strstr(text, "\"access_key\":\"AKIAFAKESERVICEKEY01\",\"secret_key\":\"fakeServiceSecretKey01\""));
    cJSON_free(text);
}

void test_aws_dump_leaves_out_keys_that_are_not_set(void **state) {
    wm_aws_bucket bucket = { .bucket = "wazuh-aws-wodle", .aws_profile = "default", .type = "cloudtrail" };
    wm_aws aws_config = { .scan_config.scan_wday = -1, .enabled = 1, .buckets = &bucket };

    char *text = aws_dump_text(&aws_config);

    assert_string_equal(text, "{\"aws-s3\":{\"disabled\":\"no\",\"run_on_start\":\"no\",\"skip_on_error\":\"no\","
                              "\"buckets\":[{\"name\":\"wazuh-aws-wodle\",\"aws_profile\":\"default\","
                              "\"type\":\"cloudtrail\",\"remove_from_bucket\":\"no\"}]}}");
    cJSON_free(text);
}

int main(void) {
    const struct CMUnitTest tests_with_startup[] = {
        cmocka_unit_test_setup_teardown(test_interval_execution, setup_test_executions, teardown_test_executions)
    };
    const struct CMUnitTest tests_without_startup[] = {
        cmocka_unit_test_setup_teardown(test_fake_tag, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_bucket_type, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_monthday_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_weekday_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_daytime_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_interval_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test(test_add_quoted_arg_value_with_spaces),
        cmocka_unit_test(test_add_quoted_arg_value_without_spaces),
        cmocka_unit_test(test_add_quoted_arg_value_with_special_chars),
        cmocka_unit_test(test_add_quoted_arg_bucket_values_with_spaces),
        cmocka_unit_test(test_aws_dump_masks_bucket_and_service_keys),
        cmocka_unit_test(test_aws_dump_never_prints_an_inline_key),
        cmocka_unit_test(test_aws_dump_reports_keys_in_clear_when_unmasked),
        cmocka_unit_test(test_aws_dump_leaves_out_keys_that_are_not_set)
    };
    int result;
    result = cmocka_run_group_tests(tests_with_startup, setup_module, teardown_module);
    result += cmocka_run_group_tests(tests_without_startup, NULL, NULL);
    return result;
}
