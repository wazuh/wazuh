/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the scheduling capacities
 * for ciscat Module
 * */

#define ENABLE_CISCAT
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>
#include "shared.h"
#include "../../../wazuh_modules/wmodules.h"
#include "../../../wazuh_modules/wm_ciscat.h"
#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../../wrappers/wazuh/shared/randombytes_wrappers.h"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"

#define TEST_MAX_DATES 5
#define TEST_CISCAT_DIR "/var/ossec/wodles/ciscat"
#define TEST_JAVA_DIR "/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin"

static wmodule *ciscat_module;
static OS_XML *lxml;
extern int test_mode;

static void wmodule_cleanup(wmodule *module){
    wm_ciscat* module_data = (wm_ciscat *) module->data;
    wm_ciscat_eval *eval = module_data->evals;
    while(eval != 0) {
        wm_ciscat_eval *aux = eval;
        eval = eval->next;
        os_free(aux->profile);
        os_free(aux->path);
        os_free(aux);
    }
    os_free(module_data->ciscat_binary);
    os_free(module_data->ciscat_path);
    os_free(module_data->java_path);
    os_free(module_data);
    os_free(module->tag);
    os_free(module);
}

int __wrap_wm_exec_in_dir(char *command, char **output, int *exitcode, int secs, const char * add_path, const char * work_dir) {
    check_expected(command);
    check_expected(secs);
    check_expected_ptr(add_path);
    check_expected_ptr(work_dir);

    char *out = mock_ptr_type(char *);
    if (out) {
        os_strdup(out, *output);
    }

    *exitcode = mock();
    return mock();
}

/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    ciscat_module = calloc(1, sizeof(wmodule));
    const char *string =
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<interval>3m</interval>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>/var/ossec/wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n"
    ;
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);
    int ret = wm_ciscat_read(lxml, nodes, ciscat_module);
    OS_ClearNode(nodes);
    test_mode = 1;
    return ret;
}

static int teardown_module(){
    test_mode = 0;
    wmodule_cleanup(ciscat_module);
    OS_ClearXML(lxml);
    return 0;
}

static int setup_test_executions() {
    return 0;
}

static int teardown_test_executions(void **state){
    wm_ciscat* module_data = (wm_ciscat *) *state;
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
    wm_ciscat *module_data = (wm_ciscat*)test->module->data;
    if (module_data) {
        os_free(module_data->ciscat_binary);
        sched_scan_free(&(module_data->scan_config));
    }
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}
// A module with a benchmark that exists, so that the evaluation reaches the CIS-CAT command
typedef struct run_state {
    wmodule *module;
    OS_XML xml;
    char bench[PATH_MAX];
} run_state;

static int setup_run(void **state, const char *binary) {
    run_state *run = calloc(1, sizeof(run_state));
    char config[OS_MAXSTR];

    snprintf(run->bench, sizeof(run->bench), "/tmp/ciscat_bench_XXXXXX");
    int fd = mkstemp(run->bench);
    if (fd < 0) {
        free(run);
        return -1;
    }
    close(fd);

    snprintf(config, sizeof(config),
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<interval>1h</interval>\n"
        "<scan-on-start>yes</scan-on-start>\n"
        "<java_path>" TEST_JAVA_DIR "</java_path>\n"
        "<ciscat_path>" TEST_CISCAT_DIR "</ciscat_path>\n"
        "<ciscat_binary>%s</ciscat_binary>\n"
        "<content type=\"xccdf\" path=\"%s\"></content>\n",
        binary, run->bench);

    run->module = calloc(1, sizeof(wmodule));
    XML_NODE nodes = string_to_xml_node(config, &run->xml);
    int ret = wm_ciscat_read(&run->xml, nodes, run->module);
    OS_ClearNode(nodes);
    test_mode = 1;
    *state = run;
    return ret;
}

static int setup_run_v3(void **state) {
    return setup_run(state, WM_CISCAT_V3_BINARY);
}

static int setup_run_v4(void **state) {
    return setup_run(state, WM_CISCAT_V4_BINARY);
}

static int teardown_run(void **state) {
    run_state *run = *state;
    wm_ciscat *module_data = (wm_ciscat *)run->module->data;
    test_mode = 0;
    sched_scan_free(&(module_data->scan_config));
    wmodule_cleanup(run->module);
    OS_ClearXML(&run->xml);
    unlink(run->bench);
    free(run);
    return 0;
}

// Expectations for one evaluation, up to the CIS-CAT command
static void expect_evaluation_start(run_state *run, char *msg, size_t size) {
    expect_wfopen("var/wodles/cis-cat", "rb", NULL);
    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);
    expect_string(__wrap_IsDir, file, TEST_CISCAT_DIR);
    will_return(__wrap_IsDir, 0);
    will_return(__wrap_FOREVER, 0);
    will_return_always(__wrap_os_random, 12345);
    expect_any_always(__wrap__mtinfo, tag);
    expect_any_always(__wrap__mtinfo, formatted_msg);

    snprintf(msg, size, "Starting CIS-CAT scan. File: %s. ", run->bench);
    expect_SendMSG_call(msg, "rootcheck", ROOTCHECK_MQ, 0);
}

static void expect_ciscat_command(const char *work_dir, char *output, int exitcode, int ret) {
    expect_any(__wrap_wm_exec_in_dir, command);
    expect_value(__wrap_wm_exec_in_dir, secs, 1800);
    expect_string(__wrap_wm_exec_in_dir, add_path, TEST_JAVA_DIR);
    if (work_dir) {
        expect_string(__wrap_wm_exec_in_dir, work_dir, work_dir);
    } else {
        expect_value(__wrap_wm_exec_in_dir, work_dir, NULL);
    }
    will_return(__wrap_wm_exec_in_dir, output);
    will_return(__wrap_wm_exec_in_dir, exitcode);
    will_return(__wrap_wm_exec_in_dir, ret);
}

/************************************/

void test_interval_execution(void **state) {
    wm_ciscat* module_data = (wm_ciscat *)ciscat_module->data;
    *state = module_data;
    FILE *fp = NULL;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 120; // 2min
    module_data->scan_config.month_interval = false;

    expect_wfopen("var/wodles/cis-cat", "rb", fp);
    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);
    expect_string(__wrap_IsDir, file, "/var/ossec/wodles/ciscat");
    will_return(__wrap_IsDir, 0);
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    will_return_always(__wrap_os_random, 12345);
    expect_string_count(__wrap__mterror, tag, "wazuh-modulesd:ciscat", TEST_MAX_DATES + 1);
    expect_string_count(__wrap__mterror, formatted_msg, "Benchmark file '/var/ossec/wodles/ciscat/benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml' not found.", TEST_MAX_DATES + 1);
    expect_any_always(__wrap__mtinfo, tag);
    expect_any_always(__wrap__mtinfo, formatted_msg);

    ciscat_module->context->start(module_data);
}

void test_fake_tag(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<time>14:59</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<invalid-tag>laklsdaklsa</invalid-tag>"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "No such tag 'invalid-tag' at module 'cis-cat'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_ciscat_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_scheduling_monthday_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<time>14:59</time>\n"
        "<day>5</day>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one month. New interval value: 1M");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_ciscat_read(&(test->xml), test->nodes, test->module),0);
    wm_ciscat* module_data = (wm_ciscat *)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 5);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "14:59");
}

void test_read_scheduling_weekday_configuration(void** state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<time>23:59</time>\n"
        "<wday>Wednesday</wday>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one week. New interval value: 1w");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_ciscat_read(&(test->xml), test->nodes, test->module),0);
    wm_ciscat* module_data = (wm_ciscat *)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 3);
    assert_string_equal(module_data->scan_config.scan_time, "23:59");
}

void test_read_scheduling_daytime_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<time>11:45</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_ciscat_read(&(test->xml), test->nodes, test->module),0);
    wm_ciscat* module_data = (wm_ciscat *)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "11:45");
}

void test_read_scheduling_interval_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<interval>1h</interval>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_ciscat_read(&(test->xml), test->nodes, test->module),0);
    wm_ciscat* module_data = (wm_ciscat *)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 3600);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
}

// A CIS-CAT Pro V3 evaluation that times out is reported by the module thread, which skips
// reading results that were never written. The command runs from the CIS-CAT directory.
void test_run_timeout_skips_results(void **state) {
    run_state *run = *state;
    wm_ciscat *module_data = (wm_ciscat *)run->module->data;
    char start_msg[OS_MAXSTR];
    char end_msg[OS_MAXSTR];
    char error_msg[OS_MAXSTR];

    expect_evaluation_start(run, start_msg, sizeof(start_msg));
    expect_ciscat_command(TEST_CISCAT_DIR, NULL, 0, WM_ERROR_TIMEOUT);

    snprintf(error_msg, sizeof(error_msg), "Timeout expired executing '%s'.", run->bench);
    expect_string(__wrap__mterror, tag, WM_CISCAT_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, error_msg);

    snprintf(end_msg, sizeof(end_msg), "Ending CIS-CAT scan. File: %s. ", run->bench);
    expect_SendMSG_call(end_msg, "rootcheck", ROOTCHECK_MQ, 0);

    run->module->context->start(module_data);

    assert_int_equal(module_data->evals->flags.error, 0);
}

// A CIS-CAT Pro V4 evaluation that fails is reported with its output. That binary runs from the
// current directory.
void test_run_error_skips_results(void **state) {
    run_state *run = *state;
    wm_ciscat *module_data = (wm_ciscat *)run->module->data;
    char start_msg[OS_MAXSTR];
    char end_msg[OS_MAXSTR];
    char error_msg[OS_MAXSTR];

    expect_evaluation_start(run, start_msg, sizeof(start_msg));
    expect_ciscat_command(NULL, "Java not found", 2, 0);

    snprintf(error_msg, sizeof(error_msg), "Ignoring content '%s' due to error (2).", run->bench);
    expect_string(__wrap__mterror, tag, WM_CISCAT_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, error_msg);
    expect_string(__wrap__mterror, tag, WM_CISCAT_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "OUTPUT: Java not found");

    snprintf(end_msg, sizeof(end_msg), "Ending CIS-CAT scan. File: %s. ", run->bench);
    expect_SendMSG_call(end_msg, "rootcheck", ROOTCHECK_MQ, 0);

    run->module->context->start(module_data);

    assert_int_equal(module_data->evals->flags.error, 0);
}

// A command that could not be run skips reading results, and the evaluation runs again next time.
void test_run_internal_error_keeps_evaluation(void **state) {
    run_state *run = *state;
    wm_ciscat *module_data = (wm_ciscat *)run->module->data;
    char start_msg[OS_MAXSTR];
    char end_msg[OS_MAXSTR];
    char error_msg[OS_MAXSTR];

    expect_evaluation_start(run, start_msg, sizeof(start_msg));
    expect_ciscat_command(TEST_CISCAT_DIR, NULL, 0, -1);

    snprintf(error_msg, sizeof(error_msg), "Internal error executing '%s'.", run->bench);
    expect_string(__wrap__mterror, tag, WM_CISCAT_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, error_msg);

    snprintf(end_msg, sizeof(end_msg), "Ending CIS-CAT scan. File: %s. ", run->bench);
    expect_SendMSG_call(end_msg, "rootcheck", ROOTCHECK_MQ, 0);

    run->module->context->start(module_data);

    assert_int_equal(module_data->evals->flags.error, 0);
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
    const struct CMUnitTest tests_run[] = {
        cmocka_unit_test_setup_teardown(test_run_timeout_skips_results, setup_run_v3, teardown_run),
        cmocka_unit_test_setup_teardown(test_run_error_skips_results, setup_run_v4, teardown_run),
        cmocka_unit_test_setup_teardown(test_run_internal_error_keeps_evaluation, setup_run_v3, teardown_run),
    };
    int result = (cmocka_run_group_tests(tests_with_startup, setup_module, teardown_module) ||
                  cmocka_run_group_tests(tests_without_startup, NULL, NULL) ||
                  cmocka_run_group_tests(tests_run, NULL, NULL));
    return result;
}
