/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the scheduling capacities
 * for docker Module
 * */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>

#include "shared.h"
#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/exec_op_wrappers.h"
#include "../../wrappers/posix/signal_wrappers.h"
#include "wmodules.h"
#include "wm_docker.h"
#include "../scheduling/wmodules_scheduling_helpers.h"

#define TEST_MAX_DATES 5

static wmodule *docker_module;
static OS_XML *lxml;
extern int test_mode;

typedef struct {
    wfd_t * wfd;
    wm_docker_t* module_data;
} states;

/******* Children pool wrappers **********/

/* Permissive on purpose: the pool itself is not what these tests check, and
 * cmocka expectations here would have to be replicated in every case that
 * launches a listener. */

static pid_t appended_sid = -1;
static bool stop_on_append = false;
static bool flag_only_on_append = false;

void __wrap_wm_append_sid(pid_t sid) {
    appended_sid = sid;

    if (stop_on_append) {
        /* Simulate SIGTERM reaching wazuh-modulesd while the listener runs:
         * wm_handler() raises the shutdown flag and then calls every module's
         * stop() callback, in that order. */
        stop_on_append = false;
        wm_shutdown_requested = 1;
        WM_DOCKER_CONTEXT.stop(docker_module->data);
    } else if (flag_only_on_append) {
        /* Simulate the losing interleaving: wm_handler() raised the flag and
         * ran stop() while this thread was still launching, so stop() read a
         * PID of zero and signalled nothing. */
        flag_only_on_append = false;
        wm_shutdown_requested = 1;
    }
}

void __wrap_wm_remove_sid(__attribute__((unused)) pid_t sid) {
}

/******* Helpers **********/

static void wmodule_cleanup(wmodule *module){
    free(module->data);
    free(module->tag);
    free(module);
}

/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    docker_module = calloc(1, sizeof(wmodule));
    const char *string =
        "<interval>10m</interval>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n";
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);
    int ret = wm_docker_read(nodes, docker_module);
    OS_ClearNode(nodes);
    test_mode = 1;
    wm_children_pool_init();
    return ret;
}

static int teardown_module(){
    test_mode = 0;
    wmodule_cleanup(docker_module);
    OS_ClearXML(lxml);
    return 0;
}

static int setup_test_executions(void **state) {
    states *states_ptr = calloc(1, sizeof(*states_ptr));
    states_ptr->wfd = calloc(1, sizeof(wfd_t));
    *state = states_ptr;
    wm_max_eps = 1;

    return 0;
}

static int teardown_test_executions(void **state){
    states *states_ptr = *state;
    wm_docker_t* module_data = states_ptr->module_data;
    sched_scan_free(&(module_data->scan_config));

    free(states_ptr->wfd);
    free(states_ptr);
    return 0;
}

static int teardown_test_shutdown(void **state) {
    wm_shutdown_requested = 0;
    stop_on_append = false;
    flag_only_on_append = false;
    appended_sid = -1;
    return teardown_test_executions(state);
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
    wm_docker_t *module_data = (wm_docker_t*)test->module->data;
    sched_scan_free(&(module_data->scan_config));
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}

/****************************************************************/

/** Tests **/
void test_interval_execution(void **state) {
    states *states_ptr = *state;
    wm_docker_t* module_data = (wm_docker_t *)docker_module->data;
    wfd_t * wfd = states_ptr->wfd;

    states_ptr->module_data = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 60 * 25; // 25min
    module_data->scan_config.month_interval = false;

    will_return_count(__wrap_wpopenl, wfd, TEST_MAX_DATES + 1);
    will_return_count(__wrap_wpclose, 0, TEST_MAX_DATES + 1);
    expect_any_count(__wrap_fgets, __stream, TEST_MAX_DATES + 1);
    will_return_count(__wrap_fgets, 0, TEST_MAX_DATES + 1);
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    expect_any_always(__wrap__mtinfo, tag);
    expect_any_always(__wrap__mtinfo, formatted_msg);
    expect_any_always(__wrap__mtwarn, tag);
    expect_any_always(__wrap__mtwarn, formatted_msg);

    docker_module->context->start(module_data);
}

void test_docker_context_has_stop(__attribute__((unused)) void **state) {
    /* Without a stop() callback the module thread stays blocked reading the
     * listener's output and the child outlives the agent. */
    assert_non_null(WM_DOCKER_CONTEXT.stop);
}

void test_docker_stop_without_child_is_noop(__attribute__((unused)) void **state) {
    /* No listener running, so no signal must be sent. An unexpected call to
     * kill() fails the test. */
    WM_DOCKER_CONTEXT.stop(NULL);
}

void test_docker_stop_signals_child(void **state) {
    states *states_ptr = *state;
    wm_docker_t* module_data = (wm_docker_t *)docker_module->data;
    wfd_t * wfd = states_ptr->wfd;

    states_ptr->module_data = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 60 * 25; // 25min
    module_data->scan_config.month_interval = false;

    wfd->pid = 4242;
    stop_on_append = true;

    will_return(__wrap_wpopenl, wfd);

    /* Four signals: the listener is terminated by its process group, which
     * wpopenv() makes equal to its PID by calling setsid() in the child, and by
     * its PID, which works even before setsid() has run. That pair comes once
     * from stop() and once more from the module's own re-check of the shutdown
     * flag after arming, which cannot know stop() already ran. Signalling a
     * process that is already dying is harmless. */
    for (int i = 0; i < 2; i++) {
        expect_value(__wrap_kill, pid, -4242);
        expect_value(__wrap_kill, sig, SIGTERM);
        will_return(__wrap_kill, 0);
        expect_value(__wrap_kill, pid, 4242);
        expect_value(__wrap_kill, sig, SIGTERM);
        will_return(__wrap_kill, 0);
    }

    // Terminating the child closes the pipe, so fgets() returns and the module
    // reaps it.
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, 0);
    will_return(__wrap_wpclose, 0);

    expect_any_always(__wrap__mtinfo, tag);
    expect_any_always(__wrap__mtinfo, formatted_msg);

    /* No __wrap_FOREVER value is queued and no warning is expected: the loop
     * must leave through the shutdown check, not through the retry path that
     * reports the listener as having finished unexpectedly. */

    docker_module->context->start(module_data);

    assert_int_equal(appended_sid, 4242);

    /* The listener has been reaped, so the module must no longer hold it as a
     * signal target. An unexpected call to kill() fails the test. */
    WM_DOCKER_CONTEXT.stop(module_data);
}

void test_docker_shutdown_during_launch_kills_child(void **state) {
    states *states_ptr = *state;
    wm_docker_t* module_data = (wm_docker_t *)docker_module->data;
    wfd_t * wfd = states_ptr->wfd;

    states_ptr->module_data = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 60 * 25; // 25min
    module_data->scan_config.month_interval = false;

    wfd->pid = 5150;
    flag_only_on_append = true;

    will_return(__wrap_wpopenl, wfd);

    // stop() ran before this thread published the PID and signalled nothing,
    // so the module has to terminate the listener itself.
    expect_value(__wrap_kill, pid, -5150);
    expect_value(__wrap_kill, sig, SIGTERM);
    will_return(__wrap_kill, 0);
    expect_value(__wrap_kill, pid, 5150);
    expect_value(__wrap_kill, sig, SIGTERM);
    will_return(__wrap_kill, 0);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, 0);
    will_return(__wrap_wpclose, 0);

    expect_any_always(__wrap__mtinfo, tag);
    expect_any_always(__wrap__mtinfo, formatted_msg);

    docker_module->context->start(module_data);

    assert_int_equal(appended_sid, 5150);
}

void test_fake_tag(void **state) {
    const char *string =
        "<time>19:55</time>\n"
        "<interval>10m</interval>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n"
        "<extra-tag>extra</extra-tag>\n";
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "No such tag 'extra-tag' at module 'docker-listener'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_docker_read(test->nodes, test->module),-1);
}

void test_read_scheduling_monthday_configuration(void **state) {
    const char *string =
        "<time>19:55</time>\n"
        "<day>10</day>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one month. New interval value: 1M");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_docker_read(test->nodes, test->module),0);
    wm_docker_t *module_data = (wm_docker_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 10);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "19:55");
}

void test_read_scheduling_weekday_configuration(void **state) {
    const char *string =
        "<time>18:55</time>\n"
        "<wday>Thursday</wday>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one week. New interval value: 1w");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_docker_read(test->nodes, test->module),0);
    wm_docker_t *module_data = (wm_docker_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 4);
    assert_string_equal(module_data->scan_config.scan_time, "18:55");
}

void test_read_scheduling_daytime_configuration(void **state) {
    const char *string =
        "<time>17:20</time>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one day. New interval value: 1d");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_docker_read(test->nodes, test->module),0);
    wm_docker_t *module_data = (wm_docker_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "17:20");
}

void test_read_scheduling_interval_configuration(void **state) {
    const char *string =
        "<interval>1d</interval>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_docker_read(test->nodes, test->module),0);
    wm_docker_t *module_data = (wm_docker_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL); // 1 day
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
}

int main(void) {
    const struct CMUnitTest tests_with_startup[] = {
        cmocka_unit_test_setup_teardown(test_interval_execution, setup_test_executions, teardown_test_executions),
        cmocka_unit_test_setup_teardown(test_docker_stop_signals_child, setup_test_executions, teardown_test_shutdown),
        cmocka_unit_test_setup_teardown(test_docker_shutdown_during_launch_kills_child, setup_test_executions, teardown_test_shutdown)
    };
    const struct CMUnitTest tests_without_startup[] = {
        cmocka_unit_test(test_docker_context_has_stop),
        cmocka_unit_test(test_docker_stop_without_child_is_noop),
        cmocka_unit_test_setup_teardown(test_fake_tag, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_monthday_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_weekday_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_daytime_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_interval_configuration, setup_test_read, teardown_test_read),
    };
    int result;
    result = cmocka_run_group_tests(tests_with_startup, setup_module, teardown_module);
    result += cmocka_run_group_tests(tests_without_startup, NULL, NULL);
    return result;
}
