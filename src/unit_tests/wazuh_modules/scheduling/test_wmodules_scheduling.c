/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the scheduling capacities
 * described in 'headers/schedule_scan.h' and
 * 'shared/schedule_scan.c' files
* */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>
#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wmodules_scheduling_helpers.h"

#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/time_op_wrappers.h"

static const int TEST_INTERVAL = 5 * 60;
static const int TEST_DELAY    = 5;
static const int TEST_DAY_MONTHS[] =  {3, 8, 15, 21};

typedef struct state_structure {
    OS_XML lxml;
    sched_scan_config scan_config;
    XML_NODE nodes;
} state_structure;

static int test_setup(void **state) {
    state_structure *test = calloc(1, sizeof(state_structure));
    *state = test;
    sched_scan_init(&test->scan_config);
    current_time = 0;
    return 0;
}

static int test_teardown(void **state) {
    state_structure *test = *state;
    sched_scan_free(&test->scan_config);
    OS_ClearNode(test->nodes);
    OS_ClearXML(&test->lxml);
    free(test);
    current_time = 0;
    return 0;
}

/**
 * Test caclulated time for an INTERVAL with a sleep in
 * between
 * */
static void test_interval_mode(void **state){
    state_structure *test = *state;
    const char *string =
        "<interval>5m</interval>"
    ;
    test->nodes = string_to_xml_node(string, &test->lxml);
    sched_scan_read(&test->scan_config, test->nodes, "");
    time_t next_time = sched_scan_get_time_until_next_scan(&test->scan_config, "TEST_INTERVAL_MODE", 0);
    // First time
    assert_int_equal((int) next_time, TEST_INTERVAL);
    // Sleep 5 secs
    w_time_delay(1000 * TEST_INTERVAL);
    next_time = sched_scan_get_time_until_next_scan(&test->scan_config, "TEST_INTERVAL_MODE", 0);
    assert_int_equal((int) next_time, TEST_INTERVAL);
}


/**
 * Test day of the month mode for different day values
 * */
static void test_day_of_the_month_mode(void **state){
    state_structure *test = *state;
    // Set day of the month
    test->scan_config.month_interval = true;
    test->scan_config.interval = 1;
    test->scan_config.scan_time = strdup("00:00");

    for(int i = 0; i < (sizeof(TEST_DAY_MONTHS)/ sizeof(int)); i++){
        test->scan_config.scan_day = TEST_DAY_MONTHS[i];

        time_t time_sleep = sched_scan_get_time_until_next_scan(&test->scan_config, "TEST_DAY_MONTH_MODE", 0);
        time_t next_time = time(NULL) + time_sleep;

        struct tm *date = localtime(&next_time);
        // Assert execution time is the expected month day
        assert_int_equal(date->tm_mday,  TEST_DAY_MONTHS[i]);
    }
}

/**
 * Test 2 consecutive day of the month
 * */
static void test_day_of_the_month_consecutive(void **state){
    state_structure *test = *state;
    const char *string =
        "<day>20</day>\n"
        "<time>0:00</time>"
    ;

    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one month. New interval value: 1M");

    test->nodes = string_to_xml_node(string, &test->lxml);
    sched_scan_read(&test->scan_config, test->nodes, "");
    // Set to 2 months
    test->scan_config.interval = 2;

    time_t time_sleep = sched_scan_get_time_until_next_scan(&test->scan_config, "TEST_DAY_MONTH_MODE", 0);
    // Sleep past execution moment by 1 hour
    w_time_delay(time_sleep * 1000);

    time_t first_time = time(NULL) ;
    struct tm first_date = *(localtime(&first_time));
    // Assert execution time is the expected month day
    assert_int_equal(first_date.tm_mday,  test->scan_config.scan_day);

    time_sleep = sched_scan_get_time_until_next_scan(&test->scan_config, "TEST_DAY_MONTH_MODE", 0);
    time_t second_time = time(NULL) + time_sleep;

    struct tm second_date = *(localtime(&second_time));

    assert_int_equal(second_date.tm_mday, test->scan_config.scan_day);
    // Check it is following month
    assert_int_equal((first_date.tm_mon + test->scan_config.interval) % 12, second_date.tm_mon);
}

/**
 * Test 1 day of the week
 * */
static void test_day_of_the_week(void **state){
    state_structure *test = *state;
    const char *string =
        "<wday>tuesday</wday>\n"
        "<time>0:00</time>\n"
        "<interval>3w</interval>\n"
    ;
    test->nodes = string_to_xml_node(string, &test->lxml);
    sched_scan_read(&test->scan_config, test->nodes, "");

    time_t time_sleep = sched_scan_get_time_until_next_scan(&test->scan_config, "TEST_WDAY_MODE", 0);
    // Sleep past execution moment by 1 hour
    w_time_delay((time_sleep + 3600) * 1000);

    time_t first_time = time(NULL);
    struct tm first_date = *(localtime(&first_time));

    assert_int_equal(first_date.tm_wday,  test->scan_config.scan_wday);

    time_sleep = sched_scan_get_time_until_next_scan(&test->scan_config, "TEST_WDAY_MODE", 0);
    time_t second_time = time(NULL) + time_sleep;

    struct tm second_date = *(localtime(&second_time));
    assert_int_equal(second_date.tm_wday,  test->scan_config.scan_wday);
    assert_int_equal(second_date.tm_yday, (first_date.tm_yday + 21) % 365);
}

/**
 * Test time of day execution
 * */
static void test_time_of_day(void **state){
    state_structure *test = *state;
    const char *string =
        "<time>5:18</time>"
    ;
    test->nodes = string_to_xml_node(string, &test->lxml);
    sched_scan_read(&test->scan_config, test->nodes, "");
    time_t time_sleep = sched_scan_get_time_until_next_scan(&test->scan_config, "TEST_WDAY_MODE", 0);
    w_time_delay(time_sleep * 1000);

    time_t aux_time = time(NULL);
    struct tm date = *(localtime(&aux_time));

    assert_int_equal(date.tm_hour, 5);
    assert_int_equal(date.tm_min, 18);
}

/**
 * Test Parsing and dumping of configurations
 * */
static void test_parse_xml_and_dump(void **state){
    state_structure *test = *state;
    const char *string =
    "<wday>friday</wday>\n"
    "<time>13:14</time>";
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one week. New interval value: 1w");
    test->nodes = string_to_xml_node(string, &test->lxml);
    sched_scan_read(&test->scan_config, test->nodes, "");
    cJSON *data = cJSON_CreateObject();
    sched_scan_dump(&test->scan_config, data);
    char *result_str = cJSON_PrintUnformatted(data);
    assert_string_equal(result_str, "{\"interval\":604800,\"wday\":\"friday\",\"time\":\"13:14\"}");
    cJSON_Delete(data);
    free(result_str);
}


/**
 * Test month day calculation when close to end of year
 * */
static void test_day_of_month_wrap_year(void **state) {
    state_structure *test = *state;
    test->scan_config.month_interval = true;
    test->scan_config.interval = 2;
    test->scan_config.scan_day = 5;
    test->scan_config.scan_time = strdup("00:00");

    time_t aux_time = time(NULL);
    struct tm tm = *(localtime(&aux_time));
    tm.tm_mon = 11;
    tm.tm_mday = 5; // 5th of December
    // Set simulation time
    set_current_time(mktime(&tm));

    time_t time_sleep = sched_scan_get_time_until_next_scan(&test->scan_config, "TEST_DAY_MONTH_MODE", 0);
    w_time_delay(time_sleep * 1000);

    time_t first_time = time(NULL) ;
    struct tm first_date = *(localtime(&first_time));
    // Assert execution time is the expected month day
    assert_int_equal(first_date.tm_mday,  test->scan_config.scan_day);
    assert_int_equal(first_date.tm_mon, 1);
    assert_int_equal(first_date.tm_year, tm.tm_year + 1);
}

static void test_day_of_month_very_long_time(void **state) {
    state_structure *test = *state;
    test->scan_config.month_interval = true;
    test->scan_config.interval = 25; // 25 months interval
    test->scan_config.scan_day = 1;
    test->scan_config.scan_time = strdup("00:00");

    time_t aux_time = time(NULL);
    struct tm tm = *(localtime(&aux_time));
    tm.tm_mon = 10;
    tm.tm_mday = 1; // 1st of November
    // Set simulation time
    set_current_time(mktime(&tm));

    time_t time_sleep = sched_scan_get_time_until_next_scan(&test->scan_config, "TEST_DAY_MONTH_MODE", 0);
    w_time_delay(time_sleep * 1000);

    time_t first_time = time(NULL) ;
    struct tm first_date = *(localtime(&first_time));
    // Assert execution time is the expected month day
    assert_int_equal(first_date.tm_mday,  test->scan_config.scan_day);
    assert_int_equal(first_date.tm_mon, 11);
    assert_int_equal(first_date.tm_year, tm.tm_year + 2);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_interval_mode, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_day_of_the_month_mode, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_day_of_the_month_consecutive, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_day_of_the_week, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_time_of_day, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_parse_xml_and_dump, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_day_of_month_wrap_year, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_day_of_month_very_long_time, test_setup, test_teardown)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
