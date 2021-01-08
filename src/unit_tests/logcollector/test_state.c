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
#include <time.h>


#include "../../headers/shared.h"
#include "../../logcollector/state.c"


#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"

// selfcontained
void w_logcollector_state_init();
char * w_logcollector_state_get();
cJSON * _w_logcollector_generate_state(lc_states_t * state, bool restart);
void _w_logcollector_state_update_file(lc_states_t * state, char * fpath, uint64_t bytes);

/* setup/teardown */

static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}

/* wraps */
time_t __wrap_time(time_t * t) {
    return mock_type(time_t);
}

char * __wrap_ctime (const time_t *__timer) {
    return mock_type(char *);
}

/* tests */

// w_logcollector_state_init
void test_w_logcollector_state_init_fail_hash_create_global(void ** state) {

    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);

    will_return(__wrap_time, (time_t) 50);
    will_return(__wrap_time, (time_t) 51);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, NULL);

    expect_string(__wrap__merror_exit, formatted_msg, "(1296): Unable to create a 'logcollector_state' hash table");

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);
    will_return(__wrap_OSHash_setSize, 1);
    will_return(__wrap_OSHash_setSize, 1);

    w_logcollector_state_init();

    assert_non_null(g_lc_states_global);
    assert_non_null(g_lc_states_interval);

    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);
}

void test_w_logcollector_state_init_fail_hash_create_interval(void ** state) {

    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);

    will_return(__wrap_time, (time_t) 50);
    will_return(__wrap_time, (time_t) 51);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 2);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, NULL);
    expect_string(__wrap__merror_exit, formatted_msg, "(1296): Unable to create a 'logcollector_state' hash table");

    will_return(__wrap_OSHash_setSize, 1);
    will_return(__wrap_OSHash_setSize, 1);

    w_logcollector_state_init();

    assert_non_null(g_lc_states_global);
    assert_non_null(g_lc_states_interval);

    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);
}

void test_w_logcollector_state_init_fail_hash_setsize_global(void ** state) {

    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);

    will_return(__wrap_time, (time_t) 50);
    will_return(__wrap_time, (time_t) 51);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 2);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 3);

    will_return(__wrap_OSHash_setSize, 0);
    expect_string(__wrap__merror_exit, formatted_msg, "(1297): Unable to set size of 'logcollector_state' hash table");

    will_return(__wrap_OSHash_setSize, 1);

    w_logcollector_state_init();

    assert_non_null(g_lc_states_global);
    assert_non_null(g_lc_states_interval);

    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);
}

void test_w_logcollector_state_init_fail_hash_setsize_interval(void ** state) {

    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);

    will_return(__wrap_time, (time_t) 50);
    will_return(__wrap_time, (time_t) 51);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);
    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 1);

    will_return(__wrap_OSHash_setSize, 1);
    will_return(__wrap_OSHash_setSize, 0);
    expect_string(__wrap__merror_exit, formatted_msg, "(1297): Unable to set size of 'logcollector_state' hash table");

    w_logcollector_state_init();

    assert_non_null(g_lc_states_global);
    assert_non_null(g_lc_states_interval);

    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);
}

void test_w_logcollector_state_init_ok(void ** state) {

    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);

    will_return(__wrap_time, (time_t) 50);
    will_return(__wrap_time, (time_t) 51);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 2);
    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 3);

    will_return(__wrap_OSHash_setSize, 1);
    will_return(__wrap_OSHash_setSize, 1);

    w_logcollector_state_init();

    assert_non_null(g_lc_states_global);
    assert_non_null(g_lc_states_interval);

    assert_ptr_equal(g_lc_states_global->states, 2);
    assert_int_equal(g_lc_states_global->start, 50);
    assert_ptr_equal(g_lc_states_interval->states, 3);
    assert_int_equal(g_lc_states_interval->start, 51);

    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);
}

// w_logcollector_state_get_null
void test_w_logcollector_state_get_null(void ** state) {

    os_free(g_lc_pritty_stats);
    assert_null(w_logcollector_state_get());
}

void test_w_logcollector_state_get_non_null(void ** state) {

    os_free(g_lc_pritty_stats);
    g_lc_pritty_stats = strdup("hi!");

    char * retval = w_logcollector_state_get();

    assert_string_equal("hi!", retval);

    os_free(retval);
    os_free(g_lc_pritty_stats);
}

// Test _w_logcollector_generate_state
void test__w_logcollector_generate_state_fail_get_node(void ** state) {

    lc_states_t stats = {.states = (OSHash *) 2};
    cJSON * retval;
    expect_value(__wrap_OSHash_Begin, self, stats.states);
    will_return(__wrap_OSHash_Begin, NULL);

    retval = _w_logcollector_generate_state(&stats, 0);
    assert_null(retval);
}

void test__w_logcollector_generate_state_one_target(void ** state) {

    cJSON * retval;
    lc_states_t stats = {.states = (OSHash *) 2};
    lc_state_target_t target = {.drops = 10, .name = "sock1"};
    lc_state_target_t * target_array[2] = {&target, NULL};

    lc_state_file_t data = {.targets = (lc_state_target_t **) &target_array, .bytes = 100, .events = 5};
    OSHashNode hash_node = {.data = &data, .key = "key_test"};

    expect_value(__wrap_OSHash_Begin, self, stats.states);
    will_return(__wrap_OSHash_Begin, &hash_node);

    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);
    will_return_always(__wrap_cJSON_AddItemToArray, true);
    will_return_always(__wrap_cJSON_AddItemToObject, true);

    will_return_always(__wrap_cJSON_CreateObject, (cJSON *) 10);
    will_return_always(__wrap_cJSON_CreateArray, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "sock1");

    expect_string(__wrap_cJSON_AddNumberToObject, name, "drops");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 10);

    expect_function_call(__wrap_cJSON_AddItemToArray);

    expect_function_call(__wrap_cJSON_AddItemToObject);

    expect_string(__wrap_cJSON_AddStringToObject, name, "location");
    expect_string(__wrap_cJSON_AddStringToObject, string, "key_test");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "bytes");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 100);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "events");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 5);

    expect_function_call(__wrap_cJSON_AddItemToArray);

    expect_value(__wrap_OSHash_Next, self, stats.states);
    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_time, (time_t) 0);
    will_return(__wrap_ctime, "Fri Jan  8 04:31:29 AM -03 2021\n");
    will_return(__wrap_ctime, "Fri Jan  8 03:31:29 AM -03 2021\n");

    expect_string(__wrap_cJSON_AddStringToObject, name, "start");
    expect_string(__wrap_cJSON_AddStringToObject, string, "Fri Jan  8 03:31:29 AM -03 2021");

    expect_string(__wrap_cJSON_AddStringToObject, name, "end");
    expect_string(__wrap_cJSON_AddStringToObject, string, "Fri Jan  8 04:31:29 AM -03 2021");

    expect_function_call(__wrap_cJSON_AddItemToObject);

    retval = _w_logcollector_generate_state(&stats, false);
    assert_ptr_equal(retval, (cJSON *) 10);
    assert_int_equal(data.bytes, 100);
    assert_int_equal(data.events, 5);
}

void test__w_logcollector_generate_state_one_target_restart(void ** state) {

    cJSON * retval;
    lc_states_t stats = {.states = (OSHash *) 2, .start = (time_t) 2020};
    lc_state_target_t target = {.drops = 10, .name = "sock1"};
    lc_state_target_t * target_array[2] = {&target, NULL};

    lc_state_file_t data = {.targets = (lc_state_target_t **) &target_array, .bytes = 100, .events = 5};
    OSHashNode hash_node = {.data = &data, .key = "key_test"};

    expect_value(__wrap_OSHash_Begin, self, stats.states);
    will_return(__wrap_OSHash_Begin, &hash_node);

    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);
    will_return_always(__wrap_cJSON_AddItemToArray, true);
    will_return_always(__wrap_cJSON_AddItemToObject, true);

    will_return_always(__wrap_cJSON_CreateObject, (cJSON *) 10);
    will_return_always(__wrap_cJSON_CreateArray, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "sock1");

    expect_string(__wrap_cJSON_AddNumberToObject, name, "drops");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 10);

    expect_function_call(__wrap_cJSON_AddItemToArray);

    expect_function_call(__wrap_cJSON_AddItemToObject);

    expect_string(__wrap_cJSON_AddStringToObject, name, "location");
    expect_string(__wrap_cJSON_AddStringToObject, string, "key_test");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "bytes");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 100);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "events");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 5);

    expect_function_call(__wrap_cJSON_AddItemToArray);

    expect_value(__wrap_OSHash_Next, self, stats.states);
    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_time, (time_t) 0);
    will_return(__wrap_ctime, "Fri Jan  8 04:31:29 AM -03 2021\n");
    will_return(__wrap_ctime, "Fri Jan  8 03:31:29 AM -03 2021\n");

    expect_string(__wrap_cJSON_AddStringToObject, name, "start");
    expect_string(__wrap_cJSON_AddStringToObject, string, "Fri Jan  8 03:31:29 AM -03 2021");

    expect_string(__wrap_cJSON_AddStringToObject, name, "end");
    expect_string(__wrap_cJSON_AddStringToObject, string, "Fri Jan  8 04:31:29 AM -03 2021");

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_time, (time_t) 2525);

    retval = _w_logcollector_generate_state(&stats, true);
    assert_ptr_equal(retval, (cJSON *) 10);
    assert_int_equal(data.bytes, 0);
    assert_int_equal(data.events, 0);
    assert_int_equal(stats.start, 2525);
}

// Test _w_logcollector_state_update_file
void test__w_logcollector_state_update_file_new_data(void ** state) {

    lc_states_t stat;

    expect_value(__wrap_OSHash_Get, self, stat.states);
    expect_string(__wrap_OSHash_Get, key, "/test_path");
    will_return(__wrap_OSHash_Get, NULL);

    will_return(__wrap_OSHash_Update, 0);

    expect_value(__wrap_OSHash_Add, key, "/test_path");
    will_return(__wrap_OSHash_Add, 0);

    _w_logcollector_state_update_file(&stat, "/test_path", 100);
}

void test__w_logcollector_state_update_file_update(void ** state) {
    
    lc_states_t stat;
    lc_state_file_t data = {0};

    expect_value(__wrap_OSHash_Get, self, stat.states);
    expect_string(__wrap_OSHash_Get, key, "/test_path");
    will_return(__wrap_OSHash_Get, &data);

    will_return(__wrap_OSHash_Update, 1);

    _w_logcollector_state_update_file(&stat, "/test_path", 100);

    assert_int_equal(data.bytes, 100);
    assert_int_equal(data.events, 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Tests w_logcollector_state_init
        cmocka_unit_test(test_w_logcollector_state_init_fail_hash_create_global),
        cmocka_unit_test(test_w_logcollector_state_init_fail_hash_create_interval),
        cmocka_unit_test(test_w_logcollector_state_init_fail_hash_setsize_global),
        cmocka_unit_test(test_w_logcollector_state_init_fail_hash_setsize_interval),
        cmocka_unit_test(test_w_logcollector_state_init_ok),

        // Tests w_logcollector_state_get
        cmocka_unit_test(test_w_logcollector_state_get_null), cmocka_unit_test(test_w_logcollector_state_get_non_null),

        // Tests _w_logcollector_generate_state
        cmocka_unit_test(test__w_logcollector_generate_state_fail_get_node),
        cmocka_unit_test(test__w_logcollector_generate_state_one_target),
        cmocka_unit_test(test__w_logcollector_generate_state_one_target_restart),

        // Tests _w_logcollector_state_update_file
        cmocka_unit_test(test__w_logcollector_state_update_file_new_data),
        cmocka_unit_test(test__w_logcollector_state_update_file_update),

    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
