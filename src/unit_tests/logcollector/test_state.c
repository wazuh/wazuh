/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include "../../logcollector/state.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/posix/pthread_wrappers.h"

void w_logcollector_state_init(w_lc_state_type_t state_type, bool state_file_enabled);
cJSON * w_logcollector_state_get();
cJSON * _w_logcollector_generate_state(w_lc_state_storage_t * state, bool restart);
void _w_logcollector_state_update_file(w_lc_state_storage_t * state, char * fpath, uint64_t bytes);
void w_logcollector_state_update_file(char * fpath, uint64_t bytes);
void _w_logcollector_state_update_target(w_lc_state_storage_t * state, char * fpath, char * target, bool dropped);
void w_logcollector_state_update_target(char * fpath, char * target, bool dropped);
void w_logcollector_state_generate();
void w_logcollector_state_dump();
void * w_logcollector_state_main(__attribute__((unused)) void * args);
void _w_logcollector_state_delete_file(w_lc_state_storage_t * state, char * fpath);
void w_logcollector_state_delete_file(char * fpath);

extern cJSON * g_lc_json_stats;
extern w_lc_state_storage_t * g_lc_states_global;
extern w_lc_state_storage_t * g_lc_states_interval;
extern w_lc_state_type_t g_lc_state_type;

/* setup/teardown */

static int setup_group(void ** state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void ** state) {
    test_mode = 0;
    return 0;
}

static int setup_global(void ** state) {
    char **array = calloc(10, sizeof(char*));

    if(array == NULL)
        return -1;

    *state = array;

    return 0;
}

static int teardown_global(void ** state) {

    return 0;
}

/* wraps */
size_t __wrap_strftime(char *s, size_t max, const char *format,
                       const struct tm *tm) {
    strncpy(s, mock_type(char *), max);
    return mock();
}

/* tests */

/* w_logcollector_state_init */
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

    w_logcollector_state_init(LC_STATE_GLOBAL|LC_STATE_INTERVAL, true);

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

    w_logcollector_state_init(LC_STATE_GLOBAL|LC_STATE_INTERVAL, true);

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

    w_logcollector_state_init(LC_STATE_GLOBAL|LC_STATE_INTERVAL, true);

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

    w_logcollector_state_init(LC_STATE_GLOBAL|LC_STATE_INTERVAL, true);

    assert_non_null(g_lc_states_global);
    assert_non_null(g_lc_states_interval);

    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);
}

void test_w_logcollector_state_init_ok(void ** state) {

    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);
    g_lc_state_type = 0;

    will_return(__wrap_time, (time_t) 50);
    will_return(__wrap_time, (time_t) 51);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 2);
    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, 3);

    will_return(__wrap_OSHash_setSize, 1);
    will_return(__wrap_OSHash_setSize, 1);

    w_logcollector_state_init(LC_STATE_GLOBAL | LC_STATE_INTERVAL, true);

    assert_non_null(g_lc_states_global);
    assert_non_null(g_lc_states_interval);

    assert_ptr_equal(g_lc_states_global->states, 2);
    assert_int_equal(g_lc_states_global->start, 50);
    assert_ptr_equal(g_lc_states_interval->states, 3);
    assert_int_equal(g_lc_states_interval->start, 51);
    assert_int_equal(g_lc_state_type, LC_STATE_GLOBAL | LC_STATE_INTERVAL);

    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);
}


void test_w_logcollector_state_get_null(void ** state) {
    g_lc_state_type = LC_STATE_INTERVAL;
    g_lc_json_stats = NULL;
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    assert_null(w_logcollector_state_get());
}

void test_w_logcollector_state_get_non_null(void ** state) {

    cJSON * expect_retval = (cJSON *) 3;
    g_lc_state_type = LC_STATE_GLOBAL | LC_STATE_INTERVAL;
    g_lc_json_stats = (cJSON *) 5;

    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_cJSON_Duplicate, expect_retval);
    expect_function_call(__wrap_pthread_mutex_unlock);

    cJSON * retval = w_logcollector_state_get();

    assert_ptr_not_equal(g_lc_json_stats, retval);
    assert_ptr_equal(expect_retval, retval);
}

/* Test _w_logcollector_generate_state */
void test__w_logcollector_generate_state_fail_get_node(void ** state) {

    w_lc_state_storage_t stats = {.states = (OSHash *) 2};
    cJSON * retval;
    expect_value(__wrap_OSHash_Begin, self, stats.states);
    will_return(__wrap_OSHash_Begin, NULL);

    retval = _w_logcollector_generate_state(&stats, 0);
    assert_null(retval);
}

void test__w_logcollector_generate_state_one_target(void ** state) {

    cJSON * retval;
    w_lc_state_storage_t stats = {.states = (OSHash *) 2 , };
    w_lc_state_target_t target = {.drops = 10, .name = "sock1"};
    w_lc_state_target_t * target_array[2] = {&target, NULL};

    w_lc_state_file_t data = {.targets = (w_lc_state_target_t **) &target_array, .bytes = 100, .events = 5};
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


    expect_string(__wrap_cJSON_AddStringToObject, name, "location");
    expect_string(__wrap_cJSON_AddStringToObject, string, "key_test");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "events");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 5);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "bytes");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 100);

    expect_function_call(__wrap_cJSON_AddItemToObject);

    expect_function_call(__wrap_cJSON_AddItemToArray);

    expect_value(__wrap_OSHash_Next, self, stats.states);
    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_strftime,"2019-02-05 12:18:37");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap_cJSON_AddStringToObject, name, "start");
    expect_string(__wrap_cJSON_AddStringToObject, string, "2019-02-05 12:18:37");

    will_return(__wrap_time, (time_t) 2525);
    will_return(__wrap_strftime,"2019-02-05 12:18:42");
    will_return(__wrap_strftime, 20);
    expect_string(__wrap_cJSON_AddStringToObject, name, "end");
    expect_string(__wrap_cJSON_AddStringToObject, string, "2019-02-05 12:18:42");

    expect_function_call(__wrap_cJSON_AddItemToObject);

    retval = _w_logcollector_generate_state(&stats, false);
    assert_ptr_equal(retval, (cJSON *) 10);
    assert_int_equal(data.bytes, 100);
    assert_int_equal(data.events, 5);
}

void test__w_logcollector_generate_state_one_target_restart(void ** state) {

    cJSON * retval;
    w_lc_state_storage_t stats = {.states = (OSHash *) 2, .start = (time_t) 2020};
    w_lc_state_target_t target = {.drops = 10, .name = "sock1"};
    w_lc_state_target_t * target_array[2] = {&target, NULL};

    w_lc_state_file_t data = {.targets = (w_lc_state_target_t **) &target_array, .bytes = 100, .events = 5};
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

    expect_string(__wrap_cJSON_AddStringToObject, name, "location");
    expect_string(__wrap_cJSON_AddStringToObject, string, "key_test");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "events");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 5);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "bytes");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 100);

    expect_function_call(__wrap_cJSON_AddItemToObject);

    expect_function_call(__wrap_cJSON_AddItemToArray);

    expect_value(__wrap_OSHash_Next, self, stats.states);
    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_strftime,"2019-02-05 12:18:37");
    will_return(__wrap_strftime, 20);
    expect_string(__wrap_cJSON_AddStringToObject, name, "start");
    expect_string(__wrap_cJSON_AddStringToObject, string, "2019-02-05 12:18:37");

    will_return(__wrap_time, (time_t) 2525);
    will_return(__wrap_strftime,"2019-02-05 12:18:42");
    will_return(__wrap_strftime, 20);;
    expect_string(__wrap_cJSON_AddStringToObject, name, "end");
    expect_string(__wrap_cJSON_AddStringToObject, string, "2019-02-05 12:18:42");

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_time, (time_t) 2525);

    retval = _w_logcollector_generate_state(&stats, true);

    assert_ptr_equal(retval, (cJSON *) 10);
    assert_int_equal(data.bytes, 0);
    assert_int_equal(data.events, 0);
    assert_int_equal(stats.start, 2525);
}

/* Test _w_logcollector_state_update_file */
void test__w_logcollector_state_update_file_new_data(void ** state) {

    w_lc_state_storage_t stat = {0};
    stat.states = (OSHash *) 2;

    expect_value(__wrap_OSHash_Get, self, stat.states);
    expect_string(__wrap_OSHash_Get, key, "/test_path");
    will_return(__wrap_OSHash_Get, NULL);

    will_return(__wrap_OSHash_Update, 0);

    expect_value(__wrap_OSHash_Add, key, "/test_path");
    will_return(__wrap_OSHash_Add, 2);

    _w_logcollector_state_update_file(&stat, "/test_path", 100);
}

void test__w_logcollector_state_update_file_update(void ** state) {

    w_lc_state_storage_t stat = {0};
    stat.states = (OSHash *) 2;
    w_lc_state_file_t data = {0};

    expect_value(__wrap_OSHash_Get, self, stat.states);
    expect_string(__wrap_OSHash_Get, key, "/test_path");
    will_return(__wrap_OSHash_Get, &data);

    will_return(__wrap_OSHash_Update, 1);

    _w_logcollector_state_update_file(&stat, "/test_path", 100);

    assert_int_equal(data.bytes, 100);
    assert_int_equal(data.events, 1);
}

/* w_logcollector_state_update_file */
void test__w_logcollector_state_update_file_fail_update(void ** state) {

    w_lc_state_storage_t stat = {0};
    stat.states = (OSHash *) 2;

    w_lc_state_file_t * data = NULL;
    os_calloc(1, sizeof(w_lc_state_file_t), data);
    os_calloc(2, sizeof(w_lc_state_target_t *), data->targets);
    os_calloc(1, sizeof(w_lc_state_target_t), data->targets[0]);

    expect_value(__wrap_OSHash_Get, self, stat.states);
    expect_string(__wrap_OSHash_Get, key, "/test_path");
    will_return(__wrap_OSHash_Get, data);

    will_return(__wrap_OSHash_Update, 0);
    expect_value(__wrap_OSHash_Add, key, "/test_path");
    will_return(__wrap_OSHash_Add, 0);

    expect_string(__wrap__merror, formatted_msg,
                  "(1299): Failure to update '/test_path' to 'logcollector_state' hash table");

    _w_logcollector_state_update_file(&stat, "/test_path", 100);
}

/* w_logcollector_state_update_file */
void test_w_logcollector_state_update_file_null(void ** state) {
    w_logcollector_state_update_file(NULL, 500);
}


/* _w_logcollector_state_update_target */
void test__w_logcollector_state_update_target_get_file_stats_fail(void ** state) {

    g_lc_state_type = LC_STATE_GLOBAL | LC_STATE_INTERVAL;
    w_lc_state_storage_t stats = {0};

    char * fpath = "/test_path";
    char * target = "test";

    bool dropped = false;

    expect_value(__wrap_OSHash_Get, self, stats.states);
    expect_string(__wrap_OSHash_Get, key, fpath);
    will_return(__wrap_OSHash_Get, NULL);

    will_return(__wrap_OSHash_Update, 1);

    _w_logcollector_state_update_target(&stats, fpath, target, dropped);
}

void test__w_logcollector_state_update_target_find_target_fail(void ** state) {

    g_lc_state_type = LC_STATE_GLOBAL | LC_STATE_INTERVAL;
    w_lc_state_storage_t * stats = NULL;
    os_calloc(1, sizeof(w_lc_state_storage_t), stats);
    stats->states = (OSHash *) 2;
    stats->start = (time_t) 2020;

    w_lc_state_target_t * target;
    os_calloc(1, sizeof(w_lc_state_target_t), target);
    target->drops = 10;
    os_strdup("test", target->name);

    w_lc_state_target_t ** target_array;
    os_calloc(2, sizeof(w_lc_state_target_t *), target_array);
    target_array[0] = target;

    w_lc_state_file_t * data;
    os_calloc(1, sizeof(w_lc_state_file_t), data);
    data->targets = target_array;
    data->bytes = 100;
    data->events = 5;

    char * fpath = "/test_path";
    char * target_str = "test2";

    bool dropped = false;

    expect_value(__wrap_OSHash_Get, self, stats->states);
    expect_string(__wrap_OSHash_Get, key, fpath);
    will_return(__wrap_OSHash_Get, data);

    will_return(__wrap_OSHash_Update, 1);

    _w_logcollector_state_update_target(stats, fpath, target_str, dropped);

    os_free(target->name);
    os_free(target);
    os_free(data->targets);
    os_free(data);
}

void test__w_logcollector_state_update_target_find_target_ok(void ** state) {

    g_lc_state_type = LC_STATE_GLOBAL | LC_STATE_INTERVAL;
    w_lc_state_storage_t stats = {.states = (OSHash *) 2, .start = (time_t) 2020};
    w_lc_state_target_t target = {.drops = 10, .name = "test"};
    w_lc_state_target_t * target_array[2] = {&target, NULL};

    w_lc_state_file_t data = {.targets = (w_lc_state_target_t **) &target_array, .bytes = 100, .events = 5};

    char * fpath = "/test_path";
    char * target_str = "test";

    bool dropped = false;

    expect_value(__wrap_OSHash_Get, self, stats.states);
    expect_string(__wrap_OSHash_Get, key, fpath);
    will_return(__wrap_OSHash_Get, &data);

    will_return(__wrap_OSHash_Update, 1);

    _w_logcollector_state_update_target(&stats, fpath, target_str, dropped);
}

void test__w_logcollector_state_update_target_dropped_true(void ** state) {

    g_lc_state_type = LC_STATE_GLOBAL | LC_STATE_INTERVAL;
    w_lc_state_storage_t stats = {.states = (OSHash *) 2, .start = (time_t) 2020};
    w_lc_state_target_t target = {.drops = 10, .name = "test"};
    w_lc_state_target_t * target_array[2] = {&target, NULL};

    w_lc_state_file_t data = {.targets = (w_lc_state_target_t **) &target_array, .bytes = 100, .events = 5};

    char * fpath = "/test_path";
    char * target_str = "test";

    bool dropped = true;

    expect_value(__wrap_OSHash_Get, self, stats.states);
    expect_string(__wrap_OSHash_Get, key, fpath);
    will_return(__wrap_OSHash_Get, &data);

    will_return(__wrap_OSHash_Update, 1);

    _w_logcollector_state_update_target(&stats, fpath, target_str, dropped);
}

void test__w_logcollector_state_update_target_OSHash_Update_fail(void ** state) {

    g_lc_state_type = LC_STATE_GLOBAL | LC_STATE_INTERVAL;
    w_lc_state_storage_t stats = {.states = (OSHash *) 2, .start = (time_t) 2020};
    w_lc_state_target_t target = {.drops = 10, .name = "test"};
    w_lc_state_target_t * target_array[2] = {&target, NULL};

    w_lc_state_file_t data = {.targets = (w_lc_state_target_t **) &target_array, .bytes = 100, .events = 5};

    char * fpath = "/test_path";
    char * target_str = "test";

    bool dropped = true;

    expect_value(__wrap_OSHash_Get, self, stats.states);
    expect_string(__wrap_OSHash_Get, key, fpath);
    will_return(__wrap_OSHash_Get, &data);

    will_return(__wrap_OSHash_Update, 0);

    expect_value(__wrap_OSHash_Add, key, "/test_path");
    will_return(__wrap_OSHash_Add, 2);

    _w_logcollector_state_update_target(&stats, fpath, target_str, dropped);
}

void test__w_logcollector_state_update_target_OSHash_Add_fail(void ** state) {

    g_lc_state_type = LC_STATE_GLOBAL | LC_STATE_INTERVAL;
    w_lc_state_storage_t stats = {.states = (OSHash *) 2};
    w_lc_state_target_t * target;
    os_calloc(1, sizeof(w_lc_state_target_t), target);
    target->drops = 10;
    os_strdup("test", target->name);

    w_lc_state_target_t ** target_array;
    os_calloc(2, sizeof(w_lc_state_target_t *), target_array);
    target_array[0] = target;

    w_lc_state_file_t * data;
    os_calloc(1, sizeof(w_lc_state_file_t), data);
    data->targets = target_array;
    data->bytes = 100;
    data->events = 5;

    char * fpath = "/test_path";
    char * target_str = "test";

    bool dropped = true;

    expect_value(__wrap_OSHash_Get, self, stats.states);
    expect_string(__wrap_OSHash_Get, key, fpath);
    will_return(__wrap_OSHash_Get, data);

    will_return(__wrap_OSHash_Update, 0);

    expect_value(__wrap_OSHash_Add, key, "/test_path");
    will_return(__wrap_OSHash_Add, 0);

    expect_string(__wrap__merror, formatted_msg,
                  "(1299): Failure to update '/test_path' to 'logcollector_state' hash table");

    _w_logcollector_state_update_target(&stats, fpath, target_str, dropped);
}

void test_w_logcollector_state_update_file_ok(void ** state) {

    g_lc_state_type = LC_STATE_GLOBAL | LC_STATE_INTERVAL;
    os_calloc(1, sizeof(w_lc_state_storage_t), g_lc_states_global);
    g_lc_states_global->states = (OSHash *) 2;
    os_calloc(1, sizeof(w_lc_state_storage_t), g_lc_states_interval);
    g_lc_states_interval->states = (OSHash *) 3;

    w_lc_state_file_t data = {0};
    w_lc_state_file_t data2 = {.bytes = 10, .events = 5};

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_value(__wrap_OSHash_Get, self, g_lc_states_global->states);
    expect_string(__wrap_OSHash_Get, key, "/test_path");
    will_return(__wrap_OSHash_Get, &data);

    will_return(__wrap_OSHash_Update, 1);

    expect_value(__wrap_OSHash_Get, self, g_lc_states_interval->states);
    expect_string(__wrap_OSHash_Get, key, "/test_path");
    will_return(__wrap_OSHash_Get, &data2);

    will_return(__wrap_OSHash_Update, 1);

    expect_function_call(__wrap_pthread_mutex_unlock);

    w_logcollector_state_update_file("/test_path", 500);

    assert_int_equal(data.bytes, 500);
    assert_int_equal(data.events, 1);
    assert_int_equal(data2.bytes, 510);
    assert_int_equal(data2.events, 6);
    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);
}

// Tests w_logcollector_state_update_target
void test_w_logcollector_state_update_target_null_target(void ** state) {
    w_logcollector_state_update_target("test path", NULL, false);
}

void test_w_logcollector_state_update_target_null_path(void ** state) {
    w_logcollector_state_update_target(NULL, "test_target", false);
}

void test_w_logcollector_state_update_target_ok(void ** state) {

    g_lc_state_type = LC_STATE_GLOBAL | LC_STATE_INTERVAL;
    os_calloc(1, sizeof(w_lc_state_storage_t), g_lc_states_global);
    g_lc_states_global->states = (OSHash *) 2;
    os_calloc(1, sizeof(w_lc_state_storage_t), g_lc_states_interval);
    g_lc_states_interval->states = (OSHash *) 3;

    w_lc_state_target_t target = {.drops = 10, .name = "test_target"};
    w_lc_state_target_t * target_array[2] = {&target, NULL};
    w_lc_state_file_t data = {.targets = (w_lc_state_target_t **) &target_array, .bytes = 100, .events = 5};

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_OSHash_Get, self, g_lc_states_global->states);
    expect_string(__wrap_OSHash_Get, key, "test_path");
    will_return(__wrap_OSHash_Get, &data);

    will_return(__wrap_OSHash_Update, 1);

    w_lc_state_target_t target2 = {.drops = 10, .name = "test_target"};
    w_lc_state_target_t * target_array2[2] = {&target, NULL};
    w_lc_state_file_t data2 = {.targets = (w_lc_state_target_t **) &target_array2, .bytes = 100, .events = 5};

    expect_value(__wrap_OSHash_Get, self, g_lc_states_interval->states);
    expect_string(__wrap_OSHash_Get, key, "test_path");
    will_return(__wrap_OSHash_Get, &data2);

    will_return(__wrap_OSHash_Update, 1);

    expect_function_call(__wrap_pthread_mutex_unlock);

    w_logcollector_state_update_target("test_path", "test_target", false);

    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);
}

/* w_logcollector_state_generate */
void test_w_logcollector_generate_state_ok(void ** state) {

    g_lc_state_type = LC_STATE_GLOBAL | LC_STATE_INTERVAL;;
    os_calloc(1, sizeof(w_lc_state_storage_t), g_lc_states_global);
    g_lc_states_global->states = (OSHash *) 2;

    w_lc_state_target_t target = {.drops = 10, .name = "sock1"};
    w_lc_state_target_t * target_array[2] = {&target, NULL};

    w_lc_state_file_t data = {.targets = (w_lc_state_target_t **) &target_array, .bytes = 100, .events = 5};
    OSHashNode hash_node = {.data = &data, .key = "key_test"};

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_lock);

    expect_function_call(__wrap_cJSON_Delete);

    will_return_always(__wrap_cJSON_CreateObject, (cJSON *) 10);

    expect_value(__wrap_OSHash_Begin, self, g_lc_states_global->states);
    will_return(__wrap_OSHash_Begin, &hash_node);

    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);
    will_return_always(__wrap_cJSON_AddItemToArray, true);
    will_return_always(__wrap_cJSON_AddItemToObject, true);

    will_return_always(__wrap_cJSON_CreateArray, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "sock1");

    expect_string(__wrap_cJSON_AddNumberToObject, name, "drops");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 10);

    expect_function_call(__wrap_cJSON_AddItemToArray);

    expect_string(__wrap_cJSON_AddStringToObject, name, "location");
    expect_string(__wrap_cJSON_AddStringToObject, string, "key_test");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "events");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 5);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "bytes");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 100);
    expect_function_call(__wrap_cJSON_AddItemToObject);


    expect_function_call(__wrap_cJSON_AddItemToArray);

    expect_value(__wrap_OSHash_Next, self, g_lc_states_global->states);
    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_strftime,"2019-02-05 12:18:37");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap_cJSON_AddStringToObject, name, "start");
    expect_string(__wrap_cJSON_AddStringToObject, string, "2019-02-05 12:18:37");

    will_return(__wrap_time, (time_t) 2525);
    will_return(__wrap_strftime,"2019-02-05 12:18:42");
    will_return(__wrap_strftime, 20);
    expect_string(__wrap_cJSON_AddStringToObject, name, "end");
    expect_string(__wrap_cJSON_AddStringToObject, string, "2019-02-05 12:18:42");

    expect_function_call(__wrap_cJSON_AddItemToObject);

    expect_function_call(__wrap_cJSON_AddItemToObject);

    os_calloc(1, sizeof(w_lc_state_storage_t), g_lc_states_interval);
    g_lc_states_interval->states = (OSHash *) 4;
    g_lc_states_interval->start = (time_t) 2020;

    w_lc_state_file_t data2 = {.targets = (w_lc_state_target_t **) &target_array, .bytes = 100, .events = 5};
    OSHashNode hash_node2 = {.data = &data2, .key = "key_test"};

    expect_value(__wrap_OSHash_Begin, self, g_lc_states_interval->states);
    will_return(__wrap_OSHash_Begin, &hash_node2);

    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "sock1");

    expect_string(__wrap_cJSON_AddNumberToObject, name, "drops");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 10);

    expect_function_call(__wrap_cJSON_AddItemToArray);


    expect_string(__wrap_cJSON_AddStringToObject, name, "location");
    expect_string(__wrap_cJSON_AddStringToObject, string, "key_test");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "events");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 5);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "bytes");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 100);
    expect_function_call(__wrap_cJSON_AddItemToObject);


    expect_function_call(__wrap_cJSON_AddItemToArray);

    expect_value(__wrap_OSHash_Next, self, g_lc_states_interval->states);
    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_strftime,"2019-02-05 12:18:37");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap_cJSON_AddStringToObject, name, "start");
    expect_string(__wrap_cJSON_AddStringToObject, string, "2019-02-05 12:18:37");

    will_return(__wrap_time, (time_t) 2525);
    will_return(__wrap_strftime,"2019-02-05 12:18:42");
    will_return(__wrap_strftime, 20);
    expect_string(__wrap_cJSON_AddStringToObject, name, "end");
    expect_string(__wrap_cJSON_AddStringToObject, string, "2019-02-05 12:18:42");

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_time, (time_t) 2525);

    expect_function_call(__wrap_cJSON_AddItemToObject);

    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    w_logcollector_state_generate();

    assert_int_equal(data.bytes, 100);
    assert_int_equal(data.events, 5);
    assert_int_equal(data2.bytes, 0);
    assert_int_equal(data2.events, 0);
    assert_int_equal(g_lc_states_interval->start, 2525);
    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);
}

/* w_logcollector_state_dump */
void test_w_logcollector_state_dump_fail_open(void ** state) {

    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_cJSON_Duplicate, (cJSON *) 3);
    expect_function_call(__wrap_pthread_mutex_unlock);
    will_return(__wrap_cJSON_Print, strdup("Test 123"));
    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap_fopen, path, LOGCOLLECTOR_STATE);
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, NULL);

    expect_string(__wrap__merror, formatted_msg,
                  "(1103): Could not open file "
                  "'var/run/wazuh-logcollector.state' due to [(0)-(Success)].");

    w_logcollector_state_dump();
}

void test_w_logcollector_state_dump_fail_write(void ** state) {

    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_cJSON_Duplicate, (cJSON *) 3);
    expect_function_call(__wrap_pthread_mutex_unlock);
    will_return(__wrap_cJSON_Print, strdup("Test 123"));
    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap_fopen, path, LOGCOLLECTOR_STATE);
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, (FILE *) 100);
    will_return(__wrap_fwrite, 0);

    expect_string(__wrap__merror, formatted_msg,
                  "(1110): Could not write file "
                  "'var/run/wazuh-logcollector.state' due to [(0)-(Success)].");

    expect_value(__wrap_fclose, _File, (FILE *) 100);
    will_return(__wrap_fclose, 0);

    w_logcollector_state_dump();
}

void test_w_logcollector_state_dump_ok(void ** state) {

    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_cJSON_Duplicate, (cJSON *) 3);
    expect_function_call(__wrap_pthread_mutex_unlock);
    will_return(__wrap_cJSON_Print, strdup("Test 123"));
    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap_fopen, path, LOGCOLLECTOR_STATE);
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, (FILE *) 100);
    will_return(__wrap_fwrite, 1);

    expect_value(__wrap_fclose, _File, (FILE *) 100);
    will_return(__wrap_fclose, 0);

    w_logcollector_state_dump();
}

void test_w_logcollector_state_main_bad_interval(void ** state) {

    g_lc_state_type = LC_STATE_GLOBAL | LC_STATE_INTERVAL;;
    int interval = -1;
    w_logcollector_state_main((void *) &interval);
}

void test_w_logcollector_state_main_ok(void ** state) {

    int interval = 105;
    will_return(__wrap_FOREVER, 1);
    expect_value(__wrap_sleep, seconds, interval);

    // w_logcollector_state_generate
    os_calloc(1, sizeof(w_lc_state_storage_t), g_lc_states_global);
    g_lc_states_global->states = (OSHash *) 2;

    w_lc_state_target_t target = {.drops = 10, .name = "sock1"};
    w_lc_state_target_t * target_array[2] = {&target, NULL};

    w_lc_state_file_t data = {.targets = (w_lc_state_target_t **) &target_array, .bytes = 100, .events = 5};
    OSHashNode hash_node = {.data = &data, .key = "key_test"};

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_lock);

    expect_function_call(__wrap_cJSON_Delete);

    will_return_always(__wrap_cJSON_CreateObject, (cJSON *) 10);

    expect_value(__wrap_OSHash_Begin, self, g_lc_states_global->states);
    will_return(__wrap_OSHash_Begin, &hash_node);

    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);
    will_return_always(__wrap_cJSON_AddItemToArray, true);
    will_return_always(__wrap_cJSON_AddItemToObject, true);

    will_return_always(__wrap_cJSON_CreateArray, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "sock1");

    expect_string(__wrap_cJSON_AddNumberToObject, name, "drops");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 10);

    expect_function_call(__wrap_cJSON_AddItemToArray);

    expect_string(__wrap_cJSON_AddStringToObject, name, "location");
    expect_string(__wrap_cJSON_AddStringToObject, string, "key_test");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "events");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 5);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "bytes");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 100);

    expect_function_call(__wrap_cJSON_AddItemToObject);

    expect_function_call(__wrap_cJSON_AddItemToArray);

    expect_value(__wrap_OSHash_Next, self, g_lc_states_global->states);
    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_strftime,"2019-02-05 12:18:37");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap_cJSON_AddStringToObject, name, "start");
    expect_string(__wrap_cJSON_AddStringToObject, string, "2019-02-05 12:18:37");

    will_return(__wrap_time, (time_t) 2525);
    will_return(__wrap_strftime,"2019-02-05 12:18:42");
    will_return(__wrap_strftime, 20);
    expect_string(__wrap_cJSON_AddStringToObject, name, "end");
    expect_string(__wrap_cJSON_AddStringToObject, string, "2019-02-05 12:18:42");

    expect_function_call(__wrap_cJSON_AddItemToObject);

    expect_function_call(__wrap_cJSON_AddItemToObject);

    os_calloc(1, sizeof(w_lc_state_storage_t), g_lc_states_interval);
    g_lc_states_interval->states = (OSHash *) 4;
    g_lc_states_interval->start = (time_t) 2020;

    w_lc_state_file_t data2 = {.targets = (w_lc_state_target_t **) &target_array, .bytes = 100, .events = 5};
    OSHashNode hash_node2 = {.data = &data2, .key = "key_test"};

    expect_value(__wrap_OSHash_Begin, self, g_lc_states_interval->states);
    will_return(__wrap_OSHash_Begin, &hash_node2);

    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "sock1");

    expect_string(__wrap_cJSON_AddNumberToObject, name, "drops");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 10);

    expect_function_call(__wrap_cJSON_AddItemToArray);


    expect_string(__wrap_cJSON_AddStringToObject, name, "location");
    expect_string(__wrap_cJSON_AddStringToObject, string, "key_test");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "events");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 5);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "bytes");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 100);

    expect_function_call(__wrap_cJSON_AddItemToObject);

    expect_function_call(__wrap_cJSON_AddItemToArray);

    expect_value(__wrap_OSHash_Next, self, g_lc_states_interval->states);
    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_strftime,"2019-02-05 12:18:37");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap_cJSON_AddStringToObject, name, "start");
    expect_string(__wrap_cJSON_AddStringToObject, string, "2019-02-05 12:18:37");

    will_return(__wrap_time, (time_t) 2525);
    will_return(__wrap_strftime,"2019-02-05 12:18:42");
    will_return(__wrap_strftime, 20);
    expect_string(__wrap_cJSON_AddStringToObject, name, "end");
    expect_string(__wrap_cJSON_AddStringToObject, string, "2019-02-05 12:18:42");

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_time, (time_t) 2525);

    expect_function_call(__wrap_cJSON_AddItemToObject);

    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_cJSON_Duplicate, (cJSON *) 3);
    expect_function_call(__wrap_pthread_mutex_unlock);
    will_return(__wrap_cJSON_Print, strdup("Test 123"));
    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap_fopen, path, LOGCOLLECTOR_STATE);
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, (FILE *) 100);
    will_return(__wrap_fwrite, 1);

    expect_value(__wrap_fclose, _File, (FILE *) 100);
    will_return(__wrap_fclose, 0);

    will_return(__wrap_FOREVER, 0);

    w_logcollector_state_main((void *) &interval);

    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);
}

/* _test_w_logcollector_state_delete_file */

void test__w_logcollector_state_delete_file_no_data(void ** state) {

    w_lc_state_storage_t storage = {0};
    os_calloc(1, sizeof(OSHash), storage.states);

    expect_value(__wrap_OSHash_Delete, self, storage.states);
    expect_string(__wrap_OSHash_Delete, key, "test_path");
    will_return(__wrap_OSHash_Delete, NULL);

    _w_logcollector_state_delete_file(&storage, "test_path");
    os_free(storage.states);

}

void test__w_logcollector_state_delete_file_ok(void ** state) {

    w_lc_state_storage_t storage = {0};
    os_calloc(1, sizeof(OSHash), storage.states);

    w_lc_state_file_t * data = NULL;
    os_calloc(1, sizeof(w_lc_state_file_t), data);
    os_calloc(3, sizeof(w_lc_state_target_t *), data->targets);
    os_calloc(1, sizeof(w_lc_state_target_t), data->targets[0]);
    os_strdup("target name 1", data->targets[0]->name);
    os_calloc(1, sizeof(w_lc_state_target_t), data->targets[1]);
    os_strdup("target name 2", data->targets[1]->name);

    expect_value(__wrap_OSHash_Delete, self, storage.states);
    expect_string(__wrap_OSHash_Delete, key, "test_path");
    will_return(__wrap_OSHash_Delete, data);

    _w_logcollector_state_delete_file(&storage, "test_path");
    os_free(storage.states);
}

/* w_logcollector_state_delete_file */

void test_w_logcollector_state_delete_file_fpath_NULL(void ** state) {

    char * fpath = NULL;

    w_logcollector_state_delete_file(fpath);

}

void test_w_logcollector_state_delete_file_global(void ** state) {

    char * fpath = NULL;

    os_strdup("test", fpath);

    g_lc_state_type = 1;

    os_calloc(1, sizeof(w_lc_state_storage_t), g_lc_states_global);
    g_lc_states_global->states = (OSHash *) 2;

    expect_value(__wrap_OSHash_Delete, self, g_lc_states_global->states);
    expect_string(__wrap_OSHash_Delete, key, fpath);
    will_return(__wrap_OSHash_Delete, NULL);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_function_call(__wrap_pthread_mutex_unlock);

    w_logcollector_state_delete_file(fpath);

    os_free(fpath);
    os_free(g_lc_states_global);

}

void test_w_logcollector_state_delete_file_interval(void ** state) {

    char * fpath = NULL;

    os_strdup("test", fpath);

    g_lc_state_type = 2;

    os_calloc(1, sizeof(w_lc_state_storage_t), g_lc_states_interval);
    g_lc_states_interval->states = (OSHash *) 2;

    expect_value(__wrap_OSHash_Delete, self, g_lc_states_interval->states);
    expect_string(__wrap_OSHash_Delete, key, fpath);
    will_return(__wrap_OSHash_Delete, NULL);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_function_call(__wrap_pthread_mutex_unlock);

    w_logcollector_state_delete_file(fpath);

    os_free(fpath);
    os_free(g_lc_states_interval);

}

void test_w_logcollector_state_delete_file_global_interval(void ** state) {

    char * fpath = NULL;

    os_strdup("test", fpath);

    g_lc_state_type = 3;

    os_calloc(1, sizeof(w_lc_state_storage_t), g_lc_states_global);
    g_lc_states_global->states = (OSHash *) 2;

    os_calloc(1, sizeof(w_lc_state_storage_t), g_lc_states_interval);
    g_lc_states_interval->states = (OSHash *) 2;

    expect_value(__wrap_OSHash_Delete, self, g_lc_states_global->states);
    expect_string(__wrap_OSHash_Delete, key, fpath);
    will_return(__wrap_OSHash_Delete, NULL);

    expect_value(__wrap_OSHash_Delete, self, g_lc_states_interval->states);
    expect_string(__wrap_OSHash_Delete, key, fpath);
    will_return(__wrap_OSHash_Delete, NULL);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_function_call(__wrap_pthread_mutex_unlock);

    w_logcollector_state_delete_file(fpath);

    os_free(fpath);
    os_free(g_lc_states_global);
    os_free(g_lc_states_interval);

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
        cmocka_unit_test(test_w_logcollector_state_get_null),
        cmocka_unit_test(test_w_logcollector_state_get_non_null),

        // Tests _w_logcollector_generate_state
        cmocka_unit_test(test__w_logcollector_generate_state_fail_get_node),
        cmocka_unit_test(test__w_logcollector_generate_state_one_target),
        cmocka_unit_test(test__w_logcollector_generate_state_one_target_restart),

        // Tests _w_logcollector_state_update_file
        cmocka_unit_test(test__w_logcollector_state_update_file_new_data),
        cmocka_unit_test(test__w_logcollector_state_update_file_update),
        cmocka_unit_test(test__w_logcollector_state_update_file_fail_update),

        // Tests w_logcollector_state_update_file
        cmocka_unit_test(test_w_logcollector_state_update_file_null),
        cmocka_unit_test(test_w_logcollector_state_update_file_ok),

        // Tests _w_logcollector_state_update_target
        cmocka_unit_test(test__w_logcollector_state_update_target_get_file_stats_fail),
        cmocka_unit_test(test__w_logcollector_state_update_target_find_target_fail),
        cmocka_unit_test(test__w_logcollector_state_update_target_find_target_ok),
        cmocka_unit_test(test__w_logcollector_state_update_target_dropped_true),
        cmocka_unit_test(test__w_logcollector_state_update_target_OSHash_Update_fail),
        cmocka_unit_test(test__w_logcollector_state_update_target_OSHash_Add_fail),

        // Tests w_logcollector_state_update_target
        cmocka_unit_test(test_w_logcollector_state_update_target_null_path),
        cmocka_unit_test(test_w_logcollector_state_update_target_null_target),
        cmocka_unit_test(test_w_logcollector_state_update_target_ok),

        // Tests w_logcollector_state_generate
        cmocka_unit_test(test_w_logcollector_generate_state_ok),

        // Tests w_logcollector_state_dump
        cmocka_unit_test(test_w_logcollector_state_dump_fail_open),
        cmocka_unit_test(test_w_logcollector_state_dump_fail_write),
        cmocka_unit_test(test_w_logcollector_state_dump_ok),

        // Tests w_logcollector_state_main
        cmocka_unit_test(test_w_logcollector_state_main_bad_interval),
        cmocka_unit_test(test_w_logcollector_state_main_ok),

        // Test _w_logcollector_state_delete_file
        cmocka_unit_test(test__w_logcollector_state_delete_file_no_data),
        cmocka_unit_test(test__w_logcollector_state_delete_file_ok),

        // Test _w_logcollector_state_delete_file
        cmocka_unit_test(test_w_logcollector_state_delete_file_fpath_NULL),
        cmocka_unit_test(test_w_logcollector_state_delete_file_global),
        cmocka_unit_test(test_w_logcollector_state_delete_file_interval),
        cmocka_unit_test(test_w_logcollector_state_delete_file_global_interval),

    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
