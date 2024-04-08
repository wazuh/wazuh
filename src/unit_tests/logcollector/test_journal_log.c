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
#include <time.h>

#include "../../logcollector/journal_log.h"

#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/common.h"
#include "../wrappers/externals/pcre2/pcre2_wrappers.h"

bool is_owned_by_root(const char * library_path);
bool load_and_validate_function(void * handle, const char * name, void ** func);
uint64_t w_get_epoch_time();
char * w_timestamp_to_string(uint64_t timestamp);

//Mocks

// Mock dlsym function to simulate the loading of valid and invalid functions
void *__wrap_dlsym(void *handle, const char *name) {
    if (strcmp(name, "valid_function") == 0) {
        return (void *)1; // Valid function
    } else {
        return NULL; // Invalid function
    }
}

// Mock dlerror function
char* __wrap_dlerror() {
    return "ERROR";
}

// Mock gmtime_r function
unsigned int __wrap_gmtime_r(__attribute__ ((__unused__)) const time_t *t, __attribute__ ((__unused__)) struct tm *tm) {
    return mock_type(unsigned int);
}

/* setup/teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    w_test_pcre2_wrappers(false);
    return 0;

}

static int group_teardown(void ** state) {
    test_mode = 0;
    w_test_pcre2_wrappers(true);
    return 0;

}

// Test is_owned_by_root

void test_is_owned_by_root_root_owned(void **state) {
    (void)state;

    const char * library_path = "existent_file_root";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_value(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    bool result = is_owned_by_root(library_path);

    // Assert
    assert_true(result);
}

void test_is_owned_by_root_not_root_owned(void **state) {
    (void)state;

    const char * library_path = "existent_file_no_root";

    struct stat mock_stat;
    mock_stat.st_uid = 1000;

    expect_value(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    bool result = is_owned_by_root(library_path);

    // Assert
    assert_false(result);
}

void test_is_owned_by_root_stat_fails(void **state) {
    (void)state;

    const char * library_path = "nonexistent_file";

    struct stat mock_stat;
    mock_stat.st_uid = 1000;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, -1);

    bool result = is_owned_by_root(library_path);

    // Assert
    assert_false(result);
}

// Test load_and_validate_function

static void test_load_and_validate_function_success(void **state) {
    // Arrange
    void *handle = (void *)1; // Simulate handle
    const char *function_name = "valid_function";
    void *function_pointer;
    
    // Act
    bool result = load_and_validate_function(handle, function_name, &function_pointer);
    
    // Assert
    assert_true(result);
    assert_non_null(function_pointer);
}

static void test_load_and_validate_function_failure(void **state) {
    // Arrange
    void *handle = NULL;  // Simulate invalid handle
    const char *function_name = "invalid_function";
    void *function_pointer = (void *)1;

    expect_string(__wrap__mwarn, formatted_msg, "(8008): Failed to load 'invalid_function': 'ERROR'.");
    
    // Act
    bool result = load_and_validate_function(handle, function_name, &function_pointer);
    
    // Assert
    assert_false(result);
    assert_null(function_pointer);
}

// Test w_get_epoch_time

static void test_w_get_epoch_time(void **state) {
    // Arrange
    expect_function_call(__wrap_gettimeofday);
    
    // Act
    uint64_t result = w_get_epoch_time();
    
    // Assert
    assert_int_equal(result, 0);
}

//Test w_timestamp_to_string

static void test_w_timestamp_to_string(void **state) {
    // Arrange
    uint64_t timestamp = 1618849174000000; // Timestamp en microsegundos
    will_return(__wrap_gmtime_r, 1);
    
    // Act
    char *result = w_timestamp_to_string(timestamp);
    
    // Assert
    free(result);
}

int main(void) {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_is_owned_by_root_root_owned),
        cmocka_unit_test(test_is_owned_by_root_not_root_owned),
        cmocka_unit_test(test_is_owned_by_root_stat_fails),
        cmocka_unit_test(test_load_and_validate_function_success),
        cmocka_unit_test(test_load_and_validate_function_failure),
        cmocka_unit_test(test_w_get_epoch_time),
        cmocka_unit_test(test_w_timestamp_to_string)
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
