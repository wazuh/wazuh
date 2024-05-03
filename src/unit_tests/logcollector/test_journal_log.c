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
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/linux/dlfcn_wrappers.h"

#define _XOPEN_SOURCE

bool is_owned_by_root(const char * library_path);
bool load_and_validate_function(void * handle, const char * name, void ** func);
uint64_t w_get_epoch_time();
char * w_timestamp_to_string(uint64_t timestamp);
char * w_timestamp_to_journalctl_since(uint64_t timestamp);
char * find_library_path(const char * library_name);
w_journal_lib_t * w_journal_lib_init();
cJSON * entry_as_json(w_journal_context_t * ctx);
char * get_field_ptr(w_journal_context_t * ctx, const char * field);
char * create_plain_syslog(const char * timestamp,
                           const char * hostname,
                           const char * syslog_identifier,
                           const char * pid,
                           const char * message);
char * entry_as_syslog(w_journal_context_t * ctx);
w_journal_entry_t * w_journal_entry_dump(w_journal_context_t * ctx, w_journal_entry_dump_type_t type);

// Mocks

/* Mock of the sd_journal_* functions */
int __wrap_sd_journal_open(sd_journal ** journal, int flags) { return mock_type(int); }

void __wrap_sd_journal_close(sd_journal * j) { function_called(); }

int __wrap_sd_journal_previous(sd_journal * j) { return mock_type(int); }

int __wrap_sd_journal_next(sd_journal * j) { return mock_type(int); }

int __wrap_sd_journal_seek_tail(sd_journal * j) { return mock_type(int); }

int __wrap_sd_journal_seek_realtime_usec(sd_journal * j, uint64_t usec) { return mock_type(int); }

// The expected value is returned in the usec parameter
// If the expected value positive, the function returns 0 and the expected value is stored in usec
int __wrap_sd_journal_get_realtime_usec(sd_journal * j, uint64_t * usec) {
    int64_t ret = mock_type(int64_t);
    if (ret >= 0) {
        *usec = (uint64_t) ret;
        return 0;
    }
    return ret;
}

int __wrap_sd_journal_get_data(sd_journal * j, const char * field, const void ** data, size_t * length) {
    check_expected(field);
    int retval = mock_type(int);
    // If function returns a positive value, return a simulated data
    if (retval >= 0) {
        *data = mock_ptr_type(char *);
        *length = strlen(*data);
    }
    return retval;
}

int __wrap_sd_journal_restart_data(sd_journal * j) { return mock_type(int); }

int __wrap_sd_journal_enumerate_data(sd_journal * j, const void ** data, size_t * length) {

    int retval = mock_type(int);
    if (retval > 0) {
        *data = mock_ptr_type(char *);
        *length = strlen(*data);
    }
    return retval;
}

int __wrap_sd_journal_get_cutoff_realtime_usec(sd_journal * j, uint64_t * from, uint64_t * to) {
    int64_t ret = mock_type(int64_t);
    if (ret >= 0) {
        *from = (uint64_t) ret;
        return 0;
    }
    return ret;
}

extern unsigned int __real_gmtime_r(const time_t * t, struct tm * tm);
unsigned int __wrap_gmtime_r(__attribute__((__unused__)) const time_t * t, __attribute__((__unused__)) struct tm * tm) {
    unsigned int mock = mock_type(unsigned int);
    if (mock == 0) {
        return mock;
    } else {
        return __real_gmtime_r(t, tm);
    }
}

int __wrap_isDebug() { return mock(); }

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

// Test is_owned_by_root with root owned
void test_is_owned_by_root_root_owned(void ** state) {
    (void) state;

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

// Test is_owned_by_root with not root owned
void test_is_owned_by_root_not_root_owned(void ** state) {
    (void) state;

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

// Test is_owned_by_root with stat fails
void test_is_owned_by_root_stat_fails(void ** state) {
    (void) state;

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

// Test load_and_validate_function success
static void test_load_and_validate_function_success(void ** state) {
    // Arrange
    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;
    const char * function_name = "valid_function";
    void * function_pointer;

    expect_any(__wrap_dlsym, handle);
    expect_string(__wrap_dlsym, symbol, "valid_function");
    will_return(__wrap_dlsym, mock_function);

    // Act
    bool result = load_and_validate_function(handle, function_name, &function_pointer);

    // Assert
    assert_true(result);
    assert_non_null(function_pointer);
}

// Test load_and_validate_function failure
static void test_load_and_validate_function_failure(void ** state) {
    // Arrange
    void * handle = NULL; // Simulate invalid handle
    void * mock_function = NULL;
    const char * function_name = "invalid_function";
    void * function_pointer = (void *) 1;

    expect_any(__wrap_dlsym, handle);
    expect_string(__wrap_dlsym, symbol, "invalid_function");
    will_return(__wrap_dlsym, mock_function);

    will_return(__wrap_dlerror, "ERROR");

    expect_string(__wrap__mwarn, formatted_msg, "(8008): Failed to load 'invalid_function': 'ERROR'.");

    // Act
    bool result = load_and_validate_function(handle, function_name, &function_pointer);

    // Assert
    assert_false(result);
    assert_null(function_pointer);
}

// Test w_get_epoch_time

static void test_w_get_epoch_time(void ** state) {
    // Arrange
    will_return(__wrap_gettimeofday, 0);

    // Act
    uint64_t result = w_get_epoch_time();

    // Cant assert the result because it is a time value and the wrapper is not set in the test

}

// Test w_timestamp_to_string

static void test_w_timestamp_to_string(void ** state) {
    // Arrange
    uint64_t timestamp = 1618849174000000; // Timestamp in microseconds
    will_return(__wrap_gmtime_r, 1);

    // Act
    char * result = w_timestamp_to_string(timestamp);

    // Assert
    free(result);
}

// Test w_timestamp_to_journalctl_since

static void test_w_timestamp_to_journalctl_since_success(void ** state) {
    // Arrange
    uint64_t timestamp = 1618849174000000; // Timestamp in microseconds (2021-04-19 16:19:34)

    will_return(__wrap_gmtime_r, 1618849174000000);

    // Act
    char * result = w_timestamp_to_journalctl_since(timestamp);

    // Assert
    assert_non_null(result);

    // Verify the result is the expected format
    assert_int_equal(strlen(result), strlen("1900-01-00 00:00:00"));
    assert_string_equal(result, "2021-04-19 16:19:34");
    free(result);
}

static void test_w_timestamp_to_journalctl_since_failure(void ** state) {
    // Arrange
    uint64_t timestamp = 0; // Timestamp que provocará el error

    will_return(__wrap_gmtime_r, 0);

    // Act
    char * result = w_timestamp_to_journalctl_since(timestamp);

    // Assert
    assert_null(result);
}

// Test find_library_path

static void test_find_library_path_success(void ** state) {
    // Arrange
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /path/to/libtest.so\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // Act
    char * result = find_library_path("libtest.so");

    // Assert
    assert_non_null(result);
    assert_string_equal(result, "/path/to/libtest.so");

    // Clean
    free(result);
}

static void test_find_library_path_failure(void ** state) {
    // Arrange

    // Set expectations for fopen
    const char * library_name = "libtest.so";
    const char * expected_mode = "r";
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Setting the return value for fopen
    FILE * maps_file = NULL; // Simulate fopen error
    will_return(__wrap_fopen, maps_file);

    // Act
    char * result = find_library_path(library_name);

    // Assert
    assert_null(result);

    // Clean
    free(result);
}

#define W_LIB_SYSTEMD "libsystemd.so.0"
#define RTLD_LAZY     1

// Test w_journal_lib_init

// Define a test case for the scenario where dlopen fails
static void test_w_journal_lib_init_dlopen_fail(void ** state) {
    // Arrange
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, NULL);

    will_return(__wrap_dlerror, "Library load failed");

    expect_string(__wrap__mwarn, formatted_msg, "(8008): Failed to load 'libsystemd.so.0': 'Library load failed'.");

    // Act
    w_journal_lib_t * result = w_journal_lib_init();

    // Assert
    assert_null(result);
}

// Define a test case for the scenario where find_library_path fails
static void test_w_journal_lib_init_find_library_path_fail(void ** state) {
    // Arrange
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_failure
    // Set expectations for fopen
    const char * library_name = "libtest.so";
    const char * expected_mode = "r";
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Setting the return value for fopen
    FILE * maps_file = NULL; // Simulate fopen error
    will_return(__wrap_fopen, maps_file);

    // expect_any(__wrap_mwarn, id);
    expect_string(__wrap__mwarn, formatted_msg, "(8009): The library 'libsystemd.so.0' is not owned by the root user.");

    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success

    // Act
    w_journal_lib_t * result = w_journal_lib_init();

    // Assert
    assert_null(result);
}

// Define a test case for the scenario where is_owned_by_root fails
static void test_w_journal_lib_init_is_owned_by_root_fail(void ** state) {
    // Arrange
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_stat_fails
    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 1000;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, -1);

    // expect_any(__wrap_mwarn, id);
    expect_string(__wrap__mwarn, formatted_msg, "(8009): The library 'libsystemd.so.0' is not owned by the root user.");

    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success

    // Act
    w_journal_lib_t * result = w_journal_lib_init();

    // Assert
    assert_null(result);
}

// Define a test case for the scenario where load_and_validate_function fails
static void test_w_journal_lib_init_load_and_validate_function_fail(void ** state) {
    // Arrange
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    // test_load_and_validate_function_failure
    void * handle = NULL; // Simulate invalid handle
    void * mock_function = NULL;
    const char * function_name = "sd_journal_open";
    void * function_pointer = (void *) 1;

    expect_any(__wrap_dlsym, handle);
    expect_string(__wrap_dlsym, symbol, function_name);
    will_return(__wrap_dlsym, mock_function);

    will_return(__wrap_dlerror, "ERROR");

    expect_string(__wrap__mwarn, formatted_msg, "(8008): Failed to load 'sd_journal_open': 'ERROR'.");

    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);

    // Act
    w_journal_lib_t * result = w_journal_lib_init();

    // Assert
    assert_null(result);
}

// Define a test case for the scenario where everything succeeds

//  Auxiliary function for setting dlsym wrap expectations
static void setup_dlsym_expectations(const char * symbol) {
    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0x1;

    if (strcmp(symbol, "sd_journal_open") == 0) {
        mock_function = (void *) __wrap_sd_journal_open;
    } else if (strcmp(symbol, "sd_journal_close") == 0) {
        mock_function = (void *) __wrap_sd_journal_close;
    } else if (strcmp(symbol, "sd_journal_previous") == 0) {
        mock_function = (void *) __wrap_sd_journal_previous;
    } else if (strcmp(symbol, "sd_journal_next") == 0) {
        mock_function = (void *) __wrap_sd_journal_next;
    } else if (strcmp(symbol, "sd_journal_seek_tail") == 0) {
        mock_function = (void *) __wrap_sd_journal_seek_tail;
    } else if (strcmp(symbol, "sd_journal_seek_realtime_usec") == 0) {
        mock_function = (void *) __wrap_sd_journal_seek_realtime_usec;
    } else if (strcmp(symbol, "sd_journal_get_realtime_usec") == 0) {
        mock_function = (void *) __wrap_sd_journal_get_realtime_usec;
    } else if (strcmp(symbol, "sd_journal_get_data") == 0) {
        mock_function = (void *) __wrap_sd_journal_get_data;
    } else if (strcmp(symbol, "sd_journal_restart_data") == 0) {
        mock_function = (void *) __wrap_sd_journal_restart_data;
    } else if (strcmp(symbol, "sd_journal_enumerate_data") == 0) {
        mock_function = (void *) __wrap_sd_journal_enumerate_data;
    } else if (strcmp(symbol, "sd_journal_get_cutoff_realtime_usec") == 0) {
        mock_function = (void *) __wrap_sd_journal_get_cutoff_realtime_usec;
    } else {
        // Invalid symbol
        assert_true(false);
    }

    expect_any(__wrap_dlsym, handle);
    expect_string(__wrap_dlsym, symbol, symbol);
    will_return(__wrap_dlsym, mock_function);
}

static void test_w_journal_lib_init_success(void ** state) {
    // Arrange
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    // Act
    w_journal_lib_t * result = w_journal_lib_init();

    // Assert
    assert_non_null(result);
    free(result);
}

// Test w_journal_context_create

// Test case for a successful context creation
static void test_w_journal_context_create_success(void ** state) {
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expect to call w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    // Open the journal
    will_return(__wrap_sd_journal_open, 0);

    // Call the function under test
    int ret = w_journal_context_create(&ctx);

    // Check the result
    assert_int_equal(ret, 0); // Success
    assert_non_null(ctx);     // ctx non null

    // Clear dynamically allocated memory
    os_free(ctx->journal);
    os_free(ctx->lib);
    os_free(ctx);
}

// Test case for a failure due to NULL context pointer
static void test_w_journal_context_create_null_pointer(void ** state) {
    // Call the function with a NULL context pointer
    int ret = w_journal_context_create(NULL);

    // Check the result
    assert_int_equal(ret, -1);
}

// Test case for a failure in library initialization
static void test_w_journal_context_create_lib_init_fail(void ** state) {
    // Allocate memory for the context
    w_journal_context_t * ctx = NULL;

    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, NULL);

    will_return(__wrap_dlerror, "Library load failed");

    expect_string(__wrap__mwarn, formatted_msg, "(8008): Failed to load 'libsystemd.so.0': 'Library load failed'.");

    // Call the function under test
    int ret = w_journal_context_create(&ctx);

    // Check the result
    assert_int_equal(ret, -1);
    assert_null(ctx);
}

// Test case for a failure in journal opening
static void test_w_journal_context_create_journal_open_fail(void ** state) {
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, -1); // Fail w_journal_lib_open
    expect_string(__wrap__mwarn, formatted_msg, "(8010): Failed open journal log: 'Operation not permitted'.");

    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success

    // Call the function under test
    int ret = w_journal_context_create(&ctx);

    // Check the result
    assert_int_equal(ret, -1);
    assert_null(ctx);
}

// Test w_journal_context_free

// Test case for freeing a NULL context
static void test_w_journal_context_free_null(void ** state) {
    w_journal_context_t * ctx = NULL;
    w_journal_context_free(ctx); // Should not cause any issues

    // Assert
    assert_null(ctx);
}

// Test case for freeing a valid context
static void test_w_journal_context_free_valid(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success

    // Perform the function under test
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);

    // No need to check the memory deallocation of ctx since it's freed
}

// Test w_journal_context_update_timestamp

// Test for w_journal_context_update_timestamp succeeds
static void test_w_journal_context_update_timestamp_success(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    will_return(__wrap_sd_journal_get_realtime_usec, 123456); // Mocked timestamp
    w_journal_context_update_timestamp(ctx);

    // Verify that the timestamp has been updated correctly.
    assert_int_equal(ctx->timestamp, 123456);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test for w_journal_context_update_timestamp with null ctx
static void test_w_journal_context_update_timestamp_ctx_null(void ** state) {
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Perform the function under test
    w_journal_context_update_timestamp(ctx);
}

// Test for w_journal_context_update_timestamp with error when getting the timestamp
static void test_w_journal_context_update_timestamp_fail(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    will_return(__wrap_sd_journal_get_realtime_usec, -EACCES); // Fail to get the timestamp value and return an error
    will_return(__wrap_gettimeofday, NULL);
    expect_string(__wrap__mwarn,
                  formatted_msg,
                  "(8011): Failed to read timestamp from journal log: 'Permission denied'. Using current time.");
    w_journal_context_update_timestamp(ctx);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test w_journal_context_seek_most_recent

// Test for w_journal_context_seek_most_recent update timestamp
static void test_w_journal_context_seek_most_recent_update_tamestamp(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    will_return(__wrap_sd_journal_seek_tail, 0);              // Mocked return value
    will_return(__wrap_sd_journal_previous, 1);               // Mocked return value
    will_return(__wrap_sd_journal_get_realtime_usec, 123456); // Mocked timestamp
    int ret = w_journal_context_seek_most_recent(ctx);

    // Check the result
    assert_int_equal(ret, 1);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test for w_journal_context_seek_most_recent with error when seeking tail
static void test_w_journal_context_seek_most_recent_seek_tail_fail(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    will_return(__wrap_sd_journal_seek_tail, -1); // Mocked return value
    int ret = w_journal_context_seek_most_recent(ctx);

    // Check the result
    assert_int_equal(ret, -1);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test for w_journal_context_seek_most_recent success
static void test_w_journal_context_seek_most_recent_success(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    will_return(__wrap_sd_journal_seek_tail, 0); // Mocked return value
    will_return(__wrap_sd_journal_previous, 0);  // Mocked return value
    int ret = w_journal_context_seek_most_recent(ctx);

    // Check the result
    assert_int_equal(ret, 0);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test for w_journal_context_seek_most_recent with null ctx
static void test_w_journal_context_seek_most_recent_ctx_null(void ** state) {
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Perform the function under test
    int ret = w_journal_context_seek_most_recent(ctx);

    // Check the result
    assert_int_equal(ret, -1);
}

// Test w_journal_context_seek_timestamp

// Test for w_journal_context_seek_timestamp with null params
static void test_w_journal_context_seek_timestamp_null_params(void ** state) {
    assert_int_equal(w_journal_context_seek_timestamp(NULL, 0), -1);
}

// Test for w_journal_context_seek_timestamp with future timestamp
static void test_w_journal_context_seek_timestamp_future_timestamp(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    will_return(__wrap_gettimeofday, NULL);
    expect_string(__wrap__mwarn,
                  formatted_msg,
                  "(8012): The timestamp '1234567' is in the future or invalid. Using the most recent entry.");
    will_return(__wrap_sd_journal_seek_tail, 0); // Mocked return value
    will_return(__wrap_sd_journal_previous, 0);  // Mocked return value
    int ret = w_journal_context_seek_timestamp(ctx, 1234567);

    // Check the result
    assert_int_equal(ret, 0);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test for w_journal_context_seek_timestamp error when getting oldest timestamp
static void test_w_journal_context_seek_timestamp_fail_read_old_ts(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    struct timeval expected_time = {.tv_sec = 1234, .tv_usec = 5678};
    struct timeval actual_time;
    will_return(__wrap_gettimeofday, &expected_time);
    will_return(__wrap_sd_journal_get_cutoff_realtime_usec, -1); // Mocked oldest timestamp
    expect_string(__wrap__mwarn,
                  formatted_msg,
                  "(8013): Failed to read oldest timestamp from journal log: 'Operation not permitted'.");
    will_return(__wrap_sd_journal_seek_realtime_usec, 0);
    will_return(__wrap_sd_journal_next, 0);

    int ret = w_journal_context_seek_timestamp(ctx, 1234567);

    // Check the result
    assert_int_equal(ret, 0);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test for w_journal_context_seek_timestamp with timestamp older than oldest available
static void test_w_journal_context_seek_timestamp_change_ts(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    struct timeval expected_time = {.tv_sec = 1233, .tv_usec = 5678};
    struct timeval actual_time;
    will_return(__wrap_gettimeofday, &expected_time);
    will_return(__wrap_sd_journal_get_cutoff_realtime_usec, 22345678); // Mocked oldest timestamp
    expect_string(
        __wrap__mwarn,
        formatted_msg,
        "(8014): The timestamp '1234567' is older than the oldest available in journal. Using the oldest entry.");
    will_return(__wrap_sd_journal_seek_realtime_usec, 0);
    will_return(__wrap_sd_journal_next, 0);

    int ret = w_journal_context_seek_timestamp(ctx, 1234567);

    // Check the result
    assert_int_equal(ret, 0);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test for w_journal_context_seek_timestamp with error when seeking timestamp
static void test_w_journal_context_seek_timestamp_seek_timestamp_fail(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    struct timeval expected_time = {.tv_sec = 1234, .tv_usec = 5678};
    struct timeval actual_time;
    will_return(__wrap_gettimeofday, &expected_time);
    will_return(__wrap_sd_journal_get_cutoff_realtime_usec, 0); // Mocked oldest timestamp
    will_return(__wrap_sd_journal_seek_realtime_usec, -1);

    int ret = w_journal_context_seek_timestamp(ctx, 1234567);

    // Check the result
    assert_int_equal(ret, -1);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test for w_journal_context_seek_timestamp with error when seek the timestamp
static void test_w_journal_context_seek_timestamp_fail_seek(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    struct timeval expected_time = {.tv_sec = 1234, .tv_usec = 5678};
    struct timeval actual_time;
    will_return(__wrap_gettimeofday, &expected_time);
    will_return(__wrap_sd_journal_get_cutoff_realtime_usec, 0); // Mocked oldest timestamp
    will_return(__wrap_sd_journal_seek_realtime_usec, -1);

    int ret = w_journal_context_seek_timestamp(ctx, 1234567);

    // Check the result
    assert_int_equal(ret, -1);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test for w_journal_context_seek_timestamp with error when getting next entry
static void test_w_journal_context_seek_timestamp_next_fail(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    struct timeval expected_time = {.tv_sec = 1234, .tv_usec = 5678};
    struct timeval actual_time;
    will_return(__wrap_gettimeofday, &expected_time);
    will_return(__wrap_sd_journal_get_cutoff_realtime_usec, 0); // Mocked oldest timestamp
    will_return(__wrap_sd_journal_seek_realtime_usec, 0);
    will_return(__wrap_sd_journal_next, -1);

    int ret = w_journal_context_seek_timestamp(ctx, 1234567);

    // Check the result
    assert_int_equal(ret, -1);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test for w_journal_context_seek_timestamp success
static void test_w_journal_context_seek_timestamp_success(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    struct timeval expected_time = {.tv_sec = 1234, .tv_usec = 5678};
    struct timeval actual_time;
    will_return(__wrap_gettimeofday, &expected_time);
    will_return(__wrap_sd_journal_get_cutoff_realtime_usec, 0); // Mocked oldest timestamp
    will_return(__wrap_sd_journal_seek_realtime_usec, 0);
    will_return(__wrap_sd_journal_next, 0);

    int ret = w_journal_context_seek_timestamp(ctx, 123457);

    // Check the result
    assert_int_equal(ret, 0);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

static void test_w_journal_context_seek_timestamp_success_new_entry(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    struct timeval expected_time = {.tv_sec = 1234, .tv_usec = 5678};
    struct timeval actual_time;
    will_return(__wrap_gettimeofday, &expected_time);
    will_return(__wrap_sd_journal_get_cutoff_realtime_usec, 0); // Mocked oldest timestamp
    will_return(__wrap_sd_journal_seek_realtime_usec, 0);
    will_return(__wrap_sd_journal_next, 1);

    // update timestamp
    will_return(__wrap_sd_journal_get_realtime_usec, 123456); // Mocked timestamp

    int ret = w_journal_context_seek_timestamp(ctx, 123457);

    // Check the result
    assert_int_equal(ret, 1);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test w_journal_context_next_newest

// Test for w_journal_context_next_newest with null ctx
static void test_w_journal_context_next_newest_ctx_null(void ** state) {
    // Perform the function under test
    int ret = w_journal_context_next_newest(NULL);

    // Check the result
    assert_int_equal(ret, -1);
}

// Test for w_journal_context_next_newest updating timestamp
static void test_w_journal_context_next_newest_update_timestamp(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    will_return(__wrap_sd_journal_next, 1);                   // Mocked return value
    will_return(__wrap_sd_journal_get_realtime_usec, 123456); // Mocked timestamp

    int ret = w_journal_context_next_newest(ctx);

    // Check the result
    assert_int_equal(ret, 1);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test for w_journal_context_next_newest success
static void test_w_journal_context_next_newest_success(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    will_return(__wrap_sd_journal_next, 0); // Mocked return value

    int ret = w_journal_context_next_newest(ctx);

    // Check the result
    assert_int_equal(ret, 0);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test w_journal_filter_apply

// Test for w_journal_filter_apply with null params
void test_w_journal_filter_apply_null_params(void ** state) {

    assert_int_equal(w_journal_filter_apply(NULL, (w_journal_filter_t *) 0x1), -1);
    assert_int_equal(w_journal_filter_apply((w_journal_context_t *) 0x1, NULL), -1);
}

// Test for w_journal_filter_apply with fail to get data
void test_w_journal_filter_apply_fail_get_data_ignore_test(void ** state) {

    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt

    // Set timestamp
    ctx->timestamp = 123456;

    // Create filter for arg, ignore if missing data = false
    w_journal_filter_t * ufilters = NULL;
    assert_int_equal(0, w_journal_filter_add_condition(&ufilters, "field_to_ignore", ".", true));
    assert_int_equal(0, w_journal_filter_add_condition(&ufilters, "field_no_ignore", ".", false));

    // Apply filter expected
    expect_string(__wrap_sd_journal_get_data, field, "field_to_ignore");
    will_return(__wrap_sd_journal_get_data, -1); // Fail get data, ignore

    expect_string(__wrap_sd_journal_get_data, field, "field_no_ignore");
    will_return(__wrap_sd_journal_get_data, -1); // Fail get data, not ignore

    // Expect err message and return error
    expect_string(__wrap__mdebug2,
                  formatted_msg,
                  "(9003): Failed to get data field 'field_no_ignore' from entry with timestamp '123456'. Error: "
                  "Operation not permitted");

    // Apply filter
    assert_int_equal(-1, w_journal_filter_apply(ctx, ufilters));

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
    // Free filter
    w_journal_filter_free(ufilters);
}

// Test for w_journal_filter_apply with fail parse data
void test_w_journal_filter_apply_fail_parse(void ** state) {

    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt

    // Set timestamp
    ctx->timestamp = 123456;

    // Create filter for arg, ignore if missing data = false
    w_journal_filter_t * ufilters = NULL;
    assert_int_equal(0, w_journal_filter_add_condition(&ufilters, "field", ".", true));

    // Apply filter expected
    expect_string(__wrap_sd_journal_get_data, field, "field");
    will_return(__wrap_sd_journal_get_data, 0);    // get data ok, the load data
    will_return(__wrap_sd_journal_get_data, "f="); // Should be a valid data, 'field='

    // Apply filter
    assert_int_equal(-1, w_journal_filter_apply(ctx, ufilters));

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
    // Free filter
    w_journal_filter_free(ufilters);
}

// Test for w_journal_filter_apply with empty field
void test_w_journal_filter_apply_empty_field(void ** state) {

    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt

    // Set timestamp
    ctx->timestamp = 123456;

    // Create filter for arg, ignore if missing data = false
    w_journal_filter_t * ufilters = NULL;
    assert_int_equal(0, w_journal_filter_add_condition(&ufilters, "field", ".", true));

    // Apply filter expected
    expect_string(__wrap_sd_journal_get_data, field, "field");
    will_return(__wrap_sd_journal_get_data, 0);        // get data ok, the load data
    will_return(__wrap_sd_journal_get_data, "field="); // Empty field

    // Apply filter
    assert_int_equal(0, w_journal_filter_apply(ctx, ufilters));

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
    // Free filter
    w_journal_filter_free(ufilters);
}

// Test for w_journal_filter_apply with match fail
void test_w_journal_filter_apply_match_fail(void ** state) {

    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt

    // Set timestamp
    ctx->timestamp = 123456;

    // Create filter for arg, match with number fail
    w_journal_filter_t * ufilters = NULL;
    assert_int_equal(0, w_journal_filter_add_condition(&ufilters, "field", "^\\d", false));

    // Apply filter expected
    expect_string(__wrap_sd_journal_get_data, field, "field");
    will_return(__wrap_sd_journal_get_data, 0);                 // get data ok, the load data
    will_return(__wrap_sd_journal_get_data, "field=test text"); // Empty field

    // Apply filter
    assert_int_equal(0, w_journal_filter_apply(ctx, ufilters));

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
    // Free filter
    w_journal_filter_free(ufilters);
}

// Test for w_journal_filter_apply with match success
void test_w_journal_filter_apply_match_success(void ** state) {

    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt

    // Set timestamp
    ctx->timestamp = 123456;

    // Create filter for arg, match with number ok
    w_journal_filter_t * ufilters = NULL;
    assert_int_equal(0, w_journal_filter_add_condition(&ufilters, "field", "^\\d", false));

    // Apply filter expected
    expect_string(__wrap_sd_journal_get_data, field, "field");
    will_return(__wrap_sd_journal_get_data, 0);              // get data ok, the load data
    will_return(__wrap_sd_journal_get_data, "field=123123"); // Empty field

    // Apply filter
    assert_int_equal(1, w_journal_filter_apply(ctx, ufilters));

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
    // Free filter
    w_journal_filter_free(ufilters);
}

// Test w_journal_context_next_newest_filtered

// Test for w_journal_context_next_newest_filtered with null filters
static void test_w_journal_context_next_newest_filtered_null_filters(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    will_return(__wrap_sd_journal_next, 0); // Mocked return value
    int ret = w_journal_context_next_newest_filtered(ctx, NULL);

    // Check the result
    assert_int_equal(ret, 0);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test for w_journal_context_next_newest_filtered with no filters
static void test_w_journal_context_next_newest_filtered_no_filters(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    will_return(__wrap_sd_journal_next, 0); // Mocked return value
    int ret = w_journal_context_next_newest_filtered(ctx, (w_journal_filters_list_t) NULL);

    // Check the result
    assert_int_equal(ret, 0);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test for w_journal_context_next_newest_filtered with one filter
static void test_w_journal_context_next_newest_filtered_one_filter(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    will_return(__wrap_sd_journal_next, 0); // Mocked return value

    // Create filter for arg, ignore if missing data = false
    w_journal_filter_t * ufilters = NULL;
    assert_int_equal(0, w_journal_filter_add_condition(&ufilters, "field", ".", true));

    int ret = w_journal_context_next_newest_filtered(ctx, (w_journal_filters_list_t) ufilters);

    // Check the result
    assert_int_equal(ret, 0);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
    // Free filter
    w_journal_filter_free(ufilters);
}

// Test for w_journal_context_next_newest_filtered is debug
static void test_w_journal_context_next_newest_filtered_is_debug(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    will_return(__wrap_sd_journal_next, 1);                   // Mocked return value
    will_return(__wrap_sd_journal_get_realtime_usec, 123456); // Mocked timestamp

    // Create filter for arg, ignore if missing data = false
    w_journal_filter_t * ufilters = NULL;
    assert_int_equal(0, w_journal_filter_add_condition(&ufilters, "field", ".", true));

    // Set debug
    will_return(__wrap_isDebug, 1);

    will_return(__wrap_gmtime_r, 0); // Mocked time
    // mock mdebug2
    expect_string(__wrap__mdebug2, formatted_msg, "(9004): Checking filters for timestamp 'unknown'");

    int ret = w_journal_context_next_newest_filtered(ctx, (w_journal_filters_list_t) ufilters);

    // Check the result
    assert_int_equal(ret, 1);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
    // Free filter
    w_journal_filter_free(ufilters);
}

// Test for w_journal_context_next_newest_filtered is debug false
static void test_w_journal_context_next_newest_filtered_is_debug_false(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    will_return(__wrap_sd_journal_next, 1);                   // Mocked return value
    will_return(__wrap_sd_journal_get_realtime_usec, 123456); // Mocked timestamp

    // Create filter for arg, ignore if missing data = false
    w_journal_filter_t * ufilters = NULL;
    assert_int_equal(0, w_journal_filter_add_condition(&ufilters, "field", ".", true));

    // Set debug
    will_return(__wrap_isDebug, 0);

    int ret = w_journal_context_next_newest_filtered(ctx, (w_journal_filters_list_t) ufilters);

    // Check the result
    assert_int_equal(ret, 1);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
    // Free filter
    w_journal_filter_free(ufilters);
}

// Test for w_journal_context_next_newest_filtered with filter apply
static void test_w_journal_context_next_newest_filtered_filter_apply(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    will_return(__wrap_sd_journal_next, 1);                   // Mocked return value
    will_return(__wrap_sd_journal_get_realtime_usec, 123456); // Mocked timestamp

    // Set debug
    will_return(__wrap_isDebug, 0);

    // Create filter for arg, ignore if missing data = false
    w_journal_filters_list_t filter_list = NULL;

    // Prepare the filter
    w_journal_filter_t * ufilters = NULL;
    assert_int_equal(0, w_journal_filter_add_condition(&ufilters, "field", ".", true));
    // Add filter to the list
    assert_true(w_journal_add_filter_to_list(&filter_list, ufilters));

    // Apply filter expected
    expect_string(__wrap_sd_journal_get_data, field, "field");
    will_return(__wrap_sd_journal_get_data, 0);              // get data ok, the load data
    will_return(__wrap_sd_journal_get_data, "field=123123"); // Empty field

    int ret = w_journal_context_next_newest_filtered(ctx, filter_list);

    // Check the result
    assert_int_equal(ret, 1);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
    // Free filter list
    w_journal_filters_list_free(filter_list);
}

// Test for w_journal_context_next_newest_filtered with filter apply fail
static void test_w_journal_context_next_newest_filtered_filter_apply_fail(void ** state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t * ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE * maps_file = (FILE *) 0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // test_is_owned_by_root_root_owned

    const char * library_path = "/libsystemd.so.0";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    void * handle = (void *) 1; // Simulate handle
    void * mock_function = (void *) 0xabcdef;

    // Set expectations for dlsym wrap
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");

    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);

    // Perform the function under test
    will_return(__wrap_sd_journal_next, 1);                   // Mocked return value
    will_return(__wrap_sd_journal_get_realtime_usec, 123456); // Mocked timestamp

    // Set debug
    will_return(__wrap_isDebug, 0);

    // Create filter for arg, ignore if missing data = false
    w_journal_filters_list_t filter_list = NULL;

    // Prepare the filter
    w_journal_filter_t * ufilters = NULL;
    assert_int_equal(0, w_journal_filter_add_condition(&ufilters, "field", "^\\d", true));
    // Add filter to the list
    assert_true(w_journal_add_filter_to_list(&filter_list, ufilters));

    // Apply filter expected
    expect_string(__wrap_sd_journal_get_data, field, "field");
    will_return(__wrap_sd_journal_get_data, 0);            // get data ok, the load data
    will_return(__wrap_sd_journal_get_data, "field=test"); // Empty field

    will_return(__wrap_sd_journal_next, 0);

    int ret = w_journal_context_next_newest_filtered(ctx, filter_list);

    // Check the result
    assert_int_equal(ret, 0);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *) 0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);                          // Simulate dlclose success
    w_journal_context_free(ctx);
    // Free filter list
    w_journal_filters_list_free(filter_list);
}

// Test entry_as_json
void test_entry_as_json_empty(void ** state) {

    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt

    // Expect
    will_return(__wrap_cJSON_CreateObject, (cJSON *) 0x123456);
    will_return(__wrap_sd_journal_restart_data, 0);
    // Empty entry
    will_return(__wrap_sd_journal_enumerate_data, 0);
    expect_function_call(__wrap_cJSON_Delete);

    assert_null(entry_as_json(ctx));

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_entry_as_json_fail_parse_field(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt

    // Expect
    will_return(__wrap_cJSON_CreateObject, (cJSON *) 0x123456);
    will_return(__wrap_sd_journal_restart_data, 0);
    // Empty entry
    will_return(__wrap_sd_journal_enumerate_data, 1);
    will_return(__wrap_sd_journal_enumerate_data, "field >> no equal sign");
    will_return(__wrap_sd_journal_enumerate_data, 0);
    expect_function_call(__wrap_cJSON_Delete);

    assert_null(entry_as_json(ctx));

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_entry_as_json_success(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt

    // Expect
    will_return(__wrap_cJSON_CreateObject, (cJSON *) 0x123456);
    will_return(__wrap_sd_journal_restart_data, 0);
    // 3 entryes
    will_return(__wrap_sd_journal_enumerate_data, 1);
    will_return(__wrap_sd_journal_enumerate_data, "field=value");
    expect_string(__wrap_cJSON_AddStringToObject, name, "field");
    expect_string(__wrap_cJSON_AddStringToObject, string, "value");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    will_return(__wrap_sd_journal_enumerate_data, 1);
    will_return(__wrap_sd_journal_enumerate_data, "field2=123");
    expect_string(__wrap_cJSON_AddStringToObject, name, "field2");
    expect_string(__wrap_cJSON_AddStringToObject, string, "123");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    will_return(__wrap_sd_journal_enumerate_data, 1);
    will_return(__wrap_sd_journal_enumerate_data, "field3=");
    expect_string(__wrap_cJSON_AddStringToObject, name, "field3");
    expect_string(__wrap_cJSON_AddStringToObject, string, "");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    will_return(__wrap_sd_journal_enumerate_data, 0);

    assert_non_null(entry_as_json(ctx));

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

// Test get_field_ptr
void test_get_field_ptr_fail_get_data(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt

    // Expect
    expect_string(__wrap_sd_journal_get_data, field, "field");
    will_return(__wrap_sd_journal_get_data, -1);

    assert_null(get_field_ptr(ctx, "field"));

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_get_field_ptr_fail_parse(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt

    // Expect
    expect_string(__wrap_sd_journal_get_data, field, "field");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "field >> no equal sign");

    assert_null(get_field_ptr(ctx, "field"));

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_get_field_ptr_empty_field(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt

    // Expect
    expect_string(__wrap_sd_journal_get_data, field, "field");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "field=");

    char * value = get_field_ptr(ctx, "field");
    assert_non_null(value);
    assert_string_equal(value, "");
    os_free(value);

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_get_field_ptr_success(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt

    // Expect
    expect_string(__wrap_sd_journal_get_data, field, "field");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "field=value");

    char * val = get_field_ptr(ctx, "field");
    assert_non_null(val);
    assert_string_equal(val, "value");
    os_free(val);

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

// Test create_plain_syslog
void test_create_plain_syslog_with_pid(void ** state) {

    char * retval = create_plain_syslog("<timestamp>", "hosname", "tag", "pid", "message");
    assert_non_null(retval);
    assert_string_equal(retval, "<timestamp> hosname tag[pid]: message");
    os_free(retval);
}

void test_create_plain_syslog_without_pid(void ** state) {

    char * retval = create_plain_syslog("<timestamp>", "hosname", "tag", NULL, "message");
    assert_non_null(retval);
    assert_string_equal(retval, "<timestamp> hosname tag: message");
    os_free(retval);
}

// Test entry_as_syslog
void test_entry_as_syslog_success(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt
    uint64_t timestamp = 1618849174000000; // Timestamp in microseconds (2021-04-19 16:19:34)
    ctx->timestamp = timestamp;

    // Extract
    expect_string(__wrap_sd_journal_get_data, field, "_HOSTNAME");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "_HOSTNAME=<hostname>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_IDENTIFIER");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "SYSLOG_IDENTIFIER=<tag>");

    expect_string(__wrap_sd_journal_get_data, field, "MESSAGE");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "MESSAGE=<message>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_PID");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "SYSLOG_PID=<pid>");

    // Get timestamp

    will_return(__wrap_gmtime_r, timestamp);

    // Check the result
    char * retval = entry_as_syslog(ctx);
    assert_non_null(retval);
    assert_string_equal(retval, "Apr 19 16:19:34 <hostname> <tag>[<pid>]: <message>");
    os_free(retval);

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_entry_as_syslog_success_system_pid(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt
    uint64_t timestamp = 1618849174000000; // Timestamp in microseconds (2021-04-19 16:19:34)
    ctx->timestamp = timestamp;

    // Extract
    expect_string(__wrap_sd_journal_get_data, field, "_HOSTNAME");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "_HOSTNAME=<hostname>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_IDENTIFIER");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "SYSLOG_IDENTIFIER=<tag>");

    expect_string(__wrap_sd_journal_get_data, field, "MESSAGE");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "MESSAGE=<message>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_PID");
    will_return(__wrap_sd_journal_get_data, -1);

    expect_string(__wrap_sd_journal_get_data, field, "_PID");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "_PID=<spid>");

    // Get timestamp

    will_return(__wrap_gmtime_r, timestamp);

    // Check the result
    char * retval = entry_as_syslog(ctx);
    assert_non_null(retval);
    assert_string_equal(retval, "Apr 19 16:19:34 <hostname> <tag>[<spid>]: <message>");
    os_free(retval);

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_entry_as_syslog_success_no_pid(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt
    uint64_t timestamp = 1618849174000000; // Timestamp in microseconds (2021-04-19 16:19:34)
    ctx->timestamp = timestamp;

    // Extract
    expect_string(__wrap_sd_journal_get_data, field, "_HOSTNAME");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "_HOSTNAME=<hostname>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_IDENTIFIER");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "SYSLOG_IDENTIFIER=<tag>");

    expect_string(__wrap_sd_journal_get_data, field, "MESSAGE");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "MESSAGE=<message>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_PID");
    will_return(__wrap_sd_journal_get_data, -1);

    expect_string(__wrap_sd_journal_get_data, field, "_PID");
    will_return(__wrap_sd_journal_get_data, -1);

    // Get timestamp

    will_return(__wrap_gmtime_r, timestamp);

    // Check the result
    char * retval = entry_as_syslog(ctx);
    assert_non_null(retval);
    assert_string_equal(retval, "Apr 19 16:19:34 <hostname> <tag>: <message>");
    os_free(retval);

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_entry_as_syslog_missing_hostname(void ** state) {

    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt
    uint64_t timestamp = 1618849174000000; // Timestamp in microseconds (2021-04-19 16:19:34)
    ctx->timestamp = timestamp;

    // Extract
    expect_string(__wrap_sd_journal_get_data, field, "_HOSTNAME");
    will_return(__wrap_sd_journal_get_data, -1);

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_IDENTIFIER");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "SYSLOG_IDENTIFIER=<tag>");

    expect_string(__wrap_sd_journal_get_data, field, "MESSAGE");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "MESSAGE=<message>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_PID");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "SYSLOG_PID=<pid>");

    // Get timestamp
    will_return(__wrap_gmtime_r, timestamp);

    // Debug msg
    expect_string(__wrap__mdebug2,
                  formatted_msg,
                  "(9002): Failed to get the required fields, discarted log with timestamp '1618849174000000'");

    // Check the result
    char * retval = entry_as_syslog(ctx);
    assert_null(retval);

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_entry_as_syslog_missing_tag(void ** state) {

    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt
    uint64_t timestamp = 1618849174000000; // Timestamp in microseconds (2021-04-19 16:19:34)
    ctx->timestamp = timestamp;

    // Extract
    expect_string(__wrap_sd_journal_get_data, field, "_HOSTNAME");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "_HOSTNAME=<hostname>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_IDENTIFIER");
    will_return(__wrap_sd_journal_get_data, -1);

    expect_string(__wrap_sd_journal_get_data, field, "MESSAGE");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "MESSAGE=<message>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_PID");
    will_return(__wrap_sd_journal_get_data, -1);

    expect_string(__wrap_sd_journal_get_data, field, "_PID");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "_PID=<spid>");

    // Get timestamp
    will_return(__wrap_gmtime_r, timestamp);

    // Debug msg
    expect_string(__wrap__mdebug2,
                  formatted_msg,
                  "(9002): Failed to get the required fields, discarted log with timestamp '1618849174000000'");

    // Check the result
    char * retval = entry_as_syslog(ctx);
    assert_null(retval);

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_entry_as_syslog_missing_message(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt
    uint64_t timestamp = 1618849174000000; // Timestamp in microseconds (2021-04-19 16:19:34)
    ctx->timestamp = timestamp;

    // Extract
    expect_string(__wrap_sd_journal_get_data, field, "_HOSTNAME");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "_HOSTNAME=<hostname>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_IDENTIFIER");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "SYSLOG_IDENTIFIER=<tag>");

    expect_string(__wrap_sd_journal_get_data, field, "MESSAGE");
    will_return(__wrap_sd_journal_get_data, -1);

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_PID");
    will_return(__wrap_sd_journal_get_data, -1);

    expect_string(__wrap_sd_journal_get_data, field, "_PID");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "_PID=<spid>");

    // Get timestamp
    will_return(__wrap_gmtime_r, timestamp);

    // Debug msg
    expect_string(__wrap__mdebug2,
                  formatted_msg,
                  "(9002): Failed to get the required fields, discarted log with timestamp '1618849174000000'");

    // Check the result
    char * retval = entry_as_syslog(ctx);
    assert_null(retval);

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_entry_as_syslog_missing_timestamp(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt
    uint64_t timestamp = 1618849174000000; // Timestamp in microseconds (2021-04-19 16:19:34)
    ctx->timestamp = timestamp;

    // Extract
    expect_string(__wrap_sd_journal_get_data, field, "_HOSTNAME");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "_HOSTNAME=<hostname>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_IDENTIFIER");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "SYSLOG_IDENTIFIER=<tag>");

    expect_string(__wrap_sd_journal_get_data, field, "MESSAGE");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "MESSAGE=<message>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_PID");
    will_return(__wrap_sd_journal_get_data, -1);

    expect_string(__wrap_sd_journal_get_data, field, "_PID");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "_PID=<spid>");

    // Get timestamp
    will_return(__wrap_gmtime_r, 0);

    // Debug msg
    expect_string(__wrap__mdebug2,
                  formatted_msg,
                  "(9002): Failed to get the required fields, discarted log with timestamp '1618849174000000'");

    // Check the result
    char * retval = entry_as_syslog(ctx);
    assert_null(retval);

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

// Test w_journal_entry_dump
void test_w_journal_entry_dump_null_params(void ** state) {
    assert_null(w_journal_entry_dump(NULL, W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG));
    assert_null(w_journal_entry_dump(NULL, W_JOURNAL_ENTRY_DUMP_TYPE_JSON));
}

void test_w_journal_entry_dump_invalid_type(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt
    ctx->timestamp = 123456;
    ctx->journal = (void *) 0x123456;

    assert_null(w_journal_entry_dump(ctx, W_JOURNAL_ENTRY_DUMP_TYPE_INVALID));

    // Test Free invalid
    w_journal_entry_t * entry = calloc(1, sizeof(w_journal_entry_t));
    entry->type = W_JOURNAL_ENTRY_DUMP_TYPE_INVALID;
    entry->timestamp = ctx->timestamp;
    assert_null(w_journal_entry_dump(ctx, W_JOURNAL_ENTRY_DUMP_TYPE_INVALID));
    w_journal_entry_free(entry);

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_w_journal_entry_dump_json_success(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt
    ctx->timestamp = 123456;
    ctx->journal = (void *) 0x123456;

    // Expect
    will_return(__wrap_cJSON_CreateObject, (cJSON *) 0x123456);
    will_return(__wrap_sd_journal_restart_data, 0);
    // 3 entryes
    will_return(__wrap_sd_journal_enumerate_data, 1);
    will_return(__wrap_sd_journal_enumerate_data, "field=value");
    expect_string(__wrap_cJSON_AddStringToObject, name, "field");
    expect_string(__wrap_cJSON_AddStringToObject, string, "value");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    will_return(__wrap_sd_journal_enumerate_data, 1);
    will_return(__wrap_sd_journal_enumerate_data, "field2=123");
    expect_string(__wrap_cJSON_AddStringToObject, name, "field2");
    expect_string(__wrap_cJSON_AddStringToObject, string, "123");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    will_return(__wrap_sd_journal_enumerate_data, 1);
    will_return(__wrap_sd_journal_enumerate_data, "field3=");
    expect_string(__wrap_cJSON_AddStringToObject, name, "field3");
    expect_string(__wrap_cJSON_AddStringToObject, string, "");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    will_return(__wrap_sd_journal_enumerate_data, 0);

    w_journal_entry_t * entry = w_journal_entry_dump(ctx, W_JOURNAL_ENTRY_DUMP_TYPE_JSON);
    assert_non_null(entry);
    assert_non_null(entry->data.json);
    assert_int_equal(entry->type, W_JOURNAL_ENTRY_DUMP_TYPE_JSON);
    assert_int_equal(entry->timestamp, ctx->timestamp);

    // Free entry (test)
    expect_function_call(__wrap_cJSON_Delete);
    w_journal_entry_free(entry);

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_w_journal_entry_dump_syslog_fail_json(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt
    ctx->timestamp = 123456;
    ctx->journal = (void *) 0x123456;

    // Expect
    will_return(__wrap_cJSON_CreateObject, (cJSON *) 0x123456);
    will_return(__wrap_sd_journal_restart_data, 0);
    // Empty entry
    will_return(__wrap_sd_journal_enumerate_data, 0);
    expect_function_call(__wrap_cJSON_Delete);

    w_journal_entry_t * entry = w_journal_entry_dump(ctx, W_JOURNAL_ENTRY_DUMP_TYPE_JSON);
    assert_null(entry);

    // Free entry (test)
    w_journal_entry_free(entry);

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_w_journal_entry_dump_syslog_success(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt
    ctx->journal = (void *) 0x123456;
    uint64_t timestamp = 1618849174000000; // Timestamp in microseconds (2021-04-19 16:19:34)
    ctx->timestamp = timestamp;

    // Expect

    // Extract
    expect_string(__wrap_sd_journal_get_data, field, "_HOSTNAME");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "_HOSTNAME=<hostname>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_IDENTIFIER");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "SYSLOG_IDENTIFIER=<tag>");

    expect_string(__wrap_sd_journal_get_data, field, "MESSAGE");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "MESSAGE=<message>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_PID");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "SYSLOG_PID=<pid>");

    // Get timestamp
    will_return(__wrap_gmtime_r, timestamp);

    w_journal_entry_t * entry = w_journal_entry_dump(ctx, W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG);
    assert_non_null(entry);
    assert_non_null(entry->data.syslog);
    assert_int_equal(entry->type, W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG);
    assert_int_equal(entry->timestamp, ctx->timestamp);

    // Free entry (test)
    w_journal_entry_free(entry);

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_w_journal_entry_dump_syslog_fail(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt
    ctx->journal = (void *) 0x123456;
    uint64_t timestamp = 1618849174000000; // Timestamp in microseconds (2021-04-19 16:19:34)
    ctx->timestamp = timestamp;

    // Extract fail
    expect_string(__wrap_sd_journal_get_data, field, "_HOSTNAME");
    will_return(__wrap_sd_journal_get_data, -1);

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_IDENTIFIER");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "SYSLOG_IDENTIFIER=<tag>");

    expect_string(__wrap_sd_journal_get_data, field, "MESSAGE");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "MESSAGE=<message>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_PID");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "SYSLOG_PID=<pid>");

    // Get timestamp
    will_return(__wrap_gmtime_r, timestamp);

    // Debug msg
    expect_string(__wrap__mdebug2,
                  formatted_msg,
                  "(9002): Failed to get the required fields, discarted log with timestamp '1618849174000000'");

    // Get timestamp

    w_journal_entry_t * entry = w_journal_entry_dump(ctx, W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG);
    assert_null(entry);
    // Free entry (test)
    w_journal_entry_free(entry);

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

// Test w_journal_entry_to_string
void test_w_journal_entry_to_string_null_params(void ** state) { assert_null(w_journal_entry_to_string(NULL)); }

void test_w_journal_entry_to_string_syslog(void ** state) {
    // init ctx
    w_journal_context_t * ctx = NULL;
    // >>>> Start Init conext
    //      w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *) 0x123456);
    //      find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");
    FILE * maps_file = (FILE *) 0x123456;
    will_return(__wrap_fopen, maps_file);
    char * simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
    will_return(__wrap_getline, simulated_line);
    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);
    //      is_owned_by_root_root_owned
    const char * library_path = "/libsystemd.so.0";
    struct stat mock_stat;
    mock_stat.st_uid = 0;
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);
    void * handle = (void *) 1;
    void * mock_function = (void *) 0xabcdef;
    //     dlsym
    setup_dlsym_expectations("sd_journal_open");
    setup_dlsym_expectations("sd_journal_close");
    setup_dlsym_expectations("sd_journal_previous");
    setup_dlsym_expectations("sd_journal_next");
    setup_dlsym_expectations("sd_journal_seek_tail");
    setup_dlsym_expectations("sd_journal_seek_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_realtime_usec");
    setup_dlsym_expectations("sd_journal_get_data");
    setup_dlsym_expectations("sd_journal_restart_data");
    setup_dlsym_expectations("sd_journal_enumerate_data");
    setup_dlsym_expectations("sd_journal_get_cutoff_realtime_usec");
    will_return(__wrap_sd_journal_open, 0);
    w_journal_context_create(&ctx);
    // <<<< End init conetxt
    ctx->journal = (void *) 0x123456;
    uint64_t timestamp = 1618849174000000; // Timestamp in microseconds (2021-04-19 16:19:34)
    ctx->timestamp = timestamp;

    // Expect

    // Extract
    expect_string(__wrap_sd_journal_get_data, field, "_HOSTNAME");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "_HOSTNAME=<hostname>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_IDENTIFIER");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "SYSLOG_IDENTIFIER=<tag>");

    expect_string(__wrap_sd_journal_get_data, field, "MESSAGE");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "MESSAGE=<message>");

    expect_string(__wrap_sd_journal_get_data, field, "SYSLOG_PID");
    will_return(__wrap_sd_journal_get_data, 0);
    will_return(__wrap_sd_journal_get_data, "SYSLOG_PID=<pid>");

    // Get timestamp
    will_return(__wrap_gmtime_r, timestamp);

    w_journal_entry_t * entry = w_journal_entry_dump(ctx, W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG);
    assert_non_null(entry);
    assert_non_null(entry->data.syslog);
    assert_int_equal(entry->type, W_JOURNAL_ENTRY_DUMP_TYPE_SYSLOG);
    assert_int_equal(entry->timestamp, ctx->timestamp);

    char * str = w_journal_entry_to_string(entry);
    assert_non_null(str);
    assert_string_equal(str, "Apr 19 16:19:34 <hostname> <tag>[<pid>]: <message>");

    // Free entry (test)
    os_free(str);
    w_journal_entry_free(entry);

    // >>>> Start context free
    expect_value(__wrap_dlclose, handle, (void *) 0x123456);
    will_return(__wrap_dlclose, 0);
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);
    // <<<< End Context free
}

void test_w_journal_entry_to_string_json(void ** state) {
    w_journal_entry_t * entry = calloc(1, sizeof(w_journal_entry_t));
    entry->type = W_JOURNAL_ENTRY_DUMP_TYPE_JSON;
    entry->timestamp = 123456;
    entry->data.json = (cJSON *) 0x123456;

    will_return(__wrap_cJSON_PrintUnformatted, strdup("json_string"));
    char * str = w_journal_entry_to_string(entry);

    assert_non_null(str);
    assert_string_equal(str, "json_string");

    os_free(str);
    os_free(entry);
}

void test_w_journal_entry_to_string_invalid_type(void ** state) {

    w_journal_entry_t * entry = calloc(1, sizeof(w_journal_entry_t));
    entry->type = W_JOURNAL_ENTRY_DUMP_TYPE_INVALID;
    entry->timestamp = 123456;
    entry->data.json = (cJSON *) 0x123456;

    char * str = w_journal_entry_to_string(entry);

    assert_null(str);

    os_free(entry);
}

int main(void) {

    const struct CMUnitTest tests[] = {
        // Test is_owned_by_root
        cmocka_unit_test(test_is_owned_by_root_root_owned),
        cmocka_unit_test(test_is_owned_by_root_not_root_owned),
        cmocka_unit_test(test_is_owned_by_root_stat_fails),
        // Test load_and_validate_function
        cmocka_unit_test(test_load_and_validate_function_success),
        cmocka_unit_test(test_load_and_validate_function_failure),
        // Test w_get_epoch_time
        cmocka_unit_test(test_w_get_epoch_time),
        // Test w_timestamp_to_string
        cmocka_unit_test(test_w_timestamp_to_string),
        cmocka_unit_test(test_w_timestamp_to_journalctl_since_success),
        cmocka_unit_test(test_w_timestamp_to_journalctl_since_failure),
        // Test find_library_path
        cmocka_unit_test(test_find_library_path_success),
        cmocka_unit_test(test_find_library_path_failure),
        // Test w_journal_context_create
        cmocka_unit_test(test_w_journal_lib_init_dlopen_fail),
        cmocka_unit_test(test_w_journal_lib_init_find_library_path_fail),
        cmocka_unit_test(test_w_journal_lib_init_is_owned_by_root_fail),
        cmocka_unit_test(test_w_journal_lib_init_load_and_validate_function_fail),
        cmocka_unit_test(test_w_journal_lib_init_success),
        // Test w_journal_context_create
        cmocka_unit_test(test_w_journal_context_create_success),
        cmocka_unit_test(test_w_journal_context_create_null_pointer),
        cmocka_unit_test(test_w_journal_context_create_lib_init_fail),
        cmocka_unit_test(test_w_journal_context_create_journal_open_fail),
        // Test w_journal_context_free
        cmocka_unit_test(test_w_journal_context_free_null),
        cmocka_unit_test(test_w_journal_context_free_valid),
        // Test w_journal_context_update_timestamp
        cmocka_unit_test(test_w_journal_context_update_timestamp_success),
        cmocka_unit_test(test_w_journal_context_update_timestamp_ctx_null),
        cmocka_unit_test(test_w_journal_context_update_timestamp_fail),
        // Test w_journal_context_seek_timestamp
        cmocka_unit_test(test_w_journal_context_seek_most_recent_update_tamestamp),
        cmocka_unit_test(test_w_journal_context_seek_most_recent_seek_tail_fail),
        cmocka_unit_test(test_w_journal_context_seek_most_recent_success),
        cmocka_unit_test(test_w_journal_context_seek_most_recent_ctx_null),
        // Test w_journal_context_seek_timestamp
        cmocka_unit_test(test_w_journal_context_seek_timestamp_null_params),
        cmocka_unit_test(test_w_journal_context_seek_timestamp_future_timestamp),
        cmocka_unit_test(test_w_journal_context_seek_timestamp_fail_read_old_ts),
        cmocka_unit_test(test_w_journal_context_seek_timestamp_change_ts),
        cmocka_unit_test(test_w_journal_context_seek_timestamp_fail_seek),
        cmocka_unit_test(test_w_journal_context_seek_timestamp_seek_timestamp_fail),
        cmocka_unit_test(test_w_journal_context_seek_timestamp_next_fail),
        cmocka_unit_test(test_w_journal_context_seek_timestamp_success),
        cmocka_unit_test(test_w_journal_context_seek_timestamp_success_new_entry),
        // Test w_journal_context_next_newest
        cmocka_unit_test(test_w_journal_context_next_newest_ctx_null),
        cmocka_unit_test(test_w_journal_context_next_newest_update_timestamp),
        cmocka_unit_test(test_w_journal_context_next_newest_success),
        // Test w_journal_filter_apply
        cmocka_unit_test(test_w_journal_filter_apply_null_params),
        cmocka_unit_test(test_w_journal_filter_apply_fail_get_data_ignore_test),
        cmocka_unit_test(test_w_journal_filter_apply_fail_parse),
        cmocka_unit_test(test_w_journal_filter_apply_empty_field),
        cmocka_unit_test(test_w_journal_filter_apply_match_fail),
        cmocka_unit_test(test_w_journal_filter_apply_match_success),
        // Test w_journal_context_next_newest_filtered
        cmocka_unit_test(test_w_journal_context_next_newest_filtered_null_filters),
        cmocka_unit_test(test_w_journal_context_next_newest_filtered_no_filters),
        cmocka_unit_test(test_w_journal_context_next_newest_filtered_one_filter),
        cmocka_unit_test(test_w_journal_context_next_newest_filtered_is_debug),
        cmocka_unit_test(test_w_journal_context_next_newest_filtered_is_debug_false),
        cmocka_unit_test(test_w_journal_context_next_newest_filtered_filter_apply),
        cmocka_unit_test(test_w_journal_context_next_newest_filtered_filter_apply_fail),
        // Test entry_as_json
        cmocka_unit_test(test_entry_as_json_empty),
        cmocka_unit_test(test_entry_as_json_fail_parse_field),
        cmocka_unit_test(test_entry_as_json_success),
        // Test get_field_ptr
        cmocka_unit_test(test_get_field_ptr_fail_get_data),
        cmocka_unit_test(test_get_field_ptr_fail_parse),
        cmocka_unit_test(test_get_field_ptr_empty_field),
        cmocka_unit_test(test_get_field_ptr_success),
        // Test create_plain_syslog
        cmocka_unit_test(test_create_plain_syslog_with_pid),
        cmocka_unit_test(test_create_plain_syslog_without_pid),
        // Test entry_as_syslog
        cmocka_unit_test(test_entry_as_syslog_success),
        cmocka_unit_test(test_entry_as_syslog_success_system_pid),
        cmocka_unit_test(test_entry_as_syslog_success_no_pid),
        cmocka_unit_test(test_entry_as_syslog_missing_hostname),
        cmocka_unit_test(test_entry_as_syslog_missing_tag),
        cmocka_unit_test(test_entry_as_syslog_missing_message),
        cmocka_unit_test(test_entry_as_syslog_missing_timestamp),
        // Test w_journal_entry_dump
        cmocka_unit_test(test_w_journal_entry_dump_null_params),
        cmocka_unit_test(test_w_journal_entry_dump_invalid_type),
        cmocka_unit_test(test_w_journal_entry_dump_json_success),
        cmocka_unit_test(test_w_journal_entry_dump_syslog_fail_json),
        cmocka_unit_test(test_w_journal_entry_dump_syslog_success),
        cmocka_unit_test(test_w_journal_entry_dump_syslog_fail),
        // Test w_journal_entry_to_string
        cmocka_unit_test(test_w_journal_entry_to_string_null_params),
        cmocka_unit_test(test_w_journal_entry_to_string_syslog),
        cmocka_unit_test(test_w_journal_entry_to_string_json),
        cmocka_unit_test(test_w_journal_entry_to_string_invalid_type),

    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
