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
#include "../wrappers/libc/stdio_wrappers.h"

#define _XOPEN_SOURCE

bool is_owned_by_root(const char * library_path);
bool load_and_validate_function(void * handle, const char * name, void ** func);
uint64_t w_get_epoch_time();
char * w_timestamp_to_string(uint64_t timestamp);
char * w_timestamp_to_journalctl_since(uint64_t timestamp);
char * find_library_path(const char * library_name);
w_journal_lib_t * w_journal_lib_init();

//Mocks

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

int __wrap_sd_journal_get_data(sd_journal * j, const char * field, const void ** data, size_t * length) { return mock_type(int); }

int __wrap_sd_journal_restart_data(sd_journal * j) { return mock_type(int); }

int __wrap_sd_journal_enumerate_data(sd_journal * j, const void ** data, size_t * length) { return mock_type(int); }

int __wrap_sd_journal_get_cutoff_realtime_usec(sd_journal * j, uint64_t * from, uint64_t * to) {
    int64_t ret = mock_type(int64_t);
    if (ret >= 0) {
        *from = (uint64_t) ret;
        return 0;
    }
    return ret;
}

// Mock dlsym function to simulate the loading of valid and invalid functions
// Mock dlsym function
extern void *__real_dlsym(void *handle, const char *symbol);
void *__wrap_dlsym(void *handle, const char *symbol) {
    if (test_mode) {
        check_expected_ptr(handle);
        check_expected_ptr(symbol);
        return mock_ptr_type(void *);
    } else {
        return __real_dlsym(handle, symbol);
    }
}

// Mock dlerror function
extern char *__real_dlerror(void);
char *__wrap_dlerror(void) {
    if (test_mode) {
        return mock_ptr_type(char *);
    } else {
        return __real_dlerror();
    }
}

// Mock gmtime_r function
extern unsigned int __real_gmtime_r(const time_t *t, struct tm *tm);
unsigned int __wrap_gmtime_r(__attribute__ ((__unused__)) const time_t *t, __attribute__ ((__unused__)) struct tm *tm) {
    unsigned int mock = mock_type(unsigned int);
    if (mock == 0) {
        return mock;
    } else {
        return __real_gmtime_r(t, tm);
    }
}

// Mock getline function
extern ssize_t __real_getline(char **lineptr, size_t *n, FILE *stream);
ssize_t __wrap_getline(char **lineptr, size_t *n, FILE *stream) {
    if (test_mode) {
        // Asegurarse de que se pase un puntero no nulo para lineptr
        assert_non_null(lineptr);

        // Configurar la línea simulada y su longitud
        *lineptr = mock_ptr_type(char *);
        *n = strlen(*lineptr);

        // Retornar la longitud de la línea simulada
        return *n;
    } else {
        return __real_getline(lineptr, n, stream);
    }
}

// Mock dlopen function
extern void *__real_dlopen(const char *filename, int flags);
void *__wrap_dlopen(const char *filename, int flags) {
    if (test_mode) {
        check_expected_ptr(filename);
        check_expected(flags);
        return mock_ptr_type(void *);
    } else {
        return __real_dlopen(filename, flags);
    }
}

// Mock dlclose function
extern int __real_dlclose(void *handle);
int __wrap_dlclose(void *handle) {
    if (test_mode) {
        check_expected_ptr(handle);
        return mock();
    } else {
        return __real_dlclose(handle);
    }
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
    void *mock_function = (void *)0xabcdef;
    const char *function_name = "valid_function";
    void *function_pointer;

    expect_any(__wrap_dlsym, handle);
    expect_string(__wrap_dlsym, symbol, "valid_function");
    will_return(__wrap_dlsym, mock_function);
    
    // Act
    bool result = load_and_validate_function(handle, function_name, &function_pointer);
    
    // Assert
    assert_true(result);
    assert_non_null(function_pointer);
}

static void test_load_and_validate_function_failure(void **state) {
    // Arrange
    void *handle = NULL;  // Simulate invalid handle
    void *mock_function = NULL;
    const char *function_name = "invalid_function";
    void *function_pointer = (void *)1;

    expect_any(__wrap_dlsym, handle);
    expect_string(__wrap_dlsym, symbol, "invalid_function");
    will_return(__wrap_dlsym, mock_function);

    will_return(__wrap_dlerror,"ERROR");

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
    will_return(__wrap_gettimeofday, 0);
    
    // Act
    uint64_t result = w_get_epoch_time();

    // Cant assert the result because it is a time value and the wrapper is not set in the test
    // assert_int_equal(result, 0); 
}

//Test w_timestamp_to_string

static void test_w_timestamp_to_string(void **state) {
    // Arrange
    uint64_t timestamp = 1618849174000000; // Timestamp in microseconds
    will_return(__wrap_gmtime_r, 1);
    
    // Act
    char *result = w_timestamp_to_string(timestamp);
    
    // Assert
    free(result);
}

//Test w_timestamp_to_journalctl_since

static void test_w_timestamp_to_journalctl_since_success(void **state) {
    // Arrange
    uint64_t timestamp = 1618849174000000; // Timestamp in microseconds (2021-04-19 16:19:34)

    will_return(__wrap_gmtime_r, 1618849174000000);
    
    // Act
    char *result = w_timestamp_to_journalctl_since(timestamp);
    
    // Assert
    assert_non_null(result);

    // Verify the result is the expected format
    assert_int_equal(strlen(result), strlen("1900-01-00 00:00:00"));
    assert_string_equal(result, "2021-04-19 16:19:34");
    free(result);
}

static void test_w_timestamp_to_journalctl_since_failure(void **state) {
    // Arrange
    uint64_t timestamp = 0; // Timestamp que provocará el error

    will_return(__wrap_gmtime_r, 0);
    
    // Act
    char *result = w_timestamp_to_journalctl_since(timestamp);
    
    // Assert
    assert_null(result);
}

//Test find_library_path

static void test_find_library_path_success(void **state) {
    // Arrange
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /path/to/libtest.so\n");
    will_return(__wrap_getline, simulated_line);

    expect_value(__wrap_fclose, _File, 0x123456);
    will_return(__wrap_fclose, 1);

    // Act
    char *result = find_library_path("libtest.so");

    // Assert
    assert_non_null(result);
    assert_string_equal(result, "/path/to/libtest.so");

    // Clean
    free(result);
}

static void test_find_library_path_failure(void **state) {
    // Arrange

    // Set expectations for fopen
    const char *library_name = "libtest.so";
    const char *expected_mode = "r";
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Setting the return value for fopen
    FILE *maps_file = NULL; // Simulate fopen error
    will_return(__wrap_fopen, maps_file);

    // Act
    char *result = find_library_path(library_name);

    // Assert
    assert_null(result);

    // Clean
    free(result);
}

#define W_LIB_SYSTEMD "libsystemd.so.0"
#define RTLD_LAZY 1

// Test w_journal_lib_init

// Define a test case for the scenario where dlopen fails
static void test_w_journal_lib_init_dlopen_fail(void **state) {
    // Arrange
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, NULL);

    will_return(__wrap_dlerror, "Library load failed");

    expect_string(__wrap__mwarn, formatted_msg, "(8008): Failed to load 'libsystemd.so.0': 'Library load failed'.");

    // Act
    w_journal_lib_t *result = w_journal_lib_init();

    // Assert
    assert_null(result);
}

// Define a test case for the scenario where find_library_path fails
static void test_w_journal_lib_init_find_library_path_fail(void **state) {
    // Arrange
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_failure
    // Set expectations for fopen
    const char *library_name = "libtest.so";
    const char *expected_mode = "r";
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Setting the return value for fopen
    FILE *maps_file = NULL; // Simulate fopen error
    will_return(__wrap_fopen, maps_file);

    //expect_any(__wrap_mwarn, id);
    expect_string(__wrap__mwarn, formatted_msg, "(8009): The library 'libsystemd.so.0' is not owned by the root user.");

    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success

    // Act
    w_journal_lib_t *result = w_journal_lib_init();

    // Assert
    assert_null(result);
}

// Define a test case for the scenario where is_owned_by_root fails
static void test_w_journal_lib_init_is_owned_by_root_fail(void **state) {
    // Arrange
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    //expect_any(__wrap_mwarn, id);
    expect_string(__wrap__mwarn, formatted_msg, "(8009): The library 'libsystemd.so.0' is not owned by the root user.");

    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success

    // Act
    w_journal_lib_t *result = w_journal_lib_init();

    // Assert
    assert_null(result);
}

// Define a test case for the scenario where load_and_validate_function fails
static void test_w_journal_lib_init_load_and_validate_function_fail(void **state) {
    // Arrange
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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
    void *handle = NULL;  // Simulate invalid handle
    void *mock_function = NULL;
    const char *function_name = "sd_journal_open";
    void *function_pointer = (void *)1;

    expect_any(__wrap_dlsym, handle);
    expect_string(__wrap_dlsym, symbol, function_name);
    will_return(__wrap_dlsym, mock_function);

    will_return(__wrap_dlerror,"ERROR");

    expect_string(__wrap__mwarn, formatted_msg, "(8008): Failed to load 'sd_journal_open': 'ERROR'.");

    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0);

    // Act
    w_journal_lib_t *result = w_journal_lib_init();

    // Assert
    assert_null(result);
}

// Define a test case for the scenario where everything succeeds

//  Auxiliary function for setting dlsym wrap expectations
static void setup_dlsym_expectations(const char *symbol) {
    void *handle = (void *)1; // Simulate handle
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

static void test_w_journal_lib_init_success(void **state) {
    // Arrange
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle
    void *mock_function = (void *)0xabcdef;

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
    w_journal_lib_t *result = w_journal_lib_init();

    // Assert
    assert_non_null(result);
    free(result);
}

// Test w_journal_context_create

// Test case for a successful context creation
static void test_w_journal_context_create_success(void **state) {
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

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
static void test_w_journal_context_create_null_pointer(void **state) {
    // Call the function with a NULL context pointer
    int ret = w_journal_context_create(NULL);

    // Check the result
    assert_int_equal(ret, -1);
}

// Test case for a failure in library initialization
static void test_w_journal_context_create_lib_init_fail(void **state) {
    // Allocate memory for the context
    w_journal_context_t *ctx = NULL;

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
static void test_w_journal_context_create_journal_open_fail(void **state) {
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle

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

    will_return(__wrap_sd_journal_open, -1);    // Fail w_journal_lib_open
    expect_string(__wrap__mwarn, formatted_msg, "(8010): Failed open journal log: 'Operation not permitted'.");

    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success

    // Call the function under test
    int ret = w_journal_context_create(&ctx);

    // Check the result
    assert_int_equal(ret, -1);
    assert_null(ctx);

}

// Test w_journal_context_free

// Test case for freeing a NULL context
static void test_w_journal_context_free_null(void **state) {
    w_journal_context_t *ctx = NULL;
    w_journal_context_free(ctx); // Should not cause any issues
    
    // Assert
    assert_null(ctx);
}

// Test case for freeing a valid context
static void test_w_journal_context_free_valid(void **state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle
    void *mock_function = (void *)0xabcdef;

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

    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success

    // Perform the function under test
    expect_function_call(__wrap_sd_journal_close);
    w_journal_context_free(ctx);

    // No need to check the memory deallocation of ctx since it's freed
}

// Test w_journal_context_update_timestamp

// Test for w_journal_context_update_timestamp succeeds
static void test_w_journal_context_update_timestamp_success(void **state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle

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
    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test for w_journal_context_update_timestamp with null ctx
static void test_w_journal_context_update_timestamp_ctx_null(void **state) {
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Perform the function under test
    w_journal_context_update_timestamp(ctx);

}

// Test for w_journal_context_update_timestamp with error when getting the timestamp
static void test_w_journal_context_update_timestamp_fail(void **state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle
    void *mock_function = (void *)0xabcdef;

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
    expect_string(__wrap__mwarn, formatted_msg, "(8011): Failed to read timestamp from journal log: 'Permission denied'. Using current time.");
    w_journal_context_update_timestamp(ctx);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success
    w_journal_context_free(ctx);
}

// Test w_journal_context_seek_most_recent

// Test for w_journal_context_seek_most_recent update timestamp
static void test_w_journal_context_seek_most_recent_update_tamestamp(void **state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle
    void *mock_function = (void *)0xabcdef;

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
    will_return(__wrap_sd_journal_previous, 1); // Mocked return value
    will_return(__wrap_sd_journal_get_realtime_usec, 123456); // Mocked timestamp
    int ret = w_journal_context_seek_most_recent(ctx);

    // Check the result
    assert_int_equal(ret, 1);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success
    w_journal_context_free(ctx);

}

// Test for w_journal_context_seek_most_recent with error when seeking tail
static void test_w_journal_context_seek_most_recent_seek_tail_fail(void **state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle
    void *mock_function = (void *)0xabcdef;

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
    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success
    w_journal_context_free(ctx);

}

// Test for w_journal_context_seek_most_recent success
static void test_w_journal_context_seek_most_recent_success(void **state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle
    void *mock_function = (void *)0xabcdef;

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
    will_return(__wrap_sd_journal_previous, 0); // Mocked return value
    int ret = w_journal_context_seek_most_recent(ctx);

    // Check the result
    assert_int_equal(ret, 0);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success
    w_journal_context_free(ctx);

}

// Test for w_journal_context_seek_most_recent with null ctx
static void test_w_journal_context_seek_most_recent_ctx_null(void **state) {
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Perform the function under test
    int ret = w_journal_context_seek_most_recent(ctx);

    // Check the result
    assert_int_equal(ret, -1);
}

/*
int w_journal_context_seek_timestamp(w_journal_context_t * ctx, uint64_t timestamp) {
    // If the timestamp is in the future or invalid, seek the most recent entry
    if (timestamp == 0 || timestamp > w_get_epoch_time()) {
        mwarn(LOGCOLLECTOR_JOURNAL_LOG_FUTURE_TS, timestamp);
        return w_journal_context_seek_most_recent(ctx);
    }

    // Check if the timestamp is older than the oldest available
    uint64_t oldest;
    int err = w_journal_context_get_oldest_timestamp(ctx, &oldest);

    if (err < 0) {
        mwarn(LOGCOLLECTOR_JOURNAL_LOG_FAIL_READ_OLD_TS, strerror(-err));
    } else if (timestamp < oldest) {
        mwarn(LOGCOLLECTOR_JOURNAL_LOG_CHANGE_TS, timestamp);
        timestamp = oldest;
    }

    err = ctx->lib->seek_timestamp(ctx->journal, timestamp);
    if (err < 0) {
        return err;
    }

    err = ctx->lib->next(ctx->journal);
    if (err > 0) // if the cursor change, update timestamp
    {
        w_journal_context_update_timestamp(ctx);
    }
    return err;
}
*/
//Create unit test for w_journal_context_seek_timestamp

// Test for w_journal_context_seek_timestamp with future timestamp
static void test_w_journal_context_seek_timestamp_future_timestamp(void **state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle
    void *mock_function = (void *)0xabcdef;

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
    expect_string(__wrap__mwarn, formatted_msg, "(8012): The timestamp '1234567' is in the future or invalid. Using the most recent entry.");
    will_return(__wrap_sd_journal_seek_tail, 0); // Mocked return value
    will_return(__wrap_sd_journal_previous, 0); // Mocked return value
    int ret = w_journal_context_seek_timestamp(ctx, 1234567);

    // Check the result
    assert_int_equal(ret, 0);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success
    w_journal_context_free(ctx);

}

// Test for w_journal_context_seek_timestamp error when getting oldest timestamp
static void test_w_journal_context_seek_timestamp_fail_read_old_ts(void **state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle
    void *mock_function = (void *)0xabcdef;

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
    struct timeval expected_time = { .tv_sec = 1234, .tv_usec = 5678 };
    struct timeval actual_time;
    will_return(__wrap_gettimeofday, &expected_time);
    will_return(__wrap_sd_journal_get_cutoff_realtime_usec, -1); // Mocked oldest timestamp
    expect_string(__wrap__mwarn, formatted_msg, "(8013): Failed to read oldest timestamp from journal log: 'Operation not permitted'.");
    will_return(__wrap_sd_journal_seek_realtime_usec, 0);
    will_return(__wrap_sd_journal_next, 0);

    int ret = w_journal_context_seek_timestamp(ctx, 1234567);

    // Check the result
    assert_int_equal(ret, 0);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success
    w_journal_context_free(ctx);

}

//Test for w_journal_context_seek_timestamp with timestamp older than oldest available
static void test_w_journal_context_seek_timestamp_change_ts(void **state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle
    void *mock_function = (void *)0xabcdef;

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
    struct timeval expected_time = { .tv_sec = 1233, .tv_usec = 5678 };
    struct timeval actual_time;
    will_return(__wrap_gettimeofday, &expected_time);
    will_return(__wrap_sd_journal_get_cutoff_realtime_usec, 22345678); // Mocked oldest timestamp
    expect_string(__wrap__mwarn, formatted_msg, "(8014): The timestamp '1234567' is older than the oldest available in journal. Using the oldest entry.");
    will_return(__wrap_sd_journal_seek_realtime_usec, 0);
    will_return(__wrap_sd_journal_next, 0);

    int ret = w_journal_context_seek_timestamp(ctx, 1234567);

    // Check the result
    assert_int_equal(ret, 0);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success
    w_journal_context_free(ctx);

}

// Test for w_journal_context_seek_timestamp with error when seeking timestamp
static void test_w_journal_context_seek_timestamp_seek_timestamp_fail(void **state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle
    void *mock_function = (void *)0xabcdef;

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
    struct timeval expected_time = { .tv_sec = 1234, .tv_usec = 5678 };
    struct timeval actual_time;
    will_return(__wrap_gettimeofday, &expected_time);
    will_return(__wrap_sd_journal_get_cutoff_realtime_usec, 0); // Mocked oldest timestamp
    will_return(__wrap_sd_journal_seek_realtime_usec, -1);
    
    int ret = w_journal_context_seek_timestamp(ctx, 1234567);

    // Check the result
    assert_int_equal(ret, -1);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success
    w_journal_context_free(ctx);

}

// Test for w_journal_context_seek_timestamp with error when getting next entry
static void test_w_journal_context_seek_timestamp_next_fail(void **state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle
    void *mock_function = (void *)0xabcdef;

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
    struct timeval expected_time = { .tv_sec = 1234, .tv_usec = 5678 };
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
    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success
    w_journal_context_free(ctx);

}

// Test for w_journal_context_seek_timestamp success
static void test_w_journal_context_seek_timestamp_success(void **state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle
    void *mock_function = (void *)0xabcdef;

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
    struct timeval expected_time = { .tv_sec = 1234, .tv_usec = 5678 };
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
    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success
    w_journal_context_free(ctx);

}

// Test w_journal_context_next_newest

// Test for w_journal_context_next_newest with null ctx
static void test_w_journal_context_next_newest_ctx_null(void **state) {
    // Perform the function under test
    int ret = w_journal_context_next_newest(NULL);

    // Check the result
    assert_int_equal(ret, -1);
}

// Test for w_journal_context_next_newest updating timestamp
static void test_w_journal_context_next_newest_update_timestamp(void **state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle
    void *mock_function = (void *)0xabcdef;

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
    will_return(__wrap_sd_journal_next, 1); // Mocked return value
    will_return(__wrap_sd_journal_get_realtime_usec, 123456); // Mocked timestamp
    
    int ret = w_journal_context_next_newest(ctx);

    // Check the result
    assert_int_equal(ret, 1);

    // Memory release
    expect_function_call(__wrap_sd_journal_close);
    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success
    w_journal_context_free(ctx);

}

// Test for w_journal_context_next_newest success
static void test_w_journal_context_next_newest_success(void **state) {
    // test_w_journal_context_create_success
    // Define a pointer to w_journal_context_t
    w_journal_context_t *ctx = NULL;

    // Expectativas de llamada a w_journal_lib_init
    expect_string(__wrap_dlopen, filename, W_LIB_SYSTEMD);
    expect_value(__wrap_dlopen, flags, RTLD_LAZY);
    will_return(__wrap_dlopen, (void *)0x123456); // Mocked handle

    // test_find_library_path_success
    expect_string(__wrap_fopen, path, "/proc/self/maps");
    expect_string(__wrap_fopen, mode, "r");

    // Simulate the successful opening of a file
    FILE *maps_file = (FILE *)0x123456; // Simulated address
    will_return(__wrap_fopen, maps_file);

    // Simulate a line containing the searched library
    char *simulated_line = strdup("00400000-0040b000 r-xp 00000000 08:01 6711792           /libsystemd.so.0\n");
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

    void *handle = (void *)1; // Simulate handle
    void *mock_function = (void *)0xabcdef;

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
    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success
    w_journal_context_free(ctx);

}



int main(void) {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_is_owned_by_root_root_owned),
        cmocka_unit_test(test_is_owned_by_root_not_root_owned),
        cmocka_unit_test(test_is_owned_by_root_stat_fails),
        cmocka_unit_test(test_load_and_validate_function_success),
        cmocka_unit_test(test_load_and_validate_function_failure),
        cmocka_unit_test(test_w_get_epoch_time),
        cmocka_unit_test(test_w_timestamp_to_string),
        cmocka_unit_test(test_w_timestamp_to_journalctl_since_success),
        cmocka_unit_test(test_w_timestamp_to_journalctl_since_failure),
        cmocka_unit_test(test_find_library_path_success),
        cmocka_unit_test(test_find_library_path_failure),
        cmocka_unit_test(test_w_journal_lib_init_dlopen_fail),
        cmocka_unit_test(test_w_journal_lib_init_find_library_path_fail),
        cmocka_unit_test(test_w_journal_lib_init_is_owned_by_root_fail),
        cmocka_unit_test(test_w_journal_lib_init_load_and_validate_function_fail),
        cmocka_unit_test(test_w_journal_lib_init_success),
        cmocka_unit_test(test_w_journal_context_create_success),
        cmocka_unit_test(test_w_journal_context_create_null_pointer),
        cmocka_unit_test(test_w_journal_context_create_lib_init_fail),
        cmocka_unit_test(test_w_journal_context_create_journal_open_fail),
        cmocka_unit_test(test_w_journal_context_free_valid),
        cmocka_unit_test(test_w_journal_context_update_timestamp_success),
        cmocka_unit_test(test_w_journal_context_update_timestamp_ctx_null),
        cmocka_unit_test(test_w_journal_context_update_timestamp_fail),
        cmocka_unit_test(test_w_journal_context_seek_most_recent_update_tamestamp),
        cmocka_unit_test(test_w_journal_context_seek_most_recent_seek_tail_fail),
        cmocka_unit_test(test_w_journal_context_seek_most_recent_success),
        cmocka_unit_test(test_w_journal_context_seek_most_recent_ctx_null),
        cmocka_unit_test(test_w_journal_context_seek_timestamp_future_timestamp),
        cmocka_unit_test(test_w_journal_context_seek_timestamp_fail_read_old_ts),
        cmocka_unit_test(test_w_journal_context_seek_timestamp_change_ts),
        cmocka_unit_test(test_w_journal_context_seek_timestamp_seek_timestamp_fail),
        cmocka_unit_test(test_w_journal_context_seek_timestamp_next_fail),
        cmocka_unit_test(test_w_journal_context_seek_timestamp_success),
        cmocka_unit_test(test_w_journal_context_next_newest_ctx_null),
        cmocka_unit_test(test_w_journal_context_next_newest_update_timestamp),
        cmocka_unit_test(test_w_journal_context_next_newest_success)
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
