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
int return_lib_open = 0; //w_journal_lib_open success

// Mock for the open function of w_journal_lib_t
int wrap_w_journal_lib_open(sd_journal **journal, int flags) {
    return return_lib_open;
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
unsigned int __wrap_gmtime_r(__attribute__ ((__unused__)) const time_t *t, __attribute__ ((__unused__)) struct tm *tm) {
    return mock_type(unsigned int);
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

//Test w_timestamp_to_journalctl_since

static void test_w_timestamp_to_journalctl_since_success(void **state) {
    // Arrange
    uint64_t timestamp = 1618849174000000; // Timestamp en microsegundos

    will_return(__wrap_gmtime_r, 1618849174000000);
    
    // Act
    char *result = w_timestamp_to_journalctl_since(timestamp);
    
    // Assert
    assert_non_null(result);

    // Verificar que la cadena generada tenga el formato esperado
    assert_true(strlen(result) == strlen("1900-01-00 00:00:00"));
    assert_true(strncmp(result, "1900-01-00 00:00:00", strlen("1900-01-00 00:00:00")) == 0);
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
    void *mock_function = wrap_w_journal_lib_open;

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

    // Call the function under test
    int ret = w_journal_context_create(&ctx);

    // Check the result
    assert_int_equal(ret, 0); // Asegurar que la función retorna 0 en caso de éxito
    assert_non_null(ctx);     // Asegurar que el contexto no es nulo

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

    return_lib_open = -1; // Fail w_journal_lib_open
    expect_string(__wrap__mwarn, formatted_msg, "(8010): Failed open journal log: 'Operation not permitted'.");

    expect_value(__wrap_dlclose, handle, (void *)0x123456); // Mocked handle
    will_return(__wrap_dlclose, 0); // Simulate dlclose success

    // Call the function under test
    int ret = w_journal_context_create(&ctx);

    // Check the result
    assert_int_equal(ret, -1);
    assert_null(ctx);

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
        cmocka_unit_test(test_w_journal_context_create_journal_open_fail)
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
