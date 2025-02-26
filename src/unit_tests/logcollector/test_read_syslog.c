#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "../../logcollector/logcollector.h"
#include "../../headers/shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/libc/string_wrappers.h"

/* Globals*/

extern int maximum_lines;

/* Setup & Teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

/* Wraps */

int __wrap_can_read() {
    return mock_type(int);
}

bool __wrap_w_get_hash_context(const char * path, EVP_MD_CTX * context, int64_t position) {
    return mock_type(bool);
}

int __wrap_w_update_file_status(const char * path, int64_t pos, EVP_MD_CTX * context) {
    bool free_context = mock_type(bool);
    if (free_context) {
        EVP_MD_CTX_free(context);
    }
    return mock_type(int);
}

void __wrap_OS_SHA1_Stream(EVP_MD_CTX *c, os_sha1 output, char * buf) {
    function_called();
    return;
}

/* Tests */

void test_read_syslog_empty_file(void **state) {
    logreader lf = { .file = "test.log" };
    int rc;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, true);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    read_syslog(&lf, &rc, 1);
}

void test_read_syslog_success(void **state) {
    logreader lf = { .file = "test.log" };
    char line[] = "test line\n";
    int rc;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, true);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line));

    expect_function_call(__wrap_OS_SHA1_Stream);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line));

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    read_syslog(&lf, &rc, 1);
}

void test_maximum_lines(void ** state) {
    logreader lf = { .file = "test" };
    int rc;
    char line1[] = "Line 1\n";
    char line2[] = "Line 2\n";
    char line3[] = "Line 3\n";
    maximum_lines = 2;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, true);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line1);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1));

    expect_function_call(__wrap_OS_SHA1_Stream);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1));

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line2);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2));

    expect_function_call(__wrap_OS_SHA1_Stream);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2));

    will_return(__wrap_can_read, 1);

    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    read_syslog(&lf, &rc, 1);
}

void test_maximum_lines_disabled(void ** state) {
    logreader lf = { .file = "test", .linecount = 3 };
    int rc;
    char line1[] = "Line 1\n";
    char line2[] = "Line 2\n";
    char line3[] = "Line 3\n";
    maximum_lines = 0;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, true);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line1);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1));

    expect_function_call(__wrap_OS_SHA1_Stream);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1));

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line2);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2));

    expect_function_call(__wrap_OS_SHA1_Stream);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2));

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line3);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2) + strlen(line3));

    expect_function_call(__wrap_OS_SHA1_Stream);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2) + strlen(line3));

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    read_syslog(&lf, &rc, 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_syslog_empty_file),
        cmocka_unit_test(test_read_syslog_success),
        cmocka_unit_test(test_maximum_lines),
        cmocka_unit_test(test_maximum_lines_disabled)
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
