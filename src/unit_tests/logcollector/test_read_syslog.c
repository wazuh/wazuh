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

void __wrap_OS_SHA1_Stream_Bytes(EVP_MD_CTX *c, const char * buf, size_t len) {
    function_called();
    check_expected(len);
    return;
}

int __wrap_w_msg_hash_queues_push(const char *str, char *file, unsigned long size, logtarget *targets, char queue_mq) {
    check_expected(size);
    return 0;
}

int __wrap_check_ignore_and_restrict(OSList * ignore_exp, OSList * restrict_exp, const char *log_line) {
    return 0;
}

/* Helpers */

static void expect_read(const char *line, int64_t end) {
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, end);
}

static void expect_hashed(size_t len) {
    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_value(__wrap_OS_SHA1_Stream_Bytes, len, len);
}

/* Read the first chunk of a line longer than the buffer */
static char *expect_long_line_start(void) {
    const int64_t chunk_len = OS_MAXSTR - OS_LOG_HEADER - 1;
    char *chunk = NULL;

    os_calloc(chunk_len + 1, sizeof(char), chunk);
    memset(chunk, 'x', chunk_len);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, true);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    expect_read(chunk, chunk_len);
    expect_hashed(chunk_len);

    return chunk;
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

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_value(__wrap_OS_SHA1_Stream_Bytes, len, strlen(line));

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

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_value(__wrap_OS_SHA1_Stream_Bytes, len, strlen(line1));

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1));

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line2);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2));

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_value(__wrap_OS_SHA1_Stream_Bytes, len, strlen(line2));

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

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_value(__wrap_OS_SHA1_Stream_Bytes, len, strlen(line1));

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1));

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line2);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2));

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_value(__wrap_OS_SHA1_Stream_Bytes, len, strlen(line2));

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2));

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line3);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2) + strlen(line3));

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_any(__wrap_OS_SHA1_Stream_Bytes, len);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2) + strlen(line3));

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    read_syslog(&lf, &rc, 1);
}

/* The first part of an oversized line is sent, its rest is discarded and the next line is read whole */
void test_read_syslog_long_line(void ** state) {
    logreader lf = { .file = "test.log" };
    const int64_t chunk_len = OS_MAXSTR - OS_LOG_HEADER - 1;
    char expected_msg[OS_SIZE_256];
    int rc;
    maximum_lines = 0;
    sample_log_length = 4;

    char *chunk = expect_long_line_start();

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "rest\n");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, chunk_len + 5);
    expect_hashed(5);

    snprintf(expected_msg, sizeof(expected_msg), "Large message size from file 'test.log' (length = %ld): 'xxxx'...", (long) (chunk_len + 5));
    expect_string(__wrap__merror, formatted_msg, expected_msg);

    expect_value(__wrap_w_msg_hash_queues_push, size, chunk_len);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, chunk_len + 5);

    expect_read("next\n", chunk_len + 10);
    expect_hashed(5);
    expect_value(__wrap_w_msg_hash_queues_push, size, 5);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, chunk_len + 10);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    read_syslog(&lf, &rc, 0);

    os_free(chunk);
}

/* If the position cannot be read while discarding the rest of an oversized line, the read stops */
void test_read_syslog_long_line_ftell_error(void ** state) {
    logreader lf = { .file = "test.log" };
    const int64_t chunk_len = OS_MAXSTR - OS_LOG_HEADER - 1;
    int rc;
    maximum_lines = 0;

    char *chunk = expect_long_line_start();

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "rest");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) -1);

    expect_any(__wrap__merror, formatted_msg);

    expect_value(__wrap_w_msg_hash_queues_push, size, chunk_len);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) -1);

    will_return(__wrap_can_read, 1);

    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    read_syslog(&lf, &rc, 0);

    os_free(chunk);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_syslog_empty_file),
        cmocka_unit_test(test_read_syslog_success),
        cmocka_unit_test(test_maximum_lines),
        cmocka_unit_test(test_maximum_lines_disabled),
        cmocka_unit_test(test_read_syslog_long_line),
        cmocka_unit_test(test_read_syslog_long_line_ftell_error)
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
