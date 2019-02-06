#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../os_zlib/os_zlib.h"
#include "tap.h"

#define TEST_STRING_1 "Hello World!"
#define TEST_STRING_2 "Test hello \n test \t test \r World\n"
#define BUFFER_LENGTH 200

int test_success_compress_string() {

    char buffer[BUFFER_LENGTH];
    unsigned long int i1 = os_zlib_compress(TEST_STRING_1, buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);

    w_assert_uint_ne(i1, 0);

    char buffer2[BUFFER_LENGTH];
    unsigned long int i2 = os_zlib_uncompress(buffer, buffer2, i1, BUFFER_LENGTH);

    w_assert_uint_ne(i2, 0);
    w_assert_str_eq(buffer2, TEST_STRING_1);
    return 1;
}

int test_success_compress_special_string() {

    char buffer[BUFFER_LENGTH];
    unsigned long int i1 = os_zlib_compress(TEST_STRING_2, buffer, strlen(TEST_STRING_2), BUFFER_LENGTH);

    w_assert_uint_ne(i1, 0);

    char buffer2[BUFFER_LENGTH];
    unsigned long int i2 = os_zlib_uncompress(buffer, buffer2, i1, BUFFER_LENGTH);

    w_assert_uint_ne(i2, 0);
    w_assert_str_eq(buffer2, TEST_STRING_2);
    return 1;
}

int test_fail_compress_null_src() {
    char buffer[BUFFER_LENGTH];
    unsigned long int i1 = os_zlib_compress(NULL, buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);
    w_assert_uint_eq(i1, 0);
    return 1;
}

int test_fail_compress_no_dest() {

    unsigned long int i1 = os_zlib_compress(TEST_STRING_1, NULL, strlen(TEST_STRING_1), BUFFER_LENGTH);
    w_assert_uint_eq(i1, 0);
    return 1;
}

int test_fail_compress_no_dest_size() {
    char buffer[BUFFER_LENGTH];
    unsigned long int i1 = os_zlib_compress(TEST_STRING_1, buffer, strlen(TEST_STRING_1), 0);
    w_assert_uint_eq(i1, 0);
    return 1;
}

int test_fail_uncompress_null_src() {
    char buffer[BUFFER_LENGTH];
    unsigned long int i1 = os_zlib_compress(TEST_STRING_1, buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);
    w_assert_uint_ne(i1, 0);

    char buffer2[BUFFER_LENGTH];
    unsigned long int i2 = os_zlib_uncompress(NULL, buffer2, i1, BUFFER_LENGTH);
    w_assert_uint_eq(i2, 0);
    return 1;
}

int test_fail_uncompress_null_dst() {
    char buffer[BUFFER_LENGTH];
    unsigned long int i1 = os_zlib_compress(TEST_STRING_1, buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);
    w_assert_uint_ne(i1, 0);

    unsigned long int i2 = os_zlib_uncompress(buffer, NULL, i1, BUFFER_LENGTH);
    w_assert_uint_eq(i2, 0);
    return 1;
}

int test_fail_uncompress_no_src_size() {
    char buffer[BUFFER_LENGTH];
    unsigned long int i1 = os_zlib_compress(TEST_STRING_1, buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);
    w_assert_uint_ne(i1, 0);

    char buffer2[BUFFER_LENGTH];
    unsigned long int i2 = os_zlib_uncompress(buffer, buffer2, 0, BUFFER_LENGTH);
    w_assert_uint_eq(i2, 0);
    return 1;
}

int test_fail_uncompress_no_dest_size() {
    char buffer[BUFFER_LENGTH];
    unsigned long int i1 = os_zlib_compress(TEST_STRING_1, buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);
    w_assert_uint_ne(i1, 0);

    char buffer2[BUFFER_LENGTH];
    unsigned long int i2 = os_zlib_uncompress(buffer, buffer2, i1, 0);
    w_assert_uint_eq(i2, 0);
    return 1;
}

int main(void) {
    printf(CYELLOW"\n\n   STARTING TEST - OS_ZLIB   \n\n" CEND);

    // Compress and uncompress a regular string test
    TAP_TEST_MSG(test_success_compress_string(), "Compress and uncompress a regular string test.");

    // Compress and uncompress a regular string with \n, \t and \r test
    TAP_TEST_MSG(test_success_compress_special_string(), "Compress and uncompress a regular string with '\\n', '\\t' and '\\r' test.");

    // Try to compress using NULL as source
    TAP_TEST_MSG(test_fail_compress_null_src(), "Try to compress using ((void *)0) as source.");

    // Try to compress using NULL as destination
    TAP_TEST_MSG(test_fail_compress_no_dest(), "Try to compress using ((void *)0) as destination.");

    // Try to compress using 0 as destination size
    TAP_TEST_MSG(test_fail_compress_no_dest_size(), "Try to compress using 0 as destination size.");

    // Try to uncompress using NULL as source
    TAP_TEST_MSG(test_fail_uncompress_null_src(), "Try to uncompress using ((void *)0) as source.");

    // Try to uncompress using NULL as destination
    TAP_TEST_MSG(test_fail_uncompress_null_dst(), "Try to uncompress using ((void *)0) as destination.");

    // Try to uncompress using 0 as source size
    TAP_TEST_MSG(test_fail_uncompress_no_src_size(), "Try to uncompress using 0 as source size.");

    // Try to uncompress using 0 as destination size
    TAP_TEST_MSG(test_fail_uncompress_no_dest_size(), "Try to uncompress using 0 as destination size.");

    TAP_PLAN;
    TAP_SUMMARY;
    printf(CYELLOW "\n   ENDING TEST  - OS_ZLIB   \n\n" CEND);
    return 0;
}