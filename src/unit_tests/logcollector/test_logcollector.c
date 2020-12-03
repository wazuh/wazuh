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

#include "../../headers/shared.h"
#include "../../logcollector/logcollector.h"
#include <math.h>
#include <pthread.h>
#include "../../os_crypto/sha1/sha1_op.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"

extern OSHash *files_status;

void w_get_hash_context (const char * path, SHA_CTX *context, ssize_t position);
void w_initialize_file_status();

/* setup/teardown */

/* wraps */

/* tests */

/* w_get_hash_context */

void test_w_get_hash_context_NULL(void ** state) {


}

void test_w_get_hash_context_done(void ** state) {


}

/* w_update_file_status */

void test_w_update_file_status_fail_update_add_table_hash(void ** state) {
    test_mode = 1;

    char * path = "test/test.log";
    long pos = 0;
    SHA_CTX context = {0};

    expect_value(__wrap_OS_SHA1_Stream, buf, NULL);
    will_return(__wrap_OS_SHA1_Stream, "a7a899f25aeda32989d1029839ef2e594835c211");

    will_return(__wrap_OSHash_Update_ex, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, files_status);
    expect_string(__wrap_OSHash_Add_ex, key, path);
    will_return(__wrap_OSHash_Add_ex, 0);

    int retval = w_update_file_status(path, pos, &context);

    assert_int_equal(retval,-1);

}

void test_w_update_file_status_update_fail_add_OK(void ** state) {
    test_mode = 1;

    char * path = "test/test.log";
    long pos = 0;
    SHA_CTX context = {0};

    expect_value(__wrap_OS_SHA1_Stream, buf, NULL);
    will_return(__wrap_OS_SHA1_Stream, "a7a899f25aeda32989d1029839ef2e594835c211");

    will_return(__wrap_OSHash_Update_ex, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, files_status);
    expect_string(__wrap_OSHash_Add_ex, key, path);
    will_return(__wrap_OSHash_Add_ex, 2);

    int retval = w_update_file_status(path, pos, &context);

    assert_int_equal(retval,0);

}

void test_w_update_file_status_update_OK(void ** state) {
    test_mode = 1;

    char * path = "test/test.log";
    long pos = 0;
    SHA_CTX context = {0};

    expect_value(__wrap_OS_SHA1_Stream, buf, NULL);
    will_return(__wrap_OS_SHA1_Stream, "a7a899f25aeda32989d1029839ef2e594835c211");

    will_return(__wrap_OSHash_Update_ex, 1);

    int retval = w_update_file_status(path, pos, &context);

    assert_int_equal(retval,0);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test w_get_hash_context
        cmocka_unit_test(test_w_get_hash_context_NULL),
        cmocka_unit_test(test_w_get_hash_context_done),

        // Test w_update_file_status
        cmocka_unit_test(test_w_update_file_status_fail_update_add_table_hash),
        cmocka_unit_test(test_w_update_file_status_update_fail_add_OK),
        cmocka_unit_test(test_w_update_file_status_update_OK)

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}