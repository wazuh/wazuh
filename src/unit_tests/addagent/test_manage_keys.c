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

#include "shared.h"
#include "../../addagent/manage_agents.h"
#include "../wrappers/common.h"
#include "../wrappers/libc/stdlib_wrappers.h"
#include "../wrappers/wazuh/shared/b64_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"

#define CLIENT_KEYS_FILENAME "tmp/client.keysXXXXXX"
#define KEY_ENCODED "MDEzIHVidW50dTIyYWdlbnQgYW55IDVmMjIwMmI2MmVkNTJjYTY3ZWIwZGMyZmRmZDZmODlmNmNlMDllZjNjNTY3NTk2ZTNhMTU3MzEzNmI3NjNkYmY="
#define KEY_DECODED_SUCCESSFUL "013 ubuntu22agent any 5f2202b62ed52ca67eb0dc2fdfd6f89f6ce09ef3c567596e3a1573136b763dbf"
#define KEY_DECODED_INVALID "013-invalidformat-any 5f2202b62ed52ca67eb0dc2fdfd6f89f6ce09ef3c567596e3a1573136b763dbf"

char shost[512];

static int test_setup(void **state) {
    (void) state;
    test_mode = 1;
    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    (void) state;
    test_mode = 0;
    return OS_SUCCESS;
}

void test_k_import_successful(void **state) {
    (void) state;

    expect_decode_base64(
        KEY_ENCODED,
        KEY_DECODED_SUCCESSFUL
    );

    expect_mkstemp_ex(CLIENT_KEYS_FILENAME, 0);

    expect_string(__wrap_chmod, path, CLIENT_KEYS_FILENAME);
    will_return(__wrap_chmod, 0);

    expect_string(__wrap_wfopen, path, CLIENT_KEYS_FILENAME);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, "test");

    expect_value(__wrap_fprintf, __stream, "test");
    expect_string(__wrap_fprintf, formatted_msg, KEY_DECODED_SUCCESSFUL "\n");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_fclose, _File, "test");
    will_return(__wrap_fclose, 1);

    expect_rename_ex(CLIENT_KEYS_FILENAME, KEYS_FILE, 0);

    putenv("OSSEC_ACTION_CONFIRMED=y");

    int retval = k_import(KEY_ENCODED);
    assert_int_equal(retval, 1);
}

void test_k_import_keyinvalid(void **state) {
    (void) state;

    expect_decode_base64(
        KEY_ENCODED,
        KEY_DECODED_INVALID
    );

    expect_value(__wrap_fgets, __stream, stdin);
    will_return(__wrap_fgets, "\r\n");

    int retval = k_import(KEY_ENCODED);
    assert_int_equal(retval, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_k_import_successful, NULL, NULL),
        cmocka_unit_test_setup_teardown(test_k_import_keyinvalid, NULL, NULL),
    };

    return cmocka_run_group_tests(tests, test_setup, test_teardown);
}
