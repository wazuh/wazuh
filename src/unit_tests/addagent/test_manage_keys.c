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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_k_import_successful, NULL, NULL),
        cmocka_unit_test_setup_teardown(test_k_import_keyinvalid, NULL, NULL),
    };

    return cmocka_run_group_tests(tests, test_setup, test_teardown);
}
