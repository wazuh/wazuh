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

#include "../wrappers/wazuh/shared/hash_op_wrappers.h"

void w_get_hash_context (const char * path, SHA_CTX *context, ssize_t position);

/* setup/teardown */

/* wraps */

/* tests */

/* w_get_hash_context */

void test_w_get_hash_context_NULL(void ** state) {


}

void test_w_get_hash_context_done(void ** state) {


}


int main(void) {
    const struct CMUnitTest tests[] = {
        // Test w_get_hash_context
        cmocka_unit_test(test_w_get_hash_context_NULL),
        cmocka_unit_test(test_w_get_hash_context_done),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}