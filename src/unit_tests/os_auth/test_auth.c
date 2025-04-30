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
#include <string.h>

#include "os_err.h"
#include "shared.h"
#include "../../os_auth/auth.h"
#include "../../headers/sec.h"
#include "../../addagent/manage_agents.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/os_auth/os_auth_wrappers.h"
#include "../wrappers/wazuh/shared/randombytes_wrappers.h"

extern struct keynode *queue_insert;
extern struct keynode * volatile *insert_tail;

/* tests */

static void test_w_generate_random_pass_success(void **state) {
    char* result = NULL;

    will_return(__wrap_os_random, 146557);
    will_return(__wrap_os_random, 314159);
    will_return(__wrap_GetRandomNoise, strdup("Wazuh"));
    will_return(__wrap_GetRandomNoise, strdup("The Open Source Security Platform"));
    will_return(__wrap_time, 1655254875);
    will_return_always(__wrap_getuname, "Linux |ubuntu-focal |5.4.0-92-generic |#103-Ubuntu SMP Fri Nov 26 16:13:00 UTC 2021 "
                                        "|x86_64 [Ubuntu|ubuntu: 20.04.2 LTS (Focal Fossa)] - Wazuh v4.3.4");

    result = w_generate_random_pass();

    assert_string_equal(result, "6e0d9a4188ac9de8fa695bd96e276090");
    os_free(result);
}

static int auth_setup(void **state) {
    insert_tail = &queue_insert;

    return 0;
}

static int auth_teardown(void **state) {
    struct keynode *cur;
    struct keynode *next;

    for (cur = queue_insert; cur; cur = next) {
        next = cur->next;
        free(cur->id);
        free(cur->name);
        free(cur->ip);
        free(cur->raw_key);
        free(cur->group);
        free(cur);
    }

    return 0;
}

static void test_w_insert_any_group(void **state) {
    os_ip ip = { .ip = "127.0.0.1" };

    keyentry entry = {
        .id = "001",
        .name = "TestName",
        .ip = &ip,
        .raw_key = "TestKey",
    };

    add_insert(&entry, "TestGroup");

    assert_string_equal(queue_insert->id, "001");
    assert_string_equal(queue_insert->name, "TestName");
    assert_string_equal(queue_insert->ip, "127.0.0.1");
    assert_string_equal(queue_insert->raw_key, "TestKey");
    assert_string_equal(queue_insert->group, "TestGroup");
}

static void test_w_insert_null_group(void **state) {
    os_ip ip = { .ip = "127.0.0.1" };

    keyentry entry = {
        .id = "001",
        .name = "TestName",
        .ip = &ip,
        .raw_key = "TestKey",
    };

    add_insert(&entry, NULL);

    assert_string_equal(queue_insert->id, "001");
    assert_string_equal(queue_insert->name, "TestName");
    assert_string_equal(queue_insert->ip, "127.0.0.1");
    assert_string_equal(queue_insert->raw_key, "TestKey");
    assert_string_equal(queue_insert->group, "default");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_w_generate_random_pass_success),
        cmocka_unit_test_setup_teardown(test_w_insert_any_group, auth_setup, auth_teardown),
        cmocka_unit_test_setup_teardown(test_w_insert_null_group, auth_setup, auth_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
