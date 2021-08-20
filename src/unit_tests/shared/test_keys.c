/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include <stdlib.h>

#include "headers/shared.h"
#include "headers/sec.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"

int OS_IsAllowedID(keystore *keys, const char *id);
int w_get_agent_net_protocol_from_keystore(keystore * keys, const char * agent_id);

// Test OS_IsAllowedID
void test_OS_IsAllowedID_id_NULL(void **state) {
    keystore *keys = NULL;

    const char * id = NULL;

    int ret = OS_IsAllowedID(keys, id);

    assert_int_equal(ret, -1);
}

void test_OS_IsAllowedID_entry_NULL(void **state) {
    test_mode = 1;

    keystore *keys = NULL;
    os_calloc(1, sizeof(keystore), keys);
    keys->keyhash_id = (OSHash*)1;

    keyentry * data = NULL;

    const char * id = "12345";

    expect_value(__wrap_OSHash_Get, self, keys->keyhash_id);
    expect_string(__wrap_OSHash_Get, key, id);
    will_return(__wrap_OSHash_Get, data);

    int ret = OS_IsAllowedID(keys, id);

    assert_int_equal(ret, -1);

    os_free(keys);
}

void test_OS_IsAllowedID_entry_OK(void **state) {
    test_mode = 1;

    keystore *keys = NULL;
    os_calloc(1, sizeof(keystore), keys);
    keys->keyhash_id = (OSHash*)1;

    keyentry * data = NULL;
    os_calloc(1, sizeof(keyentry), data);
    data->keyid = 0;

    const char * id = "12345";

    expect_value(__wrap_OSHash_Get, self, keys->keyhash_id);
    expect_string(__wrap_OSHash_Get, key, id);
    will_return(__wrap_OSHash_Get, data);

    int ret = OS_IsAllowedID(keys, id);

    assert_int_equal(ret, 0);

    os_free(keys);

    os_free(data);
}

// Test w_get_key_hash
void test_w_get_key_hash_empty_parameters(void **state) {
    keyentry *keys = NULL;
    os_sha1 output = {0};
    int ret;

    expect_string(__wrap__mdebug2, formatted_msg, "Unable to hash agent's key due to empty parameters.");
    ret = w_get_key_hash(keys, output);

    assert_int_equal(ret, OS_INVALID);
}

void test_w_get_key_hash_empty_value(void **state) {
    keyentry *keys = NULL;
    os_sha1 output = {0};
    int ret;
    os_calloc(1, sizeof (keyentry), keys);
    keys->id = "001";
    keys->name = "debian10";
    keys->raw_key = NULL;

    expect_string(__wrap__mdebug2, formatted_msg, "Unable to hash agent's key due to empty value.");
    ret = w_get_key_hash(keys, output);
    assert_int_equal(ret, OS_INVALID);

    os_free(keys);
}

void test_w_get_key_hash_success(void **state) {
    keyentry *keys = NULL;
    os_sha1 output = {0};
    int ret;
    os_calloc(1, sizeof (keyentry), keys);
    keys->id = "001";
    keys->name = "debian10";
    keys->raw_key = "6dd186d1740f6c80d4d380ebe72c8061db175881e07e809eb44404c836a7ef96";

    ret = w_get_key_hash(keys, output);

    assert_string_equal(output, "e0735a4a2c9bf633bac9b58f194cc8649537b394");
    assert_int_equal(ret, OS_SUCCESS);

    os_free(keys);
}

// Test w_get_agent_net_protocol_from_keystore
void test_w_get_agent_net_protocol_from_keystore_key_NULL(void **state) {
    test_mode = 1;

    //test_OS_IsAllowedID_entry_NULL
    keystore *keys = NULL;
    os_calloc(1, sizeof(keystore), keys);
    keys->keyhash_id = (OSHash*)1;

    keyentry * data = NULL;

    const char * id = "12345";

    expect_value(__wrap_OSHash_Get, self, keys->keyhash_id);
    expect_string(__wrap_OSHash_Get, key, id);
    will_return(__wrap_OSHash_Get, data);

    int ret = w_get_agent_net_protocol_from_keystore(keys, id);

    assert_int_equal(ret, -1);

    os_free(keys);
}

void test_w_get_agent_net_protocol_from_keystore_OK(void **state) {
    test_mode = 1;

    //test_OS_IsAllowedID_entry_OK
    keystore *keys = NULL;
    os_calloc(1, sizeof(keystore), keys);
    keys->keyhash_id = (OSHash*)1;
    os_calloc(1, sizeof(keyentry *), keys->keyentries);
    os_calloc(1, sizeof(keyentry), keys->keyentries[0]);
    keys->keyentries[0]->net_protocol = 1;

    keyentry * data = NULL;
    os_calloc(1, sizeof(keyentry), data);
    data->keyid = 0;

    const char * id = "12345";

    expect_value(__wrap_OSHash_Get, self, keys->keyhash_id);
    expect_string(__wrap_OSHash_Get, key, id);
    will_return(__wrap_OSHash_Get, data);

    int ret = w_get_agent_net_protocol_from_keystore(keys, id);

    assert_int_equal(ret, 1);

    os_free(keys->keyentries[0])
    os_free(keys->keyentries)
    os_free(keys);

    os_free(data);
}

int main(void){
    const struct CMUnitTest tests[] = {
        // Tests OS_IsAllowedID
        cmocka_unit_test(test_OS_IsAllowedID_id_NULL),
        cmocka_unit_test(test_OS_IsAllowedID_entry_NULL),
        cmocka_unit_test(test_OS_IsAllowedID_entry_OK),
        // Tests w_get_agent_net_protocol_from_keystore
        cmocka_unit_test(test_w_get_agent_net_protocol_from_keystore_key_NULL),
        cmocka_unit_test(test_w_get_agent_net_protocol_from_keystore_OK),
        // Test w_get_key_hash
        cmocka_unit_test(test_w_get_key_hash_empty_parameters),
        cmocka_unit_test(test_w_get_key_hash_empty_value),
        cmocka_unit_test(test_w_get_key_hash_success)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
