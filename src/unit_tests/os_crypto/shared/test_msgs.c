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
#include <stdlib.h>

#include "../headers/shared.h"
#include "../../os_crypto/blowfish/bf_op.h"
#include "../headers/sec.h"

/* Forward declarations */
int doEncryptByMethod(const char *input, char *output, const char *charkey,
                      long size, short int action,int method);
void StoreCounter(const keystore *keys, int id, unsigned int global, unsigned int local);

/* Setup/teardown */

static int setup_config(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_config(void **state) {
    test_mode = 0;
    return 0;
}

/* Wrappers */

time_t __wrap_time(int time) {
    check_expected(time);
    return mock();
}

/* Tests StoreCounter*/

void test_StoreCounter_updating_rids(void **state)
{
    keystore keys = KEYSTORE_INITIALIZER;
    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;
    w_linked_queue_t *queue;
    queue = linked_queue_init();
    keys.keysize = 0;
    keys.id_counter = 0;
    keys.opened_fp_queue = queue;

    int global = 1;
    int local = 2;
    int id = 0;
    int now = 123456789;

    keyentry *key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("001");
    key->updating_time = now;
    key->fp = (FILE *)1234;
    w_linked_queue_node_t *node1 = linked_queue_push(keys.opened_fp_queue, keys.keyentries[0]);
    key->rids_node = node1;
    keys.keyentries[0] = key;

    will_return(__wrap_fseek, 0);

    expect_value(__wrap_fprintf, __stream, 1234);
    expect_string(__wrap_fprintf, formatted_msg, "1:2:");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Updating rids_node for agent 001.");

    StoreCounter(&keys, id, global, local);

    assert_int_equal(keys.opened_fp_queue->elements, 1);
    linked_queue_free(keys.opened_fp_queue);
    os_free(node1);
    os_free(key->id);
    os_free(keys.keyentries[0]);
    os_free(keys.keyentries);
}

void test_StoreCounter_pushing_rids(void **state)
{
    keystore keys = KEYSTORE_INITIALIZER;
    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;
    w_linked_queue_t *queue;
    queue = linked_queue_init();
    keys.keysize = 0;
    keys.id_counter = 0;
    keys.opened_fp_queue = queue;

    int global = 1;
    int local = 2;
    int id = 0;
    int now = 123456789;

    keyentry *key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("001");
    key->updating_time = now;
    key->fp = (FILE *)1234;
    key->rids_node = NULL;
    keys.keyentries[0] = key;

    will_return(__wrap_fseek, 0);

    expect_value(__wrap_fprintf, __stream, 1234);
    expect_string(__wrap_fprintf, formatted_msg, "1:2:");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Pushing rids_node for agent 001.");
    expect_memory(__wrap_linked_queue_push_ex, queue, keys.opened_fp_queue, sizeof(keys.opened_fp_queue));
    expect_memory(__wrap_linked_queue_push_ex, data, keys.keyentries[0], sizeof(keys.keyentries[0]));

    assert_int_equal(keys.opened_fp_queue->elements, 0);

    StoreCounter(&keys, id, global, local);

    assert_int_equal(keys.opened_fp_queue->elements, 1);
    assert_int_equal(keys.keyentries[0]->updating_time, now);

    linked_queue_free(keys.opened_fp_queue);
    os_free(key->id);
    os_free(keys.keyentries[0]->rids_node);
    os_free(keys.keyentries[0]);
    os_free(keys.keyentries);
}

void test_StoreCounter_pushing_rids_fp_null(void **state)
{
    keystore keys = KEYSTORE_INITIALIZER;
    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;
    w_linked_queue_t *queue;
    queue = linked_queue_init();
    keys.keysize = 0;
    keys.id_counter = 0;
    keys.opened_fp_queue = queue;

    int global = 1;
    int local = 2;
    int id = 0;
    int now = 123456789;

    keyentry *key = NULL;
    os_calloc(1, sizeof(keyentry), key);
    key->id = strdup("001");
    key->updating_time = now;
    key->fp = NULL;
    key->rids_node = NULL;
    keys.keyentries[0] = key;

    expect_string(__wrap_wfopen, path, "queue/rids/001");
    expect_string(__wrap_wfopen, mode, "r+");
    will_return(__wrap_wfopen, 1234);

    expect_string(__wrap__mdebug2, formatted_msg, "Opening rids for agent 001.");

    will_return(__wrap_fseek, 0);

    expect_value(__wrap_fprintf, __stream, 1234);
    expect_string(__wrap_fprintf, formatted_msg, "1:2:");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Pushing rids_node for agent 001.");
    expect_memory(__wrap_linked_queue_push_ex, queue, keys.opened_fp_queue, sizeof(keys.opened_fp_queue));
    expect_memory(__wrap_linked_queue_push_ex, data, keys.keyentries[0], sizeof(keys.keyentries[0]));

    assert_int_equal(keys.opened_fp_queue->elements, 0);

    StoreCounter(&keys, id, global, local);

    assert_int_equal(keys.opened_fp_queue->elements, 1);
    assert_int_equal(keys.keyentries[0]->updating_time, now);

    linked_queue_free(keys.opened_fp_queue);
    os_free(key->id);
    os_free(keys.keyentries[0]->rids_node);
    os_free(keys.keyentries[0]);
    os_free(keys.keyentries);
}

void test_StoreCounter_fail_first_open(void **state)
{
    keystore keys = KEYSTORE_INITIALIZER;
    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;
    w_linked_queue_t *queue;
    queue = linked_queue_init();
    keys.keysize = 0;
    keys.id_counter = 0;
    keys.opened_fp_queue = queue;

    int global = 1;
    int local = 2;
    int id = 0;
    int now = 123456789;

    keyentry *key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("001");
    key->updating_time = now;
    key->fp = NULL;
    key->rids_node = NULL;
    keys.keyentries[0] = key;

    expect_string(__wrap_wfopen, path, "queue/rids/001");
    expect_string(__wrap_wfopen, mode, "r+");
    will_return(__wrap_wfopen, NULL);
    errno = EACCES;
    expect_string(__wrap_wfopen, path, "queue/rids/001");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, 1234);

    expect_string(__wrap__mdebug2, formatted_msg, "Opening rids for agent 001.");

    will_return(__wrap_fseek, 0);

    expect_value(__wrap_fprintf, __stream, 1234);
    expect_string(__wrap_fprintf, formatted_msg, "1:2:");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Pushing rids_node for agent 001.");
    expect_memory(__wrap_linked_queue_push_ex, queue, keys.opened_fp_queue, sizeof(keys.opened_fp_queue));
    expect_memory(__wrap_linked_queue_push_ex, data, keys.keyentries[0], sizeof(keys.keyentries[0]));

    assert_int_equal(keys.opened_fp_queue->elements, 0);

    StoreCounter(&keys, id, global, local);

    assert_int_equal(keys.opened_fp_queue->elements, 1);

    linked_queue_free(keys.opened_fp_queue);
    os_free(key->id);
    os_free(keys.keyentries[0]->rids_node);
    os_free(keys.keyentries[0]);
    os_free(keys.keyentries);
}

void test_encrypt_by_method_blowfish(void **state){
    const char *key = "test_key";
    const char *string = "test string";
    const int buffersize = 1024;
    char buffer1[buffersize];
    char buffer2[buffersize];

    memset(buffer1, 0, sizeof(buffer1));
    memset(buffer2, 0, sizeof(buffer2));

    assert_int_equal(doEncryptByMethod(string, buffer1, key, strlen(string), OS_ENCRYPT ,W_METH_BLOWFISH), 1);
    assert_int_equal(doEncryptByMethod(buffer1, buffer2, key, strlen(buffer1), OS_DECRYPT ,W_METH_BLOWFISH), 1);

    assert_string_equal(buffer2, string);
}

void test_encrypt_by_method_aes(void **state){
    const char *key = "test_key";
    const char *string = "test string";
    const int buffersize = 1024;
    char buffer1[buffersize];
    char buffer2[buffersize];

    memset(buffer1, 0, sizeof(buffer1));
    memset(buffer2, 0, sizeof(buffer2));

    assert_int_equal(doEncryptByMethod(string, buffer1, key, strlen(string), OS_ENCRYPT ,W_METH_AES), 16);
    assert_int_equal(doEncryptByMethod(buffer1, buffer2, key, strlen(buffer1), OS_DECRYPT ,W_METH_AES), 11);

    assert_int_equal(strncmp(buffer2, string, strlen(string)), 0);
}

void test_encrypt_by_method_default(void **state){
    const char *key = "test_key";
    const char *string = "test string";
    const int buffersize = 1024;
    char buffer1[buffersize];

    memset(buffer1, 0, sizeof(buffer1));

    assert_int_equal(doEncryptByMethod(string, buffer1, key, strlen(string), OS_ENCRYPT ,2), OS_INVALID);
}

void test_set_agent_crypto_method(void **state){
    keystore *keys;

    os_calloc(1, sizeof(keystore), keys);
    os_calloc(1, sizeof(keyentry *), keys->keyentries);
    keys->keysize = 1;

    os_calloc(1, sizeof(keyentry), keys->keyentries[0]);
    keys->keyentries[0]->keyid = 0;
    keys->keyentries[0]->id = "001";
    keys->keyentries[0]->name = "agent1";

    os_set_agent_crypto_method(keys, W_METH_BLOWFISH);

    assert_int_equal(keys->keyentries[0]->crypto_method, W_METH_BLOWFISH);

    free(keys->keyentries[0]);
    free(keys->keyentries);
    free(keys);
}

void test_ReadSecMSG_final_size_validation(void **state){
    extern unsigned int _s_recv_flush;
    extern int _s_verify_counter;

    keystore *keys;

    os_calloc(1, sizeof(keystore), keys);
    os_calloc(1, sizeof(keyentry *), keys->keyentries);
    keys->keysize = 1;
    keys->flags.key_mode = W_ENCRYPTION_KEY;

    os_calloc(1, sizeof(keyentry), keys->keyentries[0]);
    keys->keyentries[0]->keyid = 0;
    keys->keyentries[0]->id = "001";
    keys->keyentries[0]->name = "agent1";
    keys->keyentries[0]->encryption_key =
        "778823d0b0886be37049bdf01cc703f72fa8dc7bb499303";
    keys->keyentries[0]->crypto_method = W_METH_AES;
    w_mutex_init(&keys->keyentries[0]->mutex, NULL);

    const unsigned char msg_data[] = {
        0x23, 0x41, 0x45, 0x53, 0x3a, 0x0a, 0x0e, 0x1b,
        0xcd, 0x62, 0xfd, 0xa8, 0x2d, 0x59, 0x64, 0xc8,
        0xb8, 0xe1, 0x05, 0xf7, 0x94, 0x94, 0x5c, 0x94,
        0x67, 0xa5, 0xc6, 0x72, 0x16, 0x6f, 0x66, 0xeb,
        0xa0, 0x11, 0x6f, 0x8a, 0x3d, 0xa2, 0xe1, 0xc9,
        0x42, 0x94, 0x97, 0x6c, 0x89, 0xf8, 0xca, 0x73,
        0xc1, 0x23, 0x2f, 0x82, 0x00, 0x87, 0x5c, 0x63,
        0x01, 0x9a, 0x78, 0xc6, 0x6a, 0xf6, 0x8e, 0x69,
        0x32, 0xc3, 0x2c, 0xf5, 0x87, 0x28, 0x70, 0x05,
        0x1a, 0xb0, 0x52, 0xbf, 0xdf, 0x5e, 0xe5, 0xc3,
        0x5d, 0x75, 0x83, 0x67, 0x00
    };
    char msg_buf[sizeof(msg_data)];
    memcpy(msg_buf, msg_data, sizeof(msg_data));

    char cleartext[1024];
    size_t final_size = 0;
    char *output = NULL;

    int saved_verify_counter = _s_verify_counter;
    unsigned int saved_recv_flush = _s_recv_flush;

    _s_verify_counter = 0;
    _s_recv_flush = 1;

    expect_string(__wrap__mwarn, formatted_msg, "Decompressed message too short from agent '001'");

    assert_int_equal(ReadSecMSG(keys, msg_buf, cleartext, 0,
                                sizeof(msg_buf) - 1, &final_size, "127.0.0.1", &output), KS_CORRUPT);

    _s_verify_counter = saved_verify_counter;
    _s_recv_flush = saved_recv_flush;

    w_mutex_destroy(&keys->keyentries[0]->mutex);
    free(keys->keyentries[0]);
    free(keys->keyentries);
    free(keys);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests StoreCounter
        cmocka_unit_test_setup_teardown(test_StoreCounter_updating_rids, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_StoreCounter_pushing_rids, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_StoreCounter_pushing_rids_fp_null, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_StoreCounter_fail_first_open, setup_config, teardown_config),
        cmocka_unit_test(test_encrypt_by_method_blowfish),
        cmocka_unit_test(test_encrypt_by_method_aes),
        cmocka_unit_test(test_encrypt_by_method_default),
        cmocka_unit_test(test_set_agent_crypto_method),
        cmocka_unit_test(test_ReadSecMSG_final_size_validation)
        };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
