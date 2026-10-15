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

#include "shared.h"
#include "bf_op.h"
#include "sec.h"
#include "os_zlib.h"
#include "md5_op.h"

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

/* "#AES:" message that decrypts with the key below but whose decompressed
 * payload is shorter than MSG_OVERHEAD, so it never authenticates. */
static const unsigned char aes_short_msg[] = {
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

    char msg_buf[sizeof(aes_short_msg)];
    memcpy(msg_buf, aes_short_msg, sizeof(aes_short_msg));

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

void test_ReadSecMSG_unauthenticated_prefix_keeps_crypto_method(void **state){
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
    keys->keyentries[0]->crypto_method = W_METH_BLOWFISH;
    w_mutex_init(&keys->keyentries[0]->mutex, NULL);

    char msg_buf[sizeof(aes_short_msg)];
    memcpy(msg_buf, aes_short_msg, sizeof(aes_short_msg));

    char cleartext[1024];
    size_t final_size = 0;
    char *output = NULL;

    int saved_verify_counter = _s_verify_counter;
    unsigned int saved_recv_flush = _s_recv_flush;

    _s_verify_counter = 0;
    _s_recv_flush = 1;

    /* The "#AES" prefix selects the cipher, so the message decrypts... */
    expect_string(__wrap__mwarn, formatted_msg, "Decompressed message too short from agent '001'");

    assert_int_equal(ReadSecMSG(keys, msg_buf, cleartext, 0,
                                sizeof(msg_buf) - 1, &final_size, "127.0.0.1", &output), KS_CORRUPT);

    /* ...but an unauthenticated message must not switch the reply cipher. */
    assert_int_equal(keys->keyentries[0]->crypto_method, W_METH_BLOWFISH);

    _s_verify_counter = saved_verify_counter;
    _s_recv_flush = saved_recv_flush;

    w_mutex_destroy(&keys->keyentries[0]->mutex);
    free(keys->keyentries[0]);
    free(keys->keyentries);
    free(keys);
}

void test_ReadSecMSG_legacy_format_length_validation(void **state){
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
    keys->keyentries[0]->crypto_method = W_METH_BLOWFISH;
    w_mutex_init(&keys->keyentries[0]->mutex, NULL);

    /* Plaintext for the legacy ("Old format") branch: starts with ':' and is
     * far shorter than MSG_OVERHEAD, matching the undersized-message case
     * the missing length guard was supposed to reject. */
    const char plaintext[] = ":123456789";
    const size_t plain_len = sizeof(plaintext) - 1;

    char msg_buf[1 + sizeof(plaintext) - 1];
    msg_buf[0] = ':';
    assert_int_equal(doEncryptByMethod(plaintext, msg_buf + 1,
                      keys->keyentries[0]->encryption_key, (long)plain_len,
                      OS_ENCRYPT, W_METH_BLOWFISH), 1);

    char cleartext[1024];
    size_t final_size = 0;
    char *output = NULL;

    expect_string(__wrap__mwarn, formatted_msg, "Message too short from agent '001'");

    assert_int_equal(ReadSecMSG(keys, msg_buf, cleartext, 0,
                                sizeof(msg_buf) - 1, &final_size, "127.0.0.1", &output), KS_CORRUPT);

    w_mutex_destroy(&keys->keyentries[0]->mutex);
    free(keys->keyentries[0]);
    free(keys->keyentries);
    free(keys);
}

/* Tests ReadSecMSG() on messages it accepts */

#define TEST_KEY "778823d0b0886be37049bdf01cc703f72fa8dc7bb499303"

/* A key store holding one agent, '001', whose replies use @p method so far */
static keystore *one_agent_keystore(crypt_method method) {
    keystore *keys;

    os_calloc(1, sizeof(keystore), keys);
    os_calloc(1, sizeof(keyentry *), keys->keyentries);
    keys->keysize = 1;
    keys->flags.key_mode = W_ENCRYPTION_KEY;

    os_calloc(1, sizeof(keyentry), keys->keyentries[0]);
    keys->keyentries[0]->id = "001";
    keys->keyentries[0]->name = "agent1";
    keys->keyentries[0]->encryption_key = TEST_KEY;
    keys->keyentries[0]->crypto_method = method;
    w_mutex_init(&keys->keyentries[0]->mutex, NULL);

    return keys;
}

static void free_one_agent_keystore(keystore *keys) {
    w_mutex_destroy(&keys->keyentries[0]->mutex);
    free(keys->keyentries[0]);
    free(keys->keyentries);
    free(keys);
}

/* What CreateSecMSG() puts on the wire for @p payload: the cipher's prefix, then the encrypted,
 * '!'-padded, compressed "<md5><random><global>:<local>:<payload>". Returns its length. */
static size_t build_compressed_msg(int method, unsigned int global, unsigned int local, const char *payload,
                                   char *out) {
    static char plain[OS_MAXSTR];
    static char signed_msg[OS_MAXSTR];
    static char padded[OS_MAXSTR];
    const char *prefix = (method == W_METH_AES) ? "#AES:" : ":";
    size_t prefix_length = strlen(prefix);
    os_md5 md5sum;
    int length = snprintf(plain, sizeof(plain), "%05hu%010u:%04u:%s", (unsigned short) 12345, global, local, payload);
    unsigned long cmp_size;
    size_t pad;
    int crypto_length;

    OS_MD5_Str(plain, length, md5sum);
    memcpy(signed_msg, md5sum, 32);
    memcpy(signed_msg + 32, plain, (size_t) length);

    cmp_size = os_zlib_compress(signed_msg, padded + 8, (size_t) length + 32, sizeof(padded) - 12);
    assert_true(cmp_size > 0);
    cmp_size++;
    pad = (8 - (cmp_size % 8)) % 8;
    memset(padded, '!', 8);
    cmp_size += pad;

    memcpy(out, prefix, prefix_length);
    crypto_length = doEncryptByMethod(padded + (7 - pad), out + prefix_length, TEST_KEY, (long) cmp_size,
                                      OS_ENCRYPT, method);

    if ((unsigned long) crypto_length > cmp_size) {
        cmp_size = (unsigned long) crypto_length;
    }

    return cmp_size + prefix_length;
}

/* The old format: ':' and the Blowfish-encrypted ":<md5><time>:<count>:<random>:<payload>", in whole
 * 8-byte blocks. The MD5 covers what follows it, the zero padding, and the terminator ReadSecMSG()
 * writes after the message. Returns its length. */
static size_t build_legacy_msg(unsigned int time, unsigned int count, const char *payload, char *out) {
    char rest[OS_SIZE_1024] = {0};
    char plain[OS_SIZE_1024] = {0};
    os_md5 md5sum;
    int rest_length = snprintf(rest, sizeof(rest), "%010u:%04u:%05hu:%s", time, count, (unsigned short) 12345, payload);
    size_t blocks = ((size_t) rest_length + 33 + 7) / 8 * 8;

    OS_MD5_Str(rest, (ssize_t)(blocks - 33 + 1), md5sum);
    plain[0] = ':';
    memcpy(plain + 1, md5sum, 32);
    memcpy(plain + 33, rest, blocks - 33);

    out[0] = ':';
    doEncryptByMethod(plain, out + 1, TEST_KEY, (long) blocks, OS_ENCRYPT, W_METH_BLOWFISH);

    return blocks + 1;
}

/* ReadSecMSG() on @p msg as remoted calls it, with message-id verification on or off */
static int read_sec_msg(keystore *keys, char *msg, size_t length, int verify, char **output) {
    extern unsigned int _s_recv_flush;
    extern int _s_verify_counter;
    static char cleartext[OS_MAXSTR + 1];
    size_t final_size = 0;
    int saved_verify_counter = _s_verify_counter;
    unsigned int saved_recv_flush = _s_recv_flush;
    int result;

    _s_verify_counter = verify;
    /* High enough that no counter is stored to, or reloaded from, disk */
    _s_recv_flush = 1000000;

    result = ReadSecMSG(keys, msg, cleartext, 0, (unsigned int) length - 1, &final_size, "127.0.0.1", output);

    _s_verify_counter = saved_verify_counter;
    _s_recv_flush = saved_recv_flush;
    return result;
}

/* The cipher of an authenticated message is recorded on the key entry, which the manager answers
 * the agent with. One test for each way ReadSecMSG() accepts a message. */
static void assert_accepted_with_method(int verify, bool legacy, crypt_method before, crypt_method sent) {
    static char msg[OS_MAXSTR];
    keystore *keys = one_agent_keystore(before);
    char *output = NULL;
    size_t length = legacy ? build_legacy_msg(100, 1, "hello", msg) : build_compressed_msg(sent, 1, 1, "hello", msg);

    assert_int_equal(read_sec_msg(keys, msg, length, verify, &output), KS_VALID);
    assert_string_equal(output, "hello");
    assert_int_equal(keys->keyentries[0]->crypto_method, sent);

    free_one_agent_keystore(keys);
}

void test_ReadSecMSG_compressed_message_records_its_crypto_method(void **state) {
    assert_accepted_with_method(0, false, W_METH_BLOWFISH, W_METH_AES);
}

void test_ReadSecMSG_compressed_message_with_a_newer_counter_records_its_crypto_method(void **state) {
    assert_accepted_with_method(1, false, W_METH_BLOWFISH, W_METH_AES);
}

void test_ReadSecMSG_legacy_message_records_its_crypto_method(void **state) {
    assert_accepted_with_method(0, true, W_METH_AES, W_METH_BLOWFISH);
}

void test_ReadSecMSG_legacy_message_with_a_newer_counter_records_its_crypto_method(void **state) {
    assert_accepted_with_method(1, true, W_METH_AES, W_METH_BLOWFISH);
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
        cmocka_unit_test(test_ReadSecMSG_final_size_validation),
        cmocka_unit_test(test_ReadSecMSG_unauthenticated_prefix_keeps_crypto_method),
        cmocka_unit_test(test_ReadSecMSG_legacy_format_length_validation),
        cmocka_unit_test(test_ReadSecMSG_compressed_message_records_its_crypto_method),
        cmocka_unit_test(test_ReadSecMSG_compressed_message_with_a_newer_counter_records_its_crypto_method),
        cmocka_unit_test(test_ReadSecMSG_legacy_message_records_its_crypto_method),
        cmocka_unit_test(test_ReadSecMSG_legacy_message_with_a_newer_counter_records_its_crypto_method)
        };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
