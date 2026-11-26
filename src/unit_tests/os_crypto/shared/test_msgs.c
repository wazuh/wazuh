/*
 * Copyright (C) Wazuh Inc.
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
void StoreSenderCounter(const keystore *keys, unsigned int global, unsigned int local);
void ReloadCounter(const keystore *keys, unsigned int id, const char *cid);

extern unsigned int counter_open_failures;
extern time_t counter_open_last_report;
extern _Atomic (unsigned int) global_count;
extern _Atomic (unsigned int) local_count;
extern unsigned int _s_recv_flush;
extern int _s_verify_counter;
extern int __real_fclose(FILE *_File);

/* Setup/teardown */

static int setup_config(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_config(void **state) {
    test_mode = 0;
    return 0;
}

static int teardown_ceiling(void **state) {
    OS_SetCounterFdCeiling(INT_MAX);
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
    errno = ENOENT;
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

    expect_string(__wrap__mdebug1, formatted_msg, "Decompressed message too short from agent '001'");

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
    expect_string(__wrap__mdebug1, formatted_msg, "Decompressed message too short from agent '001'");

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

    expect_string(__wrap__mdebug1, formatted_msg, "Message too short from agent '001'");

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

/* With message-id verification off, a message not ahead of the stored counters (older, or a replay of the
 * last one) is still accepted, but reported stale and the stored counters are not rolled back; one ahead
 * advances them. One test per message format. */
static void assert_counters_never_go_back(bool legacy) {
    static char msg[OS_MAXSTR];
    keystore *keys = one_agent_keystore(W_METH_BLOWFISH);
    char *output = NULL;
    size_t length;

    keys->keyentries[0]->global = 100;
    keys->keyentries[0]->local = 5;

    /* Older */
    length = legacy ? build_legacy_msg(99, 9, "old", msg) : build_compressed_msg(W_METH_BLOWFISH, 99, 9, "old", msg);
    assert_int_equal(read_sec_msg(keys, msg, length, 0, &output), KS_STALE);
    assert_string_equal(output, "old");
    assert_int_equal(keys->keyentries[0]->global, 100);
    assert_int_equal(keys->keyentries[0]->local, 5);

    /* Equal: a replay of the last accepted message */
    length = legacy ? build_legacy_msg(100, 5, "same", msg) : build_compressed_msg(W_METH_BLOWFISH, 100, 5, "same", msg);
    assert_int_equal(read_sec_msg(keys, msg, length, 0, &output), KS_STALE);
    assert_int_equal(keys->keyentries[0]->global, 100);
    assert_int_equal(keys->keyentries[0]->local, 5);

    /* Ahead: accepted as valid and recorded */
    length = legacy ? build_legacy_msg(100, 6, "new", msg) : build_compressed_msg(W_METH_BLOWFISH, 100, 6, "new", msg);
    assert_int_equal(read_sec_msg(keys, msg, length, 0, &output), KS_VALID);
    assert_string_equal(output, "new");
    assert_int_equal(keys->keyentries[0]->global, 100);
    assert_int_equal(keys->keyentries[0]->local, 6);

    free_one_agent_keystore(keys);
}

void test_ReadSecMSG_compressed_stale_message_keeps_counters(void **state) {
    assert_counters_never_go_back(false);
}

void test_ReadSecMSG_legacy_stale_message_keeps_counters(void **state) {
    assert_counters_never_go_back(true);
}

/* With verification on, a replayed message is still refused as a duplicate (unchanged semantics) */
void test_ReadSecMSG_verify_on_refuses_replayed_message(void **state) {
    static char msg[OS_MAXSTR];
    keystore *keys = one_agent_keystore(W_METH_BLOWFISH);
    char *output = NULL;
    size_t length;

    keys->keyentries[0]->global = 100;
    keys->keyentries[0]->local = 5;

    length = build_compressed_msg(W_METH_BLOWFISH, 100, 5, "same", msg);
    expect_any(__wrap__mwarn, formatted_msg);
    expect_any(__wrap__merror, formatted_msg);
    assert_int_equal(read_sec_msg(keys, msg, length, 1, &output), KS_RIDS);
    assert_int_equal(keys->keyentries[0]->global, 100);
    assert_int_equal(keys->keyentries[0]->local, 5);

    free_one_agent_keystore(keys);
}

/* Tests on counter files that cannot be opened */

static void reset_counter_warnings(void) {
    counter_open_failures = 0;
    counter_open_last_report = 0;
}

/* The line logged when a counter file cannot be opened. A few buffers, since a test may keep several
 * expectations alive at once. */
static const char *counter_open_message(const char *path, int err, unsigned int failures) {
    static char messages[4][OS_MAXSTR];
    static unsigned int next = 0;
    char *message = messages[next++ % 4];

    snprintf(message, OS_MAXSTR,
             "Could not open message counter file '%s': %s (%d). Counter not saved; %u such failures since the last report.",
             path, strerror(err), err, failures);
    return message;
}

static void expect_fclose(FILE *fp, int ret) {
    expect_value(__wrap_fclose, _File, fp);
    will_return(__wrap_fclose, ret);
}

static void expect_clock(time_t now) {
    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);
}

static void expect_rids_open(const char *path, FILE *fp) {
    expect_string(__wrap_wfopen, path, path);
    expect_string(__wrap_wfopen, mode, "r+");
    will_return(__wrap_wfopen, fp);
}

/* What File_Inode() sees: its stat() answers with this inode */
static void expect_inode(const char *path, struct stat *st, ino_t inode) {
    memset(st, 0, sizeof(*st));
    st->st_ino = inode;
    expect_string(__wrap_stat, __file, path);
    will_return(__wrap_stat, st);
    will_return(__wrap_stat, 0);
}

/* A key store with the agent '001' (and no sender entry used) whose counter file is @p fp */
static void counter_keys_init(keystore *keys, keyentry ***entries, keyentry **key, FILE *fp) {
    os_calloc(1, sizeof(keyentry *), *entries);
    os_calloc(1, sizeof(keyentry), *key);
    (*key)->id = strdup("001");
    (*key)->fp = fp;
    (*entries)[0] = *key;
    memset(keys, 0, sizeof(*keys));
    keys->keyentries = *entries;
    keys->keysize = 0;
    keys->opened_fp_queue = linked_queue_init();
}

static void counter_keys_free(keystore *keys, keyentry **entries, keyentry *key) {
    linked_queue_free(keys->opened_fp_queue);
    os_free(key->rids_node);
    os_free(key->id);
    os_free(key);
    os_free(entries);
}

static void assert_store_counter_open_fails(int err) {
    keystore keys;
    keyentry **entries;
    keyentry *key;

    counter_keys_init(&keys, &entries, &key, NULL);
    reset_counter_warnings();

    expect_rids_open("queue/rids/001", NULL);
    expect_clock(100000);
    expect_string(__wrap__merror, formatted_msg, counter_open_message("queue/rids/001", err, 1));

    errno = err;
    StoreCounter(&keys, 0, 1, 2);

    assert_null(key->fp);
    assert_null(key->rids_node);
    assert_int_equal(keys.opened_fp_queue->elements, 0);

    counter_keys_free(&keys, entries, key);
}

void test_StoreCounter_open_fails_emfile(void **state)
{
    assert_store_counter_open_fails(EMFILE);
}

void test_StoreCounter_open_fails_eacces(void **state)
{
    assert_store_counter_open_fails(EACCES);
}

void test_StoreCounter_open_failure_report_is_throttled(void **state)
{
    keystore keys;
    keyentry **entries;
    keyentry *key;
    const time_t t = 1000;

    counter_keys_init(&keys, &entries, &key, NULL);
    reset_counter_warnings();

    expect_rids_open("queue/rids/001", NULL);
    expect_clock(t);
    expect_string(__wrap__merror, formatted_msg, counter_open_message("queue/rids/001", EMFILE, 1));
    errno = EMFILE;
    StoreCounter(&keys, 0, 1, 2);

    /* Just under a minute later: nothing is logged */
    expect_rids_open("queue/rids/001", NULL);
    expect_clock(t + 59);
    errno = EMFILE;
    StoreCounter(&keys, 0, 1, 2);

    /* A minute after the first line: the one that was held back is counted too */
    expect_rids_open("queue/rids/001", NULL);
    expect_clock(t + 60);
    expect_string(__wrap__merror, formatted_msg, counter_open_message("queue/rids/001", EMFILE, 2));
    errno = EMFILE;
    StoreCounter(&keys, 0, 1, 2);

    assert_null(key->fp);
    counter_keys_free(&keys, entries, key);
}

/* Tests on the descriptor ceiling */

void test_StoreCounter_closes_descriptor_at_ceiling(void **state)
{
    keystore keys;
    keyentry **entries;
    keyentry *key;

    counter_keys_init(&keys, &entries, &key, (FILE *)1234);
    OS_SetCounterFdCeiling(100);

    will_return(__wrap_fseek, 0);

    expect_value(__wrap_fprintf, __stream, 1234);
    expect_string(__wrap_fprintf, formatted_msg, "1:2:");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_fileno, __stream, 1234);
    will_return(__wrap_fileno, 100);

    expect_fclose((FILE *)1234, 0);

    StoreCounter(&keys, 0, 1, 2);

    assert_null(key->fp);
    assert_null(key->rids_node);
    assert_int_equal(keys.opened_fp_queue->elements, 0);

    OS_SetCounterFdCeiling(INT_MAX);
    counter_keys_free(&keys, entries, key);
}

void test_StoreCounter_keeps_descriptor_below_ceiling(void **state)
{
    keystore keys;
    keyentry **entries;
    keyentry *key;
    const time_t now = 123456789;

    counter_keys_init(&keys, &entries, &key, (FILE *)1234);
    OS_SetCounterFdCeiling(100);

    will_return(__wrap_fseek, 0);

    expect_value(__wrap_fprintf, __stream, 1234);
    expect_string(__wrap_fprintf, formatted_msg, "1:2:");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_fileno, __stream, 1234);
    will_return(__wrap_fileno, 99);

    expect_clock(now);

    expect_string(__wrap__mdebug2, formatted_msg, "Pushing rids_node for agent 001.");
    expect_memory(__wrap_linked_queue_push_ex, queue, keys.opened_fp_queue, sizeof(keys.opened_fp_queue));
    expect_memory(__wrap_linked_queue_push_ex, data, key, sizeof(key));

    StoreCounter(&keys, 0, 1, 2);

    assert_ptr_equal(key->fp, (FILE *)1234);
    assert_non_null(key->rids_node);
    assert_int_equal(keys.opened_fp_queue->elements, 1);

    OS_SetCounterFdCeiling(INT_MAX);
    counter_keys_free(&keys, entries, key);
}

/* Tests StoreSenderCounter */

static void sender_keys_init(keystore *keys, keyentry ***entries, keyentry **sender) {
    os_calloc(1, sizeof(keyentry *), *entries);
    os_calloc(1, sizeof(keyentry), *sender);
    (*entries)[0] = *sender;
    memset(keys, 0, sizeof(*keys));
    keys->keyentries = *entries;
    keys->keysize = 0;
}

void test_StoreSenderCounter_reopens_closed_file(void **state)
{
    keystore keys;
    keyentry **entries;
    keyentry *sender;

    sender_keys_init(&keys, &entries, &sender);
    reset_counter_warnings();

    expect_rids_open("queue/rids/sender_counter", (FILE *)1234);

    will_return(__wrap_fseek, 0);

    expect_value(__wrap_fprintf, __stream, 1234);
    expect_string(__wrap_fprintf, formatted_msg, "7:8:");
    will_return(__wrap_fprintf, 0);

    StoreSenderCounter(&keys, 7, 8);

    assert_ptr_equal(sender->fp, (FILE *)1234);

    os_free(sender);
    os_free(entries);
}

void test_StoreSenderCounter_open_fails(void **state)
{
    keystore keys;
    keyentry **entries;
    keyentry *sender;

    sender_keys_init(&keys, &entries, &sender);
    reset_counter_warnings();

    expect_rids_open("queue/rids/sender_counter", NULL);
    expect_clock(100000);
    expect_string(__wrap__merror, formatted_msg, counter_open_message("queue/rids/sender_counter", EMFILE, 1));

    errno = EMFILE;
    StoreSenderCounter(&keys, 7, 8);

    assert_null(sender->fp);

    os_free(sender);
    os_free(entries);
}

/* Tests ReloadCounter */

void test_ReloadCounter_open_failure_keeps_entry(void **state)
{
    keystore keys;
    keyentry **entries;
    keyentry *key;
    struct stat st;

    counter_keys_init(&keys, &entries, &key, (FILE *)4321);
    key->inode = 11;
    reset_counter_warnings();

    /* The inode on disk is not the one recorded, so the file is opened again */
    expect_inode("queue/rids/001", &st, 22);
    expect_rids_open("queue/rids/001", NULL);
    expect_clock(100000);
    expect_string(__wrap__merror, formatted_msg, counter_open_message("queue/rids/001", EMFILE, 1));

    errno = EMFILE;
    ReloadCounter(&keys, 0, "001");

    assert_ptr_equal(key->fp, (FILE *)4321);
    assert_int_equal(key->inode, 11);

    counter_keys_free(&keys, entries, key);
}

/* Tests ReadSecMSG() when the counter file cannot be opened */

void test_ReadSecMSG_valid_when_counter_file_cannot_be_opened(void **state)
{
    static char msg[OS_MAXSTR];
    static char cleartext[OS_MAXSTR + 1];
    keystore *keys = one_agent_keystore(W_METH_BLOWFISH);
    char *output = NULL;
    size_t final_size = 0;
    size_t length = build_compressed_msg(W_METH_BLOWFISH, 5, 3, "hello", msg);
    int saved_verify_counter = _s_verify_counter;
    unsigned int saved_recv_flush = _s_recv_flush;
    int result;

    _s_verify_counter = 0;
    /* Every message flushes the counters */
    _s_recv_flush = 0;
    reset_counter_warnings();

    expect_rids_open("queue/rids/001", NULL);
    expect_clock(100000);
    expect_string(__wrap__merror, formatted_msg, counter_open_message("queue/rids/001", EMFILE, 1));

    errno = EMFILE;
    result = ReadSecMSG(keys, msg, cleartext, 0, (unsigned int) length - 1, &final_size, "127.0.0.1", &output);

    _s_verify_counter = saved_verify_counter;
    _s_recv_flush = saved_recv_flush;

    assert_int_equal(result, KS_VALID);
    assert_string_equal(output, "hello");
    assert_int_equal(keys->keyentries[0]->global, 5);
    assert_int_equal(keys->keyentries[0]->local, 3);
    assert_null(keys->keyentries[0]->fp);

    free_one_agent_keystore(keys);
}

/* Tests OS_StartCounter and OS_RestartCounter */

/* Entries '001' and '002' (named agent1 and agent2) and the sender */
static void start_keys_init(keystore *keys) {
    memset(keys, 0, sizeof(*keys));
    os_calloc(3, sizeof(keyentry *), keys->keyentries);
    keys->keysize = 2;

    os_calloc(1, sizeof(keyentry), keys->keyentries[0]);
    keys->keyentries[0]->id = strdup("001");
    keys->keyentries[0]->name = strdup("agent1");
    os_calloc(1, sizeof(keyentry), keys->keyentries[1]);
    keys->keyentries[1]->id = strdup("002");
    keys->keyentries[1]->name = strdup("agent2");
    os_calloc(1, sizeof(keyentry), keys->keyentries[2]);
}

static void start_keys_free(keystore *keys) {
    for (unsigned int i = 0; i <= keys->keysize; i++) {
        os_free(keys->keyentries[i]->id);
        os_free(keys->keyentries[i]->name);
        os_free(keys->keyentries[i]);
    }
    os_free(keys->keyentries);
}

void test_OS_StartCounter_exits_when_counter_file_cannot_be_opened(void **state)
{
    keystore keys;

    start_keys_init(&keys);

    expect_string(__wrap__mdebug1, formatted_msg, "OS_StartCounter: keysize: 2");
    expect_rids_open("queue/rids/001", NULL);
    expect_string(__wrap__merror, formatted_msg, "Unable to open agent file. errno: 24");
    expect_string(__wrap__merror_exit, formatted_msg,
                  "(1103): Could not open file 'queue/rids/001' due to [(24)-(Too many open files)].");

    errno = EMFILE;
    expect_assert_failure(OS_StartCounter(&keys));

    start_keys_free(&keys);
}

void test_OS_RestartCounter_continues_when_counter_file_cannot_be_opened(void **state)
{
    keystore keys;
    struct stat st_first;
    struct stat st_second;
    struct stat st_sender;
    char second_counter[] = "5:7:";
    char sender_counter[] = "3:4:";
    FILE *second_fp = tmpfile();
    FILE *sender_fp = tmpfile();
    int saved_verify_counter = _s_verify_counter;

    assert_non_null(second_fp);
    assert_non_null(sender_fp);
    fputs(second_counter, second_fp);
    rewind(second_fp);
    fputs(sender_counter, sender_fp);
    rewind(sender_fp);

    start_keys_init(&keys);
    keys.keyentries[0]->global = 40;
    keys.keyentries[0]->local = 50;
    reset_counter_warnings();
    global_count = 9;
    local_count = 9;
    _s_verify_counter = 1;

    expect_string(__wrap__mdebug1, formatted_msg, "OS_StartCounter: keysize: 2");

    /* The first counter file cannot be opened */
    expect_rids_open("queue/rids/001", NULL);
    expect_inode("queue/rids/001", &st_first, 301);

    /* The second and the sender's are real files */
    expect_rids_open("queue/rids/002", second_fp);
    expect_string(__wrap__mdebug1, formatted_msg, "Assigning counter for agent agent2: '5:7'.");
    expect_fclose(second_fp, 0);
    expect_inode("queue/rids/002", &st_second, 302);

    expect_rids_open("queue/rids/sender_counter", sender_fp);
    expect_string(__wrap__mdebug1, formatted_msg, "Assigning sender counter: 3:4");
    expect_inode("queue/rids/sender_counter", &st_sender, 303);

    expect_clock(100000);
    expect_string(__wrap__merror, formatted_msg, counter_open_message("queue/rids/001", EMFILE, 1));
    expect_string(__wrap__mdebug2, formatted_msg, "Stored counter.");

    errno = EMFILE;
    OS_RestartCounter(&keys);

    assert_null(keys.keyentries[0]->fp);
    assert_int_equal(keys.keyentries[0]->global, 40);
    assert_int_equal(keys.keyentries[0]->local, 50);
    assert_int_equal(keys.keyentries[0]->inode, 301);

    assert_null(keys.keyentries[1]->fp);
    assert_int_equal(keys.keyentries[1]->global, 5);
    assert_int_equal(keys.keyentries[1]->local, 7);

    /* The sender's file is behind the counters in memory, which stay */
    assert_int_equal(global_count, 9);
    assert_int_equal(local_count, 9);
    assert_ptr_equal(keys.keyentries[2]->fp, sender_fp);

    assert_int_equal(_s_verify_counter, 1);
    assert_non_null(keys.opened_fp_queue);

    _s_verify_counter = saved_verify_counter;
    global_count = 0;
    local_count = 0;
    linked_queue_free(keys.opened_fp_queue);
    __real_fclose(second_fp);
    __real_fclose(sender_fp);
    start_keys_free(&keys);
}

/* A sender counter file that did not exist is created empty: there is nothing to read, and the counters
 * in memory stay */

void test_ReloadCounter_created_sender_file_keeps_counters(void **state)
{
    keystore keys;
    keyentry **entries;
    keyentry *sender;
    struct stat st;

    sender_keys_init(&keys, &entries, &sender);
    sender->inode = 11;
    global_count = 9;
    local_count = 9;

    expect_inode("queue/rids/sender_counter", &st, 22);
    expect_rids_open("queue/rids/sender_counter", NULL);
    expect_string(__wrap_wfopen, path, "queue/rids/sender_counter");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, (FILE *)5555);

    errno = ENOENT;
    ReloadCounter(&keys, 0, "sender_counter");

    assert_ptr_equal(sender->fp, (FILE *)5555);
    assert_int_equal(sender->inode, 22);
    assert_int_equal(global_count, 9);
    assert_int_equal(local_count, 9);

    global_count = 0;
    local_count = 0;
    os_free(sender);
    os_free(entries);
}

void test_OS_RestartCounter_created_sender_file_is_not_read(void **state)
{
    /* The real internal-options read of OS_StartCounter opens a file through the mocked wfopen(), so the
     * same loop runs through OS_RestartCounter */
    keystore keys;
    keyentry **entries;
    keyentry *sender;
    struct stat st;

    sender_keys_init(&keys, &entries, &sender);
    global_count = 9;
    local_count = 9;

    expect_string(__wrap__mdebug1, formatted_msg, "OS_StartCounter: keysize: 0");
    expect_rids_open("queue/rids/sender_counter", NULL);
    expect_string(__wrap_wfopen, path, "queue/rids/sender_counter");
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, (FILE *)5555);
    expect_inode("queue/rids/sender_counter", &st, 22);
    expect_string(__wrap__mdebug2, formatted_msg, "Stored counter.");

    errno = ENOENT;
    OS_RestartCounter(&keys);

    assert_ptr_equal(sender->fp, (FILE *)5555);
    assert_int_equal(sender->inode, 22);
    assert_int_equal(global_count, 9);
    assert_int_equal(local_count, 9);
    assert_non_null(keys.opened_fp_queue);

    global_count = 0;
    local_count = 0;
    linked_queue_free(keys.opened_fp_queue);
    os_free(sender);
    os_free(entries);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests StoreCounter
        cmocka_unit_test_setup_teardown(test_StoreCounter_updating_rids, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_StoreCounter_pushing_rids, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_StoreCounter_pushing_rids_fp_null, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_StoreCounter_fail_first_open, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_StoreCounter_open_fails_emfile, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_StoreCounter_open_fails_eacces, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_StoreCounter_open_failure_report_is_throttled, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_StoreCounter_closes_descriptor_at_ceiling, setup_config, teardown_ceiling),
        cmocka_unit_test_setup_teardown(test_StoreCounter_keeps_descriptor_below_ceiling, setup_config, teardown_ceiling),
        cmocka_unit_test_setup_teardown(test_StoreSenderCounter_reopens_closed_file, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_StoreSenderCounter_open_fails, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_ReloadCounter_open_failure_keeps_entry, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_OS_StartCounter_exits_when_counter_file_cannot_be_opened, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_OS_RestartCounter_continues_when_counter_file_cannot_be_opened, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_ReloadCounter_created_sender_file_keeps_counters, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_OS_RestartCounter_created_sender_file_is_not_read, setup_config, teardown_config),
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
        cmocka_unit_test(test_ReadSecMSG_legacy_message_with_a_newer_counter_records_its_crypto_method),
        cmocka_unit_test(test_ReadSecMSG_compressed_stale_message_keeps_counters),
        cmocka_unit_test(test_ReadSecMSG_legacy_stale_message_keeps_counters),
        cmocka_unit_test(test_ReadSecMSG_verify_on_refuses_replayed_message),
        cmocka_unit_test_setup_teardown(test_ReadSecMSG_valid_when_counter_file_cannot_be_opened, setup_config, teardown_config)
        };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
