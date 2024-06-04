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
#include "../headers/sec.h"
#include "../../wrappers/common.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/rbtree_op_wrappers.h"
#include "../../wrappers/libc/stdio_wrappers.h"

int OS_IsAllowedID(keystore *keys, const char *id);
int w_get_agent_net_protocol_from_keystore(keystore * keys, const char * agent_id);

// Setup / Teardown

static int setup_config(void **state)
{
    /*
     * 001 agent1 1.1.1.1 NULL
     * 002 agent2 2.2.2.2 1628683533
     */
    keystore *keys;

    os_calloc(1, sizeof(keystore), keys);
    os_calloc(3, sizeof(keyentry *), keys->keyentries);
    keys->keysize = 2;

    os_calloc(3, sizeof(keyentry), keys->keyentries[0]);
    keys->keyentries[0]->keyid = 0;
    keys->keyentries[0]->id = "001";
    keys->keyentries[0]->name = "agent1";
    os_calloc(1, sizeof(os_ip), keys->keyentries[0]->ip);
    os_calloc(1, sizeof(os_ipv4), keys->keyentries[0]->ip->ipv4);
    keys->keyentries[0]->ip->ipv4->netmask = 0xFFFFFFFF;
    keys->keyentries[0]->ip->ip = "1.1.1.1";

    os_calloc(3, sizeof(keyentry), keys->keyentries[1]);
    keys->keyentries[1]->keyid = 1;
    keys->keyentries[1]->id = "002";
    keys->keyentries[1]->name = "agent2";
    os_calloc(1, sizeof(os_ip), keys->keyentries[1]->ip);
    os_calloc(1, sizeof(os_ipv4), keys->keyentries[1]->ip->ipv4);
    keys->keyentries[1]->ip->ipv4->netmask = 0xFFFFFFFF;
    keys->keyentries[1]->ip->ip = "2.2.2.2";
    keys->keyentries[1]->time_added = 1628683533;

    *state = keys;
    test_mode = 1;

    return 0;
}

static int teardown_config(void **state)
{
    keystore *keys = *(keystore **)state;

    for (int i = 0; i < keys->keysize; i++) {
        free(keys->keyentries[i]->ip->ipv4);
        free(keys->keyentries[i]->ip);
        free(keys->keyentries[i]);
    }

    free(keys->keyentries);
    free(keys);

    test_mode = 0;

    return 0;
}

// Wraps

int __wrap_TempFile(File *file, const char *source, int copy) {
    file->name = mock_type(char *);
    file->fp = mock_type(FILE *);
    check_expected(source);
    check_expected(copy);
    return mock_type(int);
}

// Test OS_IsAllowedID
void test_OS_IsAllowedID_id_NULL(void **state)
{
    keystore keys;

    const char * id = NULL;

    int ret = OS_IsAllowedID(&keys, id);

    assert_int_equal(ret, -1);

}

void test_OS_IsAllowedID_entry_NULL(void **state)
{
    test_mode = 1;

    keystore *keys = NULL;
    os_calloc(1, sizeof(keystore), keys);
    keys->keytree_id = (rb_tree*)1;

    keyentry * data = NULL;

    const char * id = "12345";

    expect_value(__wrap_rbtree_get, tree, keys->keytree_id);
    expect_string(__wrap_rbtree_get, key, id);
    will_return(__wrap_rbtree_get, data);

    int ret = OS_IsAllowedID(keys, id);

    assert_int_equal(ret, -1);

    os_free(keys);

}

void test_OS_IsAllowedID_entry_OK(void **state)
{
    test_mode = 1;

    keystore *keys = NULL;
    os_calloc(1, sizeof(keystore), keys);
    keys->keytree_id = (rb_tree*)1;

    keyentry * data = NULL;
    os_calloc(1, sizeof(keyentry), data);
    data->keyid = 0;

    const char * id = "12345";

    expect_value(__wrap_rbtree_get, tree, keys->keytree_id);
    expect_string(__wrap_rbtree_get, key, id);
    will_return(__wrap_rbtree_get, data);


    int ret = OS_IsAllowedID(keys, id);

    assert_int_equal(ret, 0);

    os_free(keys);

    os_free(data);

}

// Test w_get_agent_net_protocol_from_keystore
void test_w_get_agent_net_protocol_from_keystore_key_NULL(void **state)
{
    test_mode = 1;

    //test_OS_IsAllowedID_entry_NULL
    keystore *keys = NULL;
    os_calloc(1, sizeof(keystore), keys);
    keys->keytree_id = (rb_tree*)1;

    keyentry * data = NULL;

    const char * id = "12345";

    expect_value(__wrap_rbtree_get, tree, keys->keytree_id);
    expect_string(__wrap_rbtree_get, key, id);
    will_return(__wrap_rbtree_get, data);

    int ret = w_get_agent_net_protocol_from_keystore(keys, id);

    assert_int_equal(ret, -1);

    os_free(keys);

}

void test_w_get_agent_net_protocol_from_keystore_OK(void **state)
{
    test_mode = 1;

    //test_OS_IsAllowedID_entry_OK
    keystore *keys = NULL;
    os_calloc(1, sizeof(keystore), keys);
    keys->keytree_id = (rb_tree*)1;
    os_calloc(1, sizeof(keyentry *), keys->keyentries);
    os_calloc(1, sizeof(keyentry), keys->keyentries[0]);
    keys->keyentries[0]->net_protocol = 1;

    keyentry * data = NULL;
    os_calloc(1, sizeof(keyentry), data);
    data->keyid = 0;

    const char * id = "12345";

    expect_value(__wrap_rbtree_get, tree, keys->keytree_id);
    expect_string(__wrap_rbtree_get, key, id);
    will_return(__wrap_rbtree_get, data);

    int ret = w_get_agent_net_protocol_from_keystore(keys, id);

    assert_int_equal(ret, 1);

    os_free(keys->keyentries[0])
    os_free(keys->keyentries)
    os_free(keys);

    os_free(data);

}

// Test OS_ReadTimestamps

void test_OS_ReadTimestamps_file_missing(void **state)
{
    keystore *keys = *(keystore **)state;

    expect_wfopen(TIMESTAMP_FILE, "r", NULL);
    errno = ENOENT;

    int r = OS_ReadTimestamps(keys);
    assert_int_equal(r, 0);
}

void test_OS_ReadTimestamps_file_error(void **state)
{
    keystore *keys = *(keystore **)state;

    expect_wfopen(TIMESTAMP_FILE, "r", NULL);
    errno = EACCES;

    int r = OS_ReadTimestamps(keys);
    assert_int_equal(r, -1);
}

void test_OS_ReadTimestamps_wrong_line(void **state)
{
    keystore *keys = *(keystore **)state;
    expect_wfopen(TIMESTAMP_FILE, "r", (FILE *)1);

    expect_fclose((FILE *)1, 0);
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "000 wrong line\n");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, NULL);

    int r = OS_ReadTimestamps(keys);
    assert_int_equal(r, 0);
}

void test_OS_ReadTimestamps_valid_line(void **state)
{
    keystore *keys = *(keystore **)state;

    struct tm tm = {
        .tm_sec = 11,
        .tm_min = 36,
        .tm_hour = 14,
        .tm_mday = 11,
        .tm_mon = 7,
        .tm_year = 121,
        .tm_isdst = -1
    };

    expect_wfopen(TIMESTAMP_FILE, "r", (FILE *)1);
    expect_fclose((FILE *)1, 0);
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "001 agent1 1.1.1.1 2021-08-11 14:36:11\n");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, NULL);
    expect_value(__wrap_rbtree_get, tree, NULL);
    expect_string(__wrap_rbtree_get, key, "001");
    will_return(__wrap_rbtree_get, keys->keyentries[0]);

    int r = OS_ReadTimestamps(keys);
    assert_int_equal(r, 0);

    assert_int_equal(keys->keyentries[0]->time_added, mktime(&tm));
    assert_int_equal(keys->keyentries[1]->time_added, 1628683533);
}

// Test OS_WriteTimestamps

void test_OS_WriteTimestamps_file_error(void **state)
{
    keystore *keys = *(keystore **)state;

    expect_string(__wrap_TempFile, source, TIMESTAMP_FILE);
    expect_value(__wrap_TempFile, copy, 0);
    will_return(__wrap_TempFile, NULL);
    will_return(__wrap_TempFile, NULL);
    will_return(__wrap_TempFile, -1);
    expect_string(__wrap__merror, formatted_msg, "Couldn't open timestamp file for writing.");

    int r = OS_WriteTimestamps(keys);
    assert_int_equal(r, -1);
}

void test_OS_WriteTimestamps_file_write(void **state)
{
    keystore *keys = *(keystore **)state;
    char timestamp[40];
    struct tm tm = { .tm_sec = 0 };

    strftime(timestamp, 40, "002 agent2 2.2.2.2 %Y-%m-%d %H:%M:%S\n", localtime_r(&keys->keyentries[1]->time_added, &tm));

    expect_string(__wrap_TempFile, source, TIMESTAMP_FILE);
    expect_value(__wrap_TempFile, copy, 0);
    will_return(__wrap_TempFile, strdup(TIMESTAMP_FILE ".bak"));
    will_return(__wrap_TempFile, (FILE *)1);
    will_return(__wrap_TempFile, 0);
    expect_fprintf((FILE *)1, timestamp, 0);
    expect_fclose((FILE *)1, 0);
    expect_string(__wrap_OS_MoveFile, src, TIMESTAMP_FILE ".bak");
    expect_string(__wrap_OS_MoveFile, dst, TIMESTAMP_FILE);
    will_return(__wrap_OS_MoveFile, 0);

    int r = OS_WriteTimestamps(keys);
    assert_int_equal(r, 0);
}

void test_OS_WriteTimestamps_write_error(void **state)
{
    keystore *keys = *(keystore **)state;
    char timestamp[40];
    struct tm tm = { .tm_sec = 0 };

    strftime(timestamp, 40, "002 agent2 2.2.2.2 %Y-%m-%d %H:%M:%S\n", localtime_r(&keys->keyentries[1]->time_added, &tm));

    expect_string(__wrap_TempFile, source, TIMESTAMP_FILE);
    expect_value(__wrap_TempFile, copy, 0);
    will_return(__wrap_TempFile, strdup(TIMESTAMP_FILE ".bak"));
    will_return(__wrap_TempFile, (FILE *)1);
    will_return(__wrap_TempFile, 0);
    expect_fprintf((FILE *)1, timestamp, -1);
    expect_fclose((FILE *)1, 0);
    expect_string(__wrap_unlink, file, "queue/agents-timestamp.bak");
    will_return(__wrap_unlink, 0);
    expect_string(__wrap__merror, formatted_msg, "(1110): Could not write file 'queue/agents-timestamp.bak' due to [(28)-(No space left on device)].");
    errno = ENOSPC;

    int r = OS_WriteTimestamps(keys);
    assert_int_equal(r, -1);
}

void test_OS_WriteTimestamps_close_error(void **state)
{
    keystore *keys = *(keystore **)state;
    char timestamp[40];
    struct tm tm = { .tm_sec = 0 };

    strftime(timestamp, 40, "002 agent2 2.2.2.2 %Y-%m-%d %H:%M:%S\n", localtime_r(&keys->keyentries[1]->time_added, &tm));

    expect_string(__wrap_TempFile, source, TIMESTAMP_FILE);
    expect_value(__wrap_TempFile, copy, 0);
    will_return(__wrap_TempFile, strdup(TIMESTAMP_FILE ".bak"));
    will_return(__wrap_TempFile, (FILE *)1);
    will_return(__wrap_TempFile, 0);
    expect_fprintf((FILE *)1, timestamp, 0);
    expect_fclose((FILE *)1, -1);
    expect_string(__wrap_unlink, file, "queue/agents-timestamp.bak");
    will_return(__wrap_unlink, 0);
    expect_string(__wrap__merror, formatted_msg, "(1140): Could not close file 'queue/agents-timestamp.bak' due to [(28)-(No space left on device)].");
    errno = ENOSPC;

    int r = OS_WriteTimestamps(keys);
    assert_int_equal(r, -1);
}

void test_OS_WriteTimestamps_move_error(void **state)
{
    keystore *keys = *(keystore **)state;
    char timestamp[40];
    struct tm tm = { .tm_sec = 0 };

    strftime(timestamp, 40, "002 agent2 2.2.2.2 %Y-%m-%d %H:%M:%S\n", localtime_r(&keys->keyentries[1]->time_added, &tm));

    expect_string(__wrap_TempFile, source, TIMESTAMP_FILE);
    expect_value(__wrap_TempFile, copy, 0);
    will_return(__wrap_TempFile, strdup(TIMESTAMP_FILE ".bak"));
    will_return(__wrap_TempFile, (FILE *)1);
    will_return(__wrap_TempFile, 0);
    expect_fprintf((FILE *)1, timestamp, 0);
    expect_fclose((FILE *)1, 0);
    expect_string(__wrap_OS_MoveFile, src, TIMESTAMP_FILE ".bak");
    expect_string(__wrap_OS_MoveFile, dst, TIMESTAMP_FILE);
    will_return(__wrap_OS_MoveFile, -1);
    expect_string(__wrap_unlink, file, "queue/agents-timestamp.bak");
    will_return(__wrap_unlink, 0);

    int r = OS_WriteTimestamps(keys);
    assert_int_equal(r, -1);
}

// Test w_get_key_hash

void test_w_get_key_hash_empty_parameters(void **state){
    keyentry *keys = NULL;
    os_sha1 output = {0};
    int ret;

    expect_string(__wrap__mdebug2, formatted_msg, "Unable to hash agent's key due to empty parameters.");
    ret = w_get_key_hash(keys, output);

    assert_int_equal(ret, OS_INVALID);
}

void test_w_get_key_hash_empty_value(void **state){
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

void test_w_get_key_hash_success(void **state){
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

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests OS_IsAllowedID
        cmocka_unit_test(test_OS_IsAllowedID_id_NULL),
        cmocka_unit_test(test_OS_IsAllowedID_entry_NULL),
        cmocka_unit_test(test_OS_IsAllowedID_entry_OK),
        // Tests w_get_agent_net_protocol_from_keystore
        cmocka_unit_test(test_w_get_agent_net_protocol_from_keystore_key_NULL),
        cmocka_unit_test(test_w_get_agent_net_protocol_from_keystore_OK),
        // Test OS_ReadTimestamps
        cmocka_unit_test_setup_teardown(test_OS_ReadTimestamps_file_missing, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_OS_ReadTimestamps_file_error, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_OS_ReadTimestamps_wrong_line, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_OS_ReadTimestamps_valid_line, setup_config, teardown_config),
        // Test OS_WriteTimestamps
        cmocka_unit_test_setup_teardown(test_OS_WriteTimestamps_file_error, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_OS_WriteTimestamps_file_write, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_OS_WriteTimestamps_write_error, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_OS_WriteTimestamps_close_error, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_OS_WriteTimestamps_move_error, setup_config, teardown_config),
        // Test w_get_key_hash
        cmocka_unit_test(test_w_get_key_hash_empty_parameters),
        cmocka_unit_test(test_w_get_key_hash_empty_value),
        cmocka_unit_test(test_w_get_key_hash_success)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
