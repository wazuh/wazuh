/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <cmocka.h>

#include "shared.h"
#include "remoted.h"
#include "secure.c"
#include "../wrappers/common.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/linux/socket_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/os_crypto/keys_wrappers.h"
#include "../wrappers/wazuh/os_crypto/msgs_wrappers.h"
#include "../wrappers/wazuh/remoted/manager_wrappers.h"
#include "../wrappers/wazuh/remoted/netbuffer_wrappers.h"
#include "../wrappers/wazuh/remoted/netcounter_wrappers.h"
#include "../wrappers/wazuh/remoted/queue_wrappers.h"
#include "../wrappers/wazuh/remoted/state_wrappers.h"
#include "../wrappers/wazuh/remoted/agent_metadata_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/shared/queue_linked_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"
#include "../wrappers/wazuh/shared/batch_queue_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_metadata_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"

typedef struct test_agent_info
{
    char* agent_id;
    char* agent_name;
    char* agent_ip;
} test_agent_info;

extern keystore keys;
extern remoted logr;
extern wnotify_t* notify;
extern char* str_family_address[FAMILY_ADDRESS_SIZE];
extern OSHash* agent_data_hash;

void tmp_HandleSecureMessage_invalid_family_address(sa_family_t sin_family);

/* Forward declarations */
void * close_fp_main(void * args);
void HandleSecureMessage(const message_t *message, w_indexed_queue_t * control_msg_queue, w_rr_queue_t * batch_queue);
// STATIC in secure.c, which expands to nothing under WAZUH_UNIT_TESTING.
bool discard_legacy_agent_message(const char* msg, const char* agent_id);

/* Setup/teardown */

static int setup_config(void** state)
{
    w_linked_queue_t* queue = linked_queue_init();
    keys.opened_fp_queue = queue;
    test_mode = 1;


    return 0;
}

static int teardown_config(void** state)
{
    linked_queue_free(keys.opened_fp_queue);
    test_mode = 0;
    return 0;
}

static int setup_new_tcp(void** state)
{
    test_mode = 1;
    os_calloc(1, sizeof(wnotify_t), notify);
    notify->fd = 0;
    return 0;
}

static int teardown_new_tcp(void** state)
{
    test_mode = 0;
    os_free(notify);
    return 0;
}

static int setup_remoted_configuration(void** state)
{
    test_mode = 1;
    node_name = "test_node_name";
    agent_data_hash = (OSHash*)1;

    test_agent_info* agent;
    os_calloc(1, sizeof(test_agent_info), agent);
    os_strdup("001", agent->agent_id);
    os_strdup("focal", agent->agent_name);
    os_strdup("192.168.33.20", agent->agent_ip);

    *state = agent;

    return 0;
}

static int teardown_remoted_configuration(void** state)
{
    test_mode = 0;
    node_name = "";

    test_agent_info* data = (test_agent_info*)*state;
    free(data->agent_id);
    free(data->agent_name);
    free(data->agent_ip);
    free(data);

    return 0;
}

/* Wrappers */

time_t __wrap_time(int time)
{
    check_expected(time);
    return mock();
}

void __wrap_key_lock_write()
{
    function_called();
}

void __wrap_key_unlock()
{
    function_called();
}

void __wrap_key_lock_read()
{
    function_called();
}

int __wrap_close(int __fd)
{
    return mock();
}

/*****************WRAPS********************/
int __wrap_w_mutex_lock(pthread_mutex_t* mutex)
{
    check_expected_ptr(mutex);
    return 0;
}

int __wrap_w_mutex_unlock(pthread_mutex_t* mutex)
{
    check_expected_ptr(mutex);
    return 0;
}

/* Tests close_fp_main*/

void test_close_fp_main_queue_empty(void** state)
{
    logr.rids_closing_time = 10;

    // sleep
    expect_value(__wrap_sleep, seconds, 10);

    // key_lock
    expect_function_call(__wrap_key_lock_write);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 0");

    expect_string(__wrap__mdebug1, formatted_msg, "Rids closer thread started.");

    // key_unlock
    expect_function_call(__wrap_key_unlock);

    close_fp_main(&keys);
    assert_int_equal(keys.opened_fp_queue->elements, 0);
}

void test_close_fp_main_first_node_no_close_first(void** state)
{
    logr.rids_closing_time = 10;

    keyentry* first_node_key = NULL;
    os_calloc(1, sizeof(keyentry), first_node_key);

    int now = 123456789;
    first_node_key->id = strdup("001");
    first_node_key->updating_time = now - 1;

    // Queue with one element
    w_linked_queue_node_t* node1 = linked_queue_push(keys.opened_fp_queue, first_node_key);
    keys.opened_fp_queue->first = node1;

    // sleep
    expect_value(__wrap_sleep, seconds, 10);

    // key_lock
    expect_function_call(__wrap_key_lock_write);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 1");

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Checking rids_node of agent 001.");

    expect_string(__wrap__mdebug1, formatted_msg, "Rids closer thread started.");
    // key_unlock
    expect_function_call(__wrap_key_unlock);

    close_fp_main(&keys);
    assert_int_equal(keys.opened_fp_queue->elements, 1);
    os_free(node1);
    os_free(first_node_key->id);
    os_free(first_node_key);
}

void test_close_fp_main_close_first(void** state)
{
    logr.rids_closing_time = 10;

    keyentry* first_node_key = NULL;
    os_calloc(1, sizeof(keyentry), first_node_key);

    int now = 123456789;
    first_node_key->id = strdup("001");
    first_node_key->updating_time = now - logr.rids_closing_time - 100;

    first_node_key->fp = (FILE*)1234;

    // Queue with one element
    w_linked_queue_node_t* node1 = linked_queue_push(keys.opened_fp_queue, first_node_key);

    // sleep
    expect_value(__wrap_sleep, seconds, 10);

    // key_lock
    expect_function_call(__wrap_key_lock_write);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 1");

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Checking rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Pop rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Closing rids for agent 001.");

    expect_value(__wrap_fclose, _File, (FILE*)1234);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 0");

    expect_string(__wrap__mdebug1, formatted_msg, "Rids closer thread started.");

    // key_unlock
    expect_function_call(__wrap_key_unlock);

    close_fp_main(&keys);
    assert_int_equal(keys.opened_fp_queue->elements, 0);
    os_free(first_node_key->id);
    os_free(first_node_key);
}

void test_close_fp_main_close_first_queue_2(void** state)
{
    logr.rids_closing_time = 10;

    keyentry* first_node_key = NULL;
    os_calloc(1, sizeof(keyentry), first_node_key);

    keyentry* second_node_key = NULL;
    os_calloc(1, sizeof(keyentry), second_node_key);

    int now = 123456789;
    first_node_key->id = strdup("001");
    first_node_key->updating_time = now - logr.rids_closing_time - 100;
    first_node_key->fp = (FILE*)1234;

    second_node_key->id = strdup("002");
    second_node_key->updating_time = now - 1;

    // Queue with one element
    w_linked_queue_node_t* node1 = linked_queue_push(keys.opened_fp_queue, first_node_key);
    w_linked_queue_node_t* node2 = linked_queue_push(keys.opened_fp_queue, second_node_key);

    // sleep
    expect_value(__wrap_sleep, seconds, 10);

    // key_lock
    expect_function_call(__wrap_key_lock_write);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 2");

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Checking rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Pop rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Closing rids for agent 001.");

    expect_value(__wrap_fclose, _File, (FILE*)1234);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 1");

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Checking rids_node of agent 002.");

    expect_string(__wrap__mdebug1, formatted_msg, "Rids closer thread started.");

    // key_unlock
    expect_function_call(__wrap_key_unlock);

    close_fp_main(&keys);
    assert_int_equal(keys.opened_fp_queue->elements, 1);
    os_free(first_node_key->id);
    os_free(first_node_key);

    os_free(node2);
    os_free(second_node_key->id);
    os_free(second_node_key);
}

void test_close_fp_main_close_first_queue_2_close_2(void** state)
{
    logr.rids_closing_time = 10;

    keyentry* first_node_key = NULL;
    os_calloc(1, sizeof(keyentry), first_node_key);

    keyentry* second_node_key = NULL;
    os_calloc(1, sizeof(keyentry), second_node_key);

    int now = 123456789;
    first_node_key->id = strdup("001");
    first_node_key->updating_time = now - logr.rids_closing_time - 100;
    first_node_key->fp = (FILE*)1234;

    second_node_key->id = strdup("002");
    second_node_key->updating_time = now - logr.rids_closing_time - 99;
    second_node_key->fp = (FILE*)1234;

    // Queue with one element
    w_linked_queue_node_t* node1 = linked_queue_push(keys.opened_fp_queue, first_node_key);
    w_linked_queue_node_t* node2 = linked_queue_push(keys.opened_fp_queue, second_node_key);

    // sleep
    expect_value(__wrap_sleep, seconds, 10);

    // key_lock
    expect_function_call(__wrap_key_lock_write);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 2");

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Checking rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Pop rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Closing rids for agent 001.");

    expect_value(__wrap_fclose, _File, (FILE*)1234);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 1");

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Checking rids_node of agent 002.");

    expect_string(__wrap__mdebug2, formatted_msg, "Pop rids_node of agent 002.");

    expect_string(__wrap__mdebug2, formatted_msg, "Closing rids for agent 002.");

    expect_value(__wrap_fclose, _File, (FILE*)1234);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 0");

    expect_string(__wrap__mdebug1, formatted_msg, "Rids closer thread started.");

    // key_unlock
    expect_function_call(__wrap_key_unlock);

    close_fp_main(&keys);
    assert_int_equal(keys.opened_fp_queue->elements, 0);
    os_free(first_node_key->id);
    os_free(first_node_key);

    os_free(second_node_key->id);
    os_free(second_node_key);
}

void test_close_fp_main_close_fp_null(void** state)
{
    logr.rids_closing_time = 10;

    keyentry* first_node_key = NULL;
    os_calloc(1, sizeof(keyentry), first_node_key);

    int now = 123456789;
    first_node_key->id = strdup("001");
    first_node_key->updating_time = now - logr.rids_closing_time - 100;
    first_node_key->fp = NULL;

    // Queue with one element
    w_linked_queue_node_t* node1 = linked_queue_push(keys.opened_fp_queue, first_node_key);

    // sleep
    expect_value(__wrap_sleep, seconds, 10);

    // key_lock
    expect_function_call(__wrap_key_lock_write);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 1");

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Checking rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Pop rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 0");

    expect_string(__wrap__mdebug1, formatted_msg, "Rids closer thread started.");

    // key_unlock
    expect_function_call(__wrap_key_unlock);

    close_fp_main(&keys);
    assert_int_equal(keys.opened_fp_queue->elements, 0);
    os_free(first_node_key->id);
    os_free(first_node_key);
}

void tmp_HandleSecureMessage_invalid_family_address(sa_family_t sin_family)
{
    char buffer[OS_MAXSTR + 1] = "!1234!";
    message_t message = {.buffer = buffer, .size = 6, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("001");
    key->sock = 1;
    key->keyid = 1;

    keys.keyentries[0] = key;

    global_counter = 0;

    peer_info.sin_family = sin_family;
    memcpy(&message.addr, &peer_info, sizeof(peer_info));
    char auxBuff[OS_MAXSTR + 1] = {0};

    if (peer_info.sin_family < sizeof(str_family_address) / sizeof(str_family_address[0]))
    {
        sprintf(auxBuff,
                "IP address family '%d':'%s' not supported.",
                peer_info.sin_family,
                str_family_address[peer_info.sin_family]);
        expect_string(__wrap__merror, formatted_msg, auxBuff);
    }
    else
    {
        sprintf(auxBuff, "IP address family '%d' not found.", peer_info.sin_family);
        expect_string(__wrap__merror, formatted_msg, auxBuff);
    }

    expect_function_call(__wrap_rem_inc_recv_unknown);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_invalid_family_address_af_unspec(void** state)
{
    tmp_HandleSecureMessage_invalid_family_address(AF_UNSPEC);
}

void test_HandleSecureMessage_invalid_family_address_af_netlink(void** state)
{
    tmp_HandleSecureMessage_invalid_family_address(AF_NETLINK);
}

void test_HandleSecureMessage_invalid_family_address_af_unix(void** state)
{
    tmp_HandleSecureMessage_invalid_family_address(AF_UNIX);
}

void test_HandleSecureMessage_invalid_family_address_af_x25(void** state)
{
    tmp_HandleSecureMessage_invalid_family_address(AF_X25);
}

void test_HandleSecureMessage_invalid_family_address_not_found(void** state)
{
    tmp_HandleSecureMessage_invalid_family_address(50);
}

void test_HandleSecureMessage_shutdown_message(void** state)
{
    char buffer[OS_MAXSTR + 1] = "#!-agent shutdown ";
    message_t message = {.buffer = buffer, .size = 18, .sock = 1, .counter = 10};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    agent_meta_t *mocked_meta_ptr = NULL;
    os_calloc(1, sizeof(*mocked_meta_ptr), mocked_meta_ptr);
    mocked_meta_ptr->agent_id = 1;
    mocked_meta_ptr->agent_name = strdup("test-agent");
    mocked_meta_ptr->agent_version = strdup("5.0.0");

    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("009");
    key->name = strdup("test_agent");
    key->sock = 1;
    key->keyid = 1;

    keys.keyentries[0] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = 0x0100007F;
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 0);

    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_string(__wrap_ReadSecMSG, buffer, "#!-agent shutdown ");
    expect_value(__wrap_ReadSecMSG, id, 0);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, message.size);
    will_return(__wrap_ReadSecMSG, "#!-agent shutdown ");
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_value(__wrap_rem_getCounter, fd, 1);
    will_return(__wrap_rem_getCounter, 10);

    // OS_DupKeyEntry
    expect_value(__wrap_OS_DupKeyEntry, key, key);
    will_return(__wrap_OS_DupKeyEntry, key);

    expect_value(__wrap_rem_getCounter, fd, 1);
    will_return(__wrap_rem_getCounter, 10);

    expect_function_call(__wrap_key_unlock);


    expect_function_call(__wrap_rem_inc_recv_ctrl);

    // Should be added to the queue
    expect_value(__wrap_validate_control_msg, key, key);
    expect_string(__wrap_validate_control_msg, r_msg, "agent shutdown ");
    expect_value(__wrap_validate_control_msg, msg_length, 15);
    will_return(__wrap_validate_control_msg, 1);

    // OS_FreeKey
    expect_value(__wrap_OS_FreeKey, key, key);

    /* __wrap_agent_meta_from_agent_info */
    expect_string(__wrap_agent_meta_from_agent_info, id_str, "009");
    expect_any(__wrap_agent_meta_from_agent_info, agent_name);
    expect_any(__wrap_agent_meta_from_agent_info, ai);
    will_return(__wrap_agent_meta_from_agent_info, mocked_meta_ptr);

    /* __wrap_agent_meta_upsert_locked */
    expect_string(__wrap_agent_meta_upsert_locked, agent_id_str, "009");
    expect_value(__wrap_agent_meta_upsert_locked, fresh, mocked_meta_ptr);
    will_return(__wrap_agent_meta_upsert_locked, 0);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    // Expect the control message to be added to the queue
    w_ctrl_msg_data_t * node = indexed_queue_pop(control_msg_queue);
    assert_non_null(node);
    assert_string_equal(node->message, "agent shutdown ");
    assert_int_equal('\0', node->message[strlen("agent shutdown ")]);
    assert_int_equal(node->key->keyid, 1);
    assert_int_equal(node->key->sock, 1);
    assert_string_equal(node->key->id, "009");

    OS_FreeKey(node->key);
    os_free(node->message);
    os_free(node);

    os_free(key->id);
    os_free(key->name);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
    agent_meta_clear(mocked_meta_ptr);
    agent_meta_free(mocked_meta_ptr);
}

void test_HandleSecureMessage_HC_req_message(void** state)
{
    char buffer[OS_MAXSTR + 1] = "#!-req payload";
    message_t message = {.buffer = buffer, .size = 14, .sock = 1, .counter = 11};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("009");
    key->name = strdup("test_agent");
    key->sock = 1;
    key->keyid = 1;

    keys.keyentries[0] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = 0x0100007F;
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 0);

    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_string(__wrap_ReadSecMSG, buffer, "#!-req payload");
    expect_value(__wrap_ReadSecMSG, id, 0);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, message.size);
    will_return(__wrap_ReadSecMSG, "#!-req payload");
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_value(__wrap_rem_getCounter, fd, 1);
    will_return(__wrap_rem_getCounter, 10);

    // OS_DupKeyEntry
    expect_value(__wrap_OS_DupKeyEntry, key, key);
    will_return(__wrap_OS_DupKeyEntry, key);

    // OS_AddSocket
    expect_value(__wrap_OS_AddSocket, keys, &keys);
    expect_value(__wrap_OS_AddSocket, i, 0);
    expect_value(__wrap_OS_AddSocket, sock, message.sock);
    will_return(__wrap_OS_AddSocket, OS_ADDSOCKET_KEY_ADDED);

    expect_string(__wrap__mdebug2, formatted_msg, "TCP socket 1 added to keystore.");

    expect_function_call(__wrap_key_unlock);

    expect_value(__wrap_rem_getCounter, fd, 1);
    will_return(__wrap_rem_getCounter, 10);

    expect_function_call(__wrap_rem_inc_recv_ctrl);

    // Should be added to the queue
    expect_value(__wrap_validate_control_msg, key, key);
    expect_string(__wrap_validate_control_msg, r_msg, "req payload");
    expect_value(__wrap_validate_control_msg, msg_length, 11);
    will_return(__wrap_validate_control_msg, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Control message processed directly, not queued.");


    // OS_FreeKey
    expect_value(__wrap_OS_FreeKey, key, key);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    // Expect the control message to be added to the queue
    assert_true(indexed_queue_empty(control_msg_queue));

    os_free(key->id);
    os_free(key->name);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}


void test_HandleSecureMessage_invalid_HC_req_message(void** state)
{
    char buffer[OS_MAXSTR + 1] = "#!-req witouthCounter";
    message_t message = {.buffer = buffer, .size = 21, .sock = 1, .counter = 11};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("009");
    key->name = strdup("test_agent");
    key->sock = 1;
    key->keyid = 1;

    keys.keyentries[0] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = 0x0100007F;
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 0);

    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_string(__wrap_ReadSecMSG, buffer, "#!-req witouthCounter");
    expect_value(__wrap_ReadSecMSG, id, 0);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, message.size);
    will_return(__wrap_ReadSecMSG, "#!-req witouthCounter");
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_value(__wrap_rem_getCounter, fd, 1);
    will_return(__wrap_rem_getCounter, 10);

    // OS_DupKeyEntry
    expect_value(__wrap_OS_DupKeyEntry, key, key);
    will_return(__wrap_OS_DupKeyEntry, key);

    // OS_AddSocket
    expect_value(__wrap_OS_AddSocket, keys, &keys);
    expect_value(__wrap_OS_AddSocket, i, 0);
    expect_value(__wrap_OS_AddSocket, sock, message.sock);
    will_return(__wrap_OS_AddSocket, OS_ADDSOCKET_KEY_ADDED);

    expect_string(__wrap__mdebug2, formatted_msg, "TCP socket 1 added to keystore.");

    expect_function_call(__wrap_key_unlock);

    expect_value(__wrap_rem_getCounter, fd, 1);
    will_return(__wrap_rem_getCounter, 10);

    expect_function_call(__wrap_rem_inc_recv_ctrl);

    // Should be added to the queue
    expect_value(__wrap_validate_control_msg, key, key);
    expect_string(__wrap_validate_control_msg, r_msg, "req witouthCounter");
    expect_value(__wrap_validate_control_msg, msg_length, 18);
    will_return(__wrap_validate_control_msg, -1);

    expect_string(__wrap__mwarn, formatted_msg, "Error validating control message from agent ID '009'.");


    // OS_FreeKey
    expect_value(__wrap_OS_FreeKey, key, key);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    // Expect the control message to be added to the queue
    assert_true(indexed_queue_empty(control_msg_queue));

    os_free(key->id);
    os_free(key->name);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}


void test_HandleSecureMessage_NewMessage_NoShutdownMessage(void** state)
{
    char buffer[OS_MAXSTR + 1] = "#!-agent startup ";
    message_t message = {.buffer = buffer, .size = 17, .sock = 1, .counter = 11};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    agent_meta_t *mocked_meta_ptr = NULL;
    os_calloc(1, sizeof(*mocked_meta_ptr), mocked_meta_ptr);
    mocked_meta_ptr->agent_id = 1;
    mocked_meta_ptr->agent_name = strdup("test-agent");
    mocked_meta_ptr->agent_version = strdup("5.0.0");

    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("009");
    key->sock = 1;
    key->keyid = 1;

    keys.keyentries[0] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = 0x0100007F;
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 0);

    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_string(__wrap_ReadSecMSG, buffer, "#!-agent startup ");
    expect_value(__wrap_ReadSecMSG, id, 0);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, message.size);
    will_return(__wrap_ReadSecMSG, "#!-agent startup ");
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_value(__wrap_rem_getCounter, fd, 1);
    will_return(__wrap_rem_getCounter, 10);

    // OS_DupKeyEntry
    expect_value(__wrap_OS_DupKeyEntry, key, key);
    will_return(__wrap_OS_DupKeyEntry, key);

    expect_value(__wrap_rem_getCounter, fd, 1);
    will_return(__wrap_rem_getCounter, 10);

    expect_value(__wrap_OS_AddSocket, keys, &keys);
    expect_value(__wrap_OS_AddSocket, i, 0);
    expect_value(__wrap_OS_AddSocket, sock, message.sock);
    will_return(__wrap_OS_AddSocket, 2);

    expect_string(__wrap__mdebug2, formatted_msg, "TCP socket 1 added to keystore.");

    expect_function_call(__wrap_key_unlock);


    expect_function_call(__wrap_rem_inc_recv_ctrl);

    // Should be added to the queue
    expect_value(__wrap_validate_control_msg, key, key);
    expect_string(__wrap_validate_control_msg, r_msg, "agent startup ");
    expect_value(__wrap_validate_control_msg, msg_length, 14);
    will_return(__wrap_validate_control_msg, 1);

    /* __wrap_agent_meta_from_agent_info */
    expect_string(__wrap_agent_meta_from_agent_info, id_str, "009");
    expect_any(__wrap_agent_meta_from_agent_info, agent_name);
    expect_any(__wrap_agent_meta_from_agent_info, ai);
    will_return(__wrap_agent_meta_from_agent_info, mocked_meta_ptr);

    /* __wrap_agent_meta_upsert_locked */
    expect_string(__wrap_agent_meta_upsert_locked, agent_id_str, "009");
    expect_value(__wrap_agent_meta_upsert_locked, fresh, mocked_meta_ptr);
    will_return(__wrap_agent_meta_upsert_locked, 0);

    // OS_FreeKey
    expect_value(__wrap_OS_FreeKey, key, key);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    // Expect the control message to be added to the queue
    w_ctrl_msg_data_t * node = indexed_queue_pop(control_msg_queue);
    assert_non_null(node);
    assert_string_equal(node->message, "agent startup ");
    assert_int_equal(node->key->keyid, 1);
    assert_int_equal(node->key->sock, 1);
    assert_string_equal(node->key->id, "009");

    OS_FreeKey(node->key);
    os_free(node->message);
    os_free(node);

    os_free(key->id);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
    agent_meta_clear(mocked_meta_ptr);
    agent_meta_free(mocked_meta_ptr);
}

void test_HandleSecureMessage_OldMessage_NoShutdownMessage(void** state)
{
    char buffer[OS_MAXSTR + 1] = "#!-agent startup ";
    message_t message = {.buffer = buffer, .size = 17, .sock = 1, .counter = 5};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("009");
    key->sock = 1;
    key->keyid = 1;

    keys.keyentries[0] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = 0x0100007F;
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 0);

    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_string(__wrap_ReadSecMSG, buffer, "#!-agent startup ");
    expect_value(__wrap_ReadSecMSG, id, 0);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, message.size);
    will_return(__wrap_ReadSecMSG, "#!-agent startup ");
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_value(__wrap_rem_getCounter, fd, 1);
    will_return(__wrap_rem_getCounter, 10);

    expect_function_call(__wrap_key_unlock);
    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_invalid_message(void** state)
{
    char buffer[OS_MAXSTR + 1] = "!1234!";
    message_t message = {.buffer = buffer, .size = 6, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("001");
    key->sock = 1;
    key->keyid = 1;

    keys.keyentries[0] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = 0x0100007F;
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedDynamicID
    expect_string(__wrap_OS_IsAllowedDynamicID, id, "1234");
    expect_string(__wrap_OS_IsAllowedDynamicID, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedDynamicID, 0);

    expect_string(__wrap__mwarn, formatted_msg, "Received message is empty from '127.0.0.1'");

    expect_function_call(__wrap_key_unlock);

    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, message.sock);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, 1);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [1]");

    expect_function_call(__wrap_rem_inc_recv_unknown);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_different_sock(void** state)
{
    char buffer[OS_MAXSTR + 1] = "!12!";
    message_t message = {.buffer = buffer, .size = 4, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    logr.connection_overtake_time = 60;

    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("001");
    key->sock = 4;
    key->keyid = 1;
    key->rcvd = 200;         // not idle, no overtake
    key->conflict_ts = 100;  // conflict older than the window -> warn

    keys.keyentries[0] = key;

    global_counter = 0;
    current_ts = 200;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedDynamicID
    expect_string(__wrap_OS_IsAllowedDynamicID, id, "12");
    expect_string(__wrap_OS_IsAllowedDynamicID, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedDynamicID, 0);

    expect_function_call(__wrap_key_unlock);

    expect_string(__wrap__mwarn, formatted_msg, "Agent key already in use: agent ID '001' (source IP: 127.0.0.1)");

    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, message.sock);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, 1);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [1]");

    expect_function_call(__wrap_rem_inc_recv_unknown);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_different_sock_2(void** state)
{
    char buffer[OS_MAXSTR + 1] = "12!";
    message_t message = {.buffer = buffer, .size = 4, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    logr.connection_overtake_time = 60;

    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("001");
    key->sock = 4;
    key->keyid = 1;
    key->rcvd = 200;         // not idle, no overtake
    key->conflict_ts = 100;  // conflict older than the window -> warn

    keys.keyentries[0] = key;

    global_counter = 0;
    current_ts = 200;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedDynamicID
    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 0);

    expect_function_call(__wrap_key_unlock);

    expect_string(__wrap__mwarn, formatted_msg, "Agent key already in use: agent ID '001' (source IP: 127.0.0.1)");

    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, message.sock);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, 1);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [1]");

    expect_function_call(__wrap_rem_inc_recv_unknown);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_conflict_first_seen(void** state)
{
    char buffer[OS_MAXSTR + 1] = "!12!";
    message_t message = {.buffer = buffer, .size = 4, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    logr.connection_overtake_time = 60;
    current_ts = 100;

    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("001");
    key->sock = 4;
    key->keyid = 1;
    key->rcvd = 100;        // not idle, no overtake
    key->conflict_ts = 0;   // first conflict

    keys.keyentries[0] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedDynamicID
    expect_string(__wrap_OS_IsAllowedDynamicID, id, "12");
    expect_string(__wrap_OS_IsAllowedDynamicID, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedDynamicID, 0);

    expect_function_call(__wrap_key_unlock);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent ID '001' reconnected from '127.0.0.1' before its previous session was closed.");

    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, message.sock);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, 1);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [1]");

    expect_function_call(__wrap_rem_inc_recv_unknown);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    assert_int_equal(key->conflict_ts, 100); // conflict recorded

    os_free(key->id);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_conflict_persists(void** state)
{
    char buffer[OS_MAXSTR + 1] = "!12!";
    message_t message = {.buffer = buffer, .size = 4, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    logr.connection_overtake_time = 60;
    current_ts = 200;

    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("001");
    key->sock = 4;
    key->keyid = 1;
    key->rcvd = 200;         // not idle, no overtake
    key->conflict_ts = 100;  // conflict older than the window -> warn

    keys.keyentries[0] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedDynamicID
    expect_string(__wrap_OS_IsAllowedDynamicID, id, "12");
    expect_string(__wrap_OS_IsAllowedDynamicID, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedDynamicID, 0);

    expect_function_call(__wrap_key_unlock);

    expect_string(__wrap__mwarn, formatted_msg, "Agent key already in use: agent ID '001' (source IP: 127.0.0.1)");

    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, message.sock);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, 1);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [1]");

    expect_function_call(__wrap_rem_inc_recv_unknown);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_close_idle_sock(void** state)
{
    char buffer[OS_MAXSTR + 1] = "12!";
    message_t message = {.buffer = buffer, .size = 4, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    current_ts = 61;

    logr.connection_overtake_time = 60;

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    os_calloc(1, sizeof(os_ip), key->ip);

    key->id = strdup("001");
    key->sock = 4;
    key->keyid = 1;
    key->rcvd = 0;
    key->ip->ip = "127.0.0.1";
    key->name = strdup("name");

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedDynamicID
    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Idle socket [4] from agent ID '001' will be closed.");

    // ReadSecMSG
    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_string(__wrap_ReadSecMSG, buffer, buffer);
    expect_value(__wrap_ReadSecMSG, id, 1);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, message.size);
    will_return(__wrap_ReadSecMSG, buffer);
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_function_call(__wrap_key_unlock);

    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, key->sock);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, key->sock);
    expect_value(__wrap_nb_close, sock, key->sock);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, 4);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [4]");
    expect_string(__wrap__mdebug1, formatted_msg, "Stripped 1 trailing null byte(s) from event payload of agent '001'");

    /* enqueue */
    expect_value(__wrap_batch_queue_enqueue_ex, sched, events_queue);
    expect_string(__wrap_batch_queue_enqueue_ex, agent_key, "001");
    expect_any(__wrap_batch_queue_enqueue_ex, data);
    will_return(__wrap_batch_queue_enqueue_ex, -1);
    expect_value(__wrap_time, time, NULL);
    will_return(__wrap_time, 0);
    expect_function_call(__wrap_rem_inc_recv_events_failed);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key->name);
    os_free(key->ip);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_close_idle_sock_2(void** state)
{
    char buffer[OS_MAXSTR + 1] = "!12!AAA";
    message_t message = {.buffer = buffer, .size = 7, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    current_ts = 61;

    logr.connection_overtake_time = 60;

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    os_calloc(1, sizeof(os_ip), key->ip);

    key->id = strdup("001");
    key->sock = 4;
    key->keyid = 1;
    key->rcvd = 0;
    key->ip->ip = "127.0.0.1";
    key->name = strdup("name");

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedDynamicID
    expect_string(__wrap_OS_IsAllowedDynamicID, id, "12");
    expect_string(__wrap_OS_IsAllowedDynamicID, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedDynamicID, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Idle socket [4] from agent ID '001' will be closed.");

    // ReadSecMSG
    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_string(__wrap_ReadSecMSG, buffer, "AAA");
    expect_value(__wrap_ReadSecMSG, id, 1);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, 3);
    will_return(__wrap_ReadSecMSG, "AAA");
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_function_call(__wrap_key_unlock);
    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, key->sock);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, key->sock);
    expect_value(__wrap_nb_close, sock, key->sock);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, 4);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [4]");

    /* enqueue */
    expect_value(__wrap_batch_queue_enqueue_ex, sched, events_queue);
    expect_string(__wrap_batch_queue_enqueue_ex, agent_key, "001");
    expect_any(__wrap_batch_queue_enqueue_ex, data);
    will_return(__wrap_batch_queue_enqueue_ex, -1);
    expect_value(__wrap_time, time, NULL);
    will_return(__wrap_time, 0);
    expect_function_call(__wrap_rem_inc_recv_events_failed);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key->ip);
    os_free(key->name);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_close_idle_sock_disabled(void** state)
{
    char buffer[OS_MAXSTR + 1] = "12!";
    message_t message = {.buffer = buffer, .size = 4, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    current_ts = 61;

    logr.connection_overtake_time = 0;

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("001");
    key->sock = 4;
    key->keyid = 1;
    key->rcvd = 0;
    key->name = strdup("name");

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedDynamicID
    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 1);

    expect_function_call(__wrap_key_unlock);

    expect_string(__wrap__mwarn, formatted_msg, "Agent key already in use: agent ID '001' (source IP: 127.0.0.1)");

    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, message.sock);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, 1);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [1]");

    expect_function_call(__wrap_rem_inc_recv_unknown);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key->name);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_close_idle_sock_disabled_2(void** state)
{
    char buffer[OS_MAXSTR + 1] = "!12!AAA";
    message_t message = {.buffer = buffer, .size = 7, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    current_ts = 61;

    logr.connection_overtake_time = 0;

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("001");
    key->sock = 4;
    key->keyid = 1;
    key->rcvd = 0;
    key->name = strdup("name");

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedDynamicID
    expect_string(__wrap_OS_IsAllowedDynamicID, id, "12");
    expect_string(__wrap_OS_IsAllowedDynamicID, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedDynamicID, 1);

    expect_function_call(__wrap_key_unlock);

    expect_string(__wrap__mwarn, formatted_msg, "Agent key already in use: agent ID '001' (source IP: 127.0.0.1)");

    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, message.sock);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, 1);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [1]");

    expect_function_call(__wrap_rem_inc_recv_unknown);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key->name);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_close_idle_sock_recv_fail(void** state)
{
    char buffer[OS_MAXSTR + 1] = "12!";
    message_t message = {.buffer = buffer, .size = 0, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    current_ts = 61;

    logr.connection_overtake_time = 60;

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    os_calloc(1, sizeof(os_ip), key->ip);

    key->id = strdup("001");
    key->sock = 4;
    key->keyid = 1;
    key->rcvd = 0;
    key->ip->ip = "127.0.0.1";

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedDynamicID
    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Idle socket [4] from agent ID '001' will be closed.");

    expect_string(__wrap__mwarn, formatted_msg, "Received message is empty from '127.0.0.1'");

    expect_function_call(__wrap_key_unlock);

    // Close new socket
    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, message.sock);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, 1);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [1]");

    // Close idle socket
    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, key->sock);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, key->sock);
    expect_value(__wrap_nb_close, sock, key->sock);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, 4);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [4]");

    expect_function_call(__wrap_rem_inc_recv_unknown);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key->ip);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_close_idle_sock_decrypt_fail(void** state)
{
    char buffer[OS_MAXSTR + 1] = "12!";
    message_t message = {.buffer = buffer, .size = 4, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    current_ts = 61;

    logr.connection_overtake_time = 60;

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    os_calloc(1, sizeof(os_ip), key->ip);

    key->id = strdup("001");
    key->sock = 4;
    key->keyid = 1;
    key->rcvd = 0;
    key->ip->ip = "127.0.0.1";

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedDynamicID
    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Idle socket [4] from agent ID '001' will be closed.");

    // ReadSecMSG
    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_string(__wrap_ReadSecMSG, buffer, buffer);
    expect_value(__wrap_ReadSecMSG, id, 1);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, message.size);
    will_return(__wrap_ReadSecMSG, buffer);
    will_return(__wrap_ReadSecMSG, -1);

    expect_function_call(__wrap_key_unlock);

    expect_string(__wrap__mwarn, formatted_msg, "Decrypt the message fail from '127.0.0.1', socket 1");

    // Close new socket
    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, message.sock);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_value(__wrap_nb_close, sock, message.sock);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, 1);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [1]");

    // Close idle socket
    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, key->sock);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, key->sock);
    expect_value(__wrap_nb_close, sock, key->sock);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, 4);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [4]");

    expect_function_call(__wrap_rem_inc_recv_unknown);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key->ip);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_close_idle_sock_control_msg_succes(void** state)
{
    char buffer[OS_MAXSTR + 1] = "#!-12!";
    message_t message = {.buffer = buffer, .size = 6, .sock = 1, .counter = 11};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    current_ts = 61;

    logr.connection_overtake_time = 60;

    agent_meta_t *mocked_meta_ptr = NULL;
    os_calloc(1, sizeof(*mocked_meta_ptr), mocked_meta_ptr);
    mocked_meta_ptr->agent_id = 1;
    mocked_meta_ptr->agent_name = strdup("test-agent");
    mocked_meta_ptr->agent_version = strdup("5.0.0");

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    os_calloc(1, sizeof(os_ip), key->ip);

    key->id = strdup("001");
    key->sock = 4;
    key->keyid = 1;
    key->rcvd = 0;
    key->ip->ip = "127.0.0.1";

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedDynamicID
    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Idle socket [4] from agent ID '001' will be closed.");

    // ReadSecMSG
    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_string(__wrap_ReadSecMSG, buffer, buffer);
    expect_value(__wrap_ReadSecMSG, id, 1);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, message.size);
    will_return(__wrap_ReadSecMSG, buffer);
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_value(__wrap_rem_getCounter, fd, 1);
    will_return(__wrap_rem_getCounter, 10);

    // OS_DupKeyEntry
    expect_value(__wrap_OS_DupKeyEntry, key, key);
    will_return(__wrap_OS_DupKeyEntry, key);

    // OS_AddSocket
    expect_value(__wrap_OS_AddSocket, keys, &keys);
    expect_value(__wrap_OS_AddSocket, i, 1);
    expect_value(__wrap_OS_AddSocket, sock, message.sock);
    will_return(__wrap_OS_AddSocket, OS_ADDSOCKET_KEY_ADDED);

    expect_string(__wrap__mdebug2, formatted_msg, "TCP socket 1 added to keystore.");

    expect_function_call(__wrap_key_unlock);

    // Close idle socket
    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, key->sock);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, key->sock);
    expect_value(__wrap_nb_close, sock, key->sock);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, 4);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [4]");


    expect_function_call(__wrap_rem_inc_recv_ctrl);

    // Should be added to the control message queue
    expect_value(__wrap_validate_control_msg, key, key);
    expect_string(__wrap_validate_control_msg, r_msg, "12!");
    expect_value(__wrap_validate_control_msg, msg_length, 3);
    will_return(__wrap_validate_control_msg, 1);

    /* __wrap_agent_meta_from_agent_info */
    expect_string(__wrap_agent_meta_from_agent_info, id_str, "001");
    expect_any(__wrap_agent_meta_from_agent_info, agent_name);
    expect_any(__wrap_agent_meta_from_agent_info, ai);
    will_return(__wrap_agent_meta_from_agent_info, mocked_meta_ptr);

    /* __wrap_agent_meta_upsert_locked */
    expect_string(__wrap_agent_meta_upsert_locked, agent_id_str, "001");
    expect_value(__wrap_agent_meta_upsert_locked, fresh, mocked_meta_ptr);
    will_return(__wrap_agent_meta_upsert_locked, 0);

    // OS_FreeKey
    expect_value(__wrap_OS_FreeKey, key, key);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    // Expect the control message to be added to the queue
    w_ctrl_msg_data_t * node = indexed_queue_pop(control_msg_queue);
    assert_non_null(node);
    assert_string_equal(node->message, "12!");
    assert_int_equal(node->key->keyid, 1);
    assert_string_equal(node->key->id, "001");
    assert_int_equal(node->key->sock, 1);

    OS_FreeKey(node->key);
    os_free(node->message);
    os_free(node);

    os_free(key->id);
    os_free(key->ip);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
    agent_meta_clear(mocked_meta_ptr);
    agent_meta_free(mocked_meta_ptr);
}

void test_HandleSecureMessage_close_same_sock(void** state)
{
    char buffer[OS_MAXSTR + 1] = "12!";
    message_t message = {.buffer = buffer, .size = 4, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    current_ts = 61;

    logr.connection_overtake_time = 60;

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    os_calloc(1, sizeof(os_ip), key->ip);

    key->id = strdup("001");
    key->sock = 1;
    key->keyid = 1;
    key->rcvd = 0;
    key->ip->ip = "127.0.0.1";
    key->name = strdup("name");

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedDynamicID
    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 1);

    // ReadSecMSG
    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_string(__wrap_ReadSecMSG, buffer, buffer);
    expect_value(__wrap_ReadSecMSG, id, 1);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, message.size);
    will_return(__wrap_ReadSecMSG, buffer);
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_function_call(__wrap_key_unlock);
    expect_string(__wrap__mdebug1, formatted_msg, "Stripped 1 trailing null byte(s) from event payload of agent '001'");

    /* enqueue */
    expect_value(__wrap_batch_queue_enqueue_ex, sched, events_queue);
    expect_string(__wrap_batch_queue_enqueue_ex, agent_key, "001");
    expect_any(__wrap_batch_queue_enqueue_ex, data);
    will_return(__wrap_batch_queue_enqueue_ex, -1);
    expect_value(__wrap_time, time, NULL);
    will_return(__wrap_time, 0);
    expect_function_call(__wrap_rem_inc_recv_events_failed);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key->ip);
    os_free(key->name);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_close_same_sock_2(void** state)
{
    char buffer[OS_MAXSTR + 1] = "!12!AAA";
    message_t message = {.buffer = buffer, .size = 7, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    current_ts = 61;

    logr.connection_overtake_time = 60;

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    os_calloc(1, sizeof(os_ip), key->ip);

    key->id = strdup("001");
    key->sock = 1;
    key->keyid = 1;
    key->rcvd = 0;
    key->ip->ip = "127.0.0.1";
    key->name = strdup("name");

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedDynamicID
    expect_string(__wrap_OS_IsAllowedDynamicID, id, "12");
    expect_string(__wrap_OS_IsAllowedDynamicID, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedDynamicID, 1);

    // ReadSecMSG
    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_string(__wrap_ReadSecMSG, buffer, "AAA");
    expect_value(__wrap_ReadSecMSG, id, 1);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, 4);
    will_return(__wrap_ReadSecMSG, "AAA");
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_function_call(__wrap_key_unlock);
    expect_string(__wrap__mdebug1, formatted_msg, "Stripped 1 trailing null byte(s) from event payload of agent '001'");

    /* enqueue */
    expect_value(__wrap_batch_queue_enqueue_ex, sched, events_queue);
    expect_string(__wrap_batch_queue_enqueue_ex, agent_key, "001");
    expect_any(__wrap_batch_queue_enqueue_ex, data);
    will_return(__wrap_batch_queue_enqueue_ex, -1);
    expect_value(__wrap_time, time, NULL);
    will_return(__wrap_time, 0);
    expect_function_call(__wrap_rem_inc_recv_events_failed);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key->ip);
    os_free(key->name);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

/* legacy_task_process_upgrade_ack() (legacy_task_delivery.c) owns parsing the ack and replying
 * with clear_upgrade_result; discard_legacy_agent_message() only needs to call it and then still let
 * the message fall through to the normal event path. Mocked here so this file only asserts that
 * call happens (with the right agent id and the ack body, header stripped) -- not the reply's
 * wire mechanics, which belong to test_legacy_task_delivery.c. */
bool __wrap_legacy_task_process_upgrade_ack(const char *agent_id, const char *ack_json) {
    check_expected(agent_id);
    check_expected(ack_json);
    return mock_type(bool);
}

/* The agent's upgrade ack must now fall through to the normal event path (like any other
 * agent message) instead of being discarded. Covers all three known ack shapes -- the interception
 * in discard_legacy_agent_message() is header-prefix-only, so all three must behave identically. */
static int check_evt_item_matches_ack(const LargestIntegralType value,
                                      const LargestIntegralType check_value_data) {
    evt_item_t *e = (evt_item_t *)(uintptr_t)value;
    const char *expected = (const char *)(uintptr_t)check_value_data;
    assert_non_null(e);
    assert_non_null(e->raw);
    assert_int_equal(e->len, strlen(expected));
    assert_memory_equal(e->raw, expected, e->len);
    return 1;
}

static void run_upgrade_ack_forwarded_test(const char *ack_json) {
    char buffer[OS_MAXSTR + 1];
    snprintf(buffer, sizeof(buffer), "u:upgrade_module:%s", ack_json);
    message_t message = {.buffer = buffer, .size = strlen(buffer), .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    os_calloc(1, sizeof(os_ip), key->ip);

    key->id = strdup("001");
    key->sock = 1;
    key->keyid = 1;
    key->rcvd = 0;
    key->ip->ip = "127.0.0.1";
    key->name = strdup("test_agent");

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedIP
    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 1);

    // ReadSecMSG
    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_string(__wrap_ReadSecMSG, buffer, buffer);
    expect_value(__wrap_ReadSecMSG, id, 1);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, message.size);
    will_return(__wrap_ReadSecMSG, buffer);
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_function_call(__wrap_key_unlock);

    expect_string(__wrap_legacy_task_process_upgrade_ack, agent_id, "001");
    expect_string(__wrap_legacy_task_process_upgrade_ack, ack_json, ack_json);
    will_return(__wrap_legacy_task_process_upgrade_ack, true);

    expect_string(__wrap__mdebug2, formatted_msg,
                  "Upgrade acknowledgment from agent '001' routed to the normal event path");

    // discard_legacy_agent_message() returns false for this header -> falls through to the
    // ordinary batch_queue_enqueue_ex path, with the exact raw message unmodified.
    expect_value(__wrap_batch_queue_enqueue_ex, sched, events_queue);
    expect_string(__wrap_batch_queue_enqueue_ex, agent_key, "001");
    expect_check(__wrap_batch_queue_enqueue_ex, data, check_evt_item_matches_ack,
                 (LargestIntegralType)(uintptr_t)buffer);
    will_return(__wrap_batch_queue_enqueue_ex, -1);
    expect_value(__wrap_time, time, NULL);
    will_return(__wrap_time, 0);
    expect_function_call(__wrap_rem_inc_recv_events_failed);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key->name);
    os_free(key->ip);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_upgrade_ack_success_forwarded(void** state)
{
    (void) state;
    run_upgrade_ack_forwarded_test(
        "{\"command\":\"upgrade_update_status\",\"parameters\":{\"error\":0,"
        "\"message\":\"Upgrade was successful\",\"status\":\"Done\"}}");
}

void test_HandleSecureMessage_upgrade_ack_missing_dependency_forwarded(void** state)
{
    (void) state;
    run_upgrade_ack_forwarded_test(
        "{\"command\":\"upgrade_update_status\",\"parameters\":{\"error\":1,"
        "\"message\":\"Upgrade failed due missing dependency\",\"status\":\"Failed\"}}");
}

void test_HandleSecureMessage_upgrade_ack_failed_forwarded(void** state)
{
    (void) state;
    run_upgrade_ack_forwarded_test(
        "{\"command\":\"upgrade_update_status\",\"parameters\":{\"error\":2,"
        "\"message\":\"Upgrade failed\",\"status\":\"Failed\"}}");
}

/* Companion test: discard_legacy_agent_message() itself must return false for this header (callers
 * key behavior off the return value), not just "the message happens to end up enqueued". */
void test_discard_legacy_agent_message_upgrade_ack_returns_false(void** state)
{
    (void) state;
    char msg[] = "u:upgrade_module:{\"command\":\"upgrade_update_status\",\"parameters\":"
                 "{\"error\":0,\"message\":\"Upgrade was successful\",\"status\":\"Done\"}}";

    expect_string(__wrap_legacy_task_process_upgrade_ack, agent_id, "001");
    expect_string(__wrap_legacy_task_process_upgrade_ack, ack_json,
                  "{\"command\":\"upgrade_update_status\",\"parameters\":"
                  "{\"error\":0,\"message\":\"Upgrade was successful\",\"status\":\"Done\"}}");
    will_return(__wrap_legacy_task_process_upgrade_ack, true);

    expect_string(__wrap__mdebug2, formatted_msg,
                  "Upgrade acknowledgment from agent '001' routed to the normal event path");

    assert_false(discard_legacy_agent_message(msg, "001"));
}

void test_HandleSecureMessage_event_enqueue_failed(void** state)
{
    char buffer[OS_MAXSTR + 1] = "12!";
    message_t message = {.buffer = buffer, .size = 4, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    current_ts = 61;

    logr.connection_overtake_time = 60;

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    os_calloc(1, sizeof(os_ip), key->ip);

    key->id = strdup("001");
    key->sock = 1;
    key->keyid = 1;
    key->rcvd = 0;
    key->ip->ip = "127.0.0.1";
    key->name = strdup("name");

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedDynamicID
    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 1);

    // ReadSecMSG
    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_string(__wrap_ReadSecMSG, buffer, buffer);
    expect_value(__wrap_ReadSecMSG, id, 1);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, message.size);
    will_return(__wrap_ReadSecMSG, buffer);
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_function_call(__wrap_key_unlock);

    expect_string(__wrap__mdebug1, formatted_msg, "Stripped 1 trailing null byte(s) from event payload of agent '001'");

    /* enqueue failure path: the event is disposed and the failure metric bumped */
    expect_value(__wrap_batch_queue_enqueue_ex, sched, events_queue);
    expect_string(__wrap_batch_queue_enqueue_ex, agent_key, "001");
    expect_any(__wrap_batch_queue_enqueue_ex, data);
    will_return(__wrap_batch_queue_enqueue_ex, -1);
    expect_value(__wrap_time, time, NULL);
    will_return(__wrap_time, 0);
    expect_function_call(__wrap_rem_inc_recv_events_failed);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key->name);
    os_free(key->ip);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_discard_dbsync_message(void** state)
{
    char buffer[OS_MAXSTR + 1] = "5:dbsync_data_from_4x_agent";
    message_t message = {.buffer = buffer, .size = strlen(buffer), .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    os_calloc(1, sizeof(os_ip), key->ip);

    key->id = strdup("001");
    key->sock = 1;
    key->keyid = 1;
    key->rcvd = 0;
    key->ip->ip = "127.0.0.1";
    key->name = strdup("test_agent");

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    // OS_IsAllowedIP
    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 1);

    // ReadSecMSG
    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_string(__wrap_ReadSecMSG, buffer, buffer);
    expect_value(__wrap_ReadSecMSG, id, 1);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, message.size);
    will_return(__wrap_ReadSecMSG, buffer);
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_function_call(__wrap_key_unlock);

    // Expect debug message about discarding DBSYNC message
    expect_string(__wrap__mdebug2, formatted_msg, "Discarding DBSYNC message from 4.x agent '001' (not supported in 5.0)");

    // Message should be discarded

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key->name);
    os_free(key->ip);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

static int check_evt_item_sentinel(const LargestIntegralType value,
                                   const LargestIntegralType check_value_data) {
    (void)check_value_data;
    evt_item_t *e = (evt_item_t *)(uintptr_t)value;
    assert_non_null(e);
    assert_non_null(e->raw);
    assert_int_equal('\0', e->raw[e->len]);
    return 1;
}

/* When batch_queue_enqueue_ex is mocked as successful the production code
 * relinquishes ownership of the evt_item; capture it here so the test can
 * dispose it after HandleSecureMessage returns. */
static evt_item_t *g_captured_evt_item;

static int check_evt_item_capture(const LargestIntegralType value,
                                  const LargestIntegralType check_value_data) {
    (void)check_value_data;
    g_captured_evt_item = (evt_item_t *)(uintptr_t)value;
    assert_non_null(g_captured_evt_item);
    assert_non_null(g_captured_evt_item->raw);
    return 1;
}

void test_HandleSecureMessage_event_without_trailing_null(void** state)
{
    const char *payload = "Apr 23 12:34:56 host dpkg[1]: status installed foo:amd64 1.0.0";
    size_t payload_len = strlen(payload);

    char buffer[OS_MAXSTR + 1];
    memset(buffer, 0xAA, sizeof(buffer));
    memcpy(buffer, payload, payload_len);

    message_t message = {.buffer = buffer, .size = payload_len, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);
    os_calloc(1, sizeof(os_ip), key->ip);

    key->id = strdup("001");
    key->sock = 1;
    key->keyid = 1;
    key->rcvd = 0;
    key->ip->ip = "127.0.0.1";
    key->name = strdup("name");

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 1);

    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_any(__wrap_ReadSecMSG, buffer);
    expect_value(__wrap_ReadSecMSG, id, 1);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, payload_len);
    will_return(__wrap_ReadSecMSG, buffer);
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_function_call(__wrap_key_unlock);

    expect_value(__wrap_batch_queue_enqueue_ex, sched, events_queue);
    expect_string(__wrap_batch_queue_enqueue_ex, agent_key, "001");
    expect_check(__wrap_batch_queue_enqueue_ex, data, check_evt_item_sentinel, NULL);
    will_return(__wrap_batch_queue_enqueue_ex, -1);
    expect_value(__wrap_time, time, NULL);
    will_return(__wrap_time, 0);
    expect_function_call(__wrap_rem_inc_recv_events_failed);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key->name);
    os_free(key->ip);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_HandleSecureMessage_event_enqueue_success(void** state)
{
    const char *payload = "Apr 23 12:34:56 host dpkg[1]: status installed foo:amd64 1.0.0";
    size_t payload_len = strlen(payload);

    char buffer[OS_MAXSTR + 1];
    memset(buffer, 0xAA, sizeof(buffer));
    memcpy(buffer, payload, payload_len);

    message_t message = {.buffer = buffer, .size = payload_len, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);
    os_calloc(1, sizeof(os_ip), key->ip);

    key->id = strdup("001");
    key->sock = 1;
    key->keyid = 1;
    key->rcvd = 0;
    key->ip->ip = "127.0.0.1";
    key->name = strdup("name");

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 1);

    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_any(__wrap_ReadSecMSG, buffer);
    expect_value(__wrap_ReadSecMSG, id, 1);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, payload_len);
    will_return(__wrap_ReadSecMSG, buffer);
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_function_call(__wrap_key_unlock);

    g_captured_evt_item = NULL;
    expect_value(__wrap_batch_queue_enqueue_ex, sched, events_queue);
    expect_string(__wrap_batch_queue_enqueue_ex, agent_key, "001");
    expect_check(__wrap_batch_queue_enqueue_ex, data, check_evt_item_capture, NULL);
    will_return(__wrap_batch_queue_enqueue_ex, 0);
    expect_function_call(__wrap_rem_inc_recv_events);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    /* The mocked queue did not actually take ownership; release the item. */
    if (g_captured_evt_item) {
        dispose_evt_item(g_captured_evt_item);
        g_captured_evt_item = NULL;
    }

    os_free(key->id);
    os_free(key->name);
    os_free(key->ip);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

static int check_evt_item_trimmed(const LargestIntegralType value,
                                  const LargestIntegralType check_value_data) {
    (void)check_value_data;
    evt_item_t *e = (evt_item_t *)(uintptr_t)value;
    assert_non_null(e);
    assert_non_null(e->raw);
    assert_int_equal(62, e->len);
    assert_int_not_equal('\0', e->raw[e->len - 1]);
    assert_int_equal('\0', e->raw[e->len]);
    return 1;
}

void test_HandleSecureMessage_event_with_trailing_null(void** state)
{
    const char *payload = "Apr 23 12:34:56 host dpkg[1]: status installed foo:amd64 1.0.0";
    size_t payload_len = strlen(payload);
    assert_int_equal(62, payload_len);

    char buffer[OS_MAXSTR + 1];
    memset(buffer, 0xAA, sizeof(buffer));
    memcpy(buffer, payload, payload_len);
    buffer[payload_len] = '\0';

    message_t message = {.buffer = buffer, .size = payload_len + 1, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);
    os_calloc(1, sizeof(os_ip), key->ip);

    key->id = strdup("001");
    key->sock = 1;
    key->keyid = 1;
    key->rcvd = 0;
    key->ip->ip = "127.0.0.1";
    key->name = strdup("name");

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 1);

    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_any(__wrap_ReadSecMSG, buffer);
    expect_value(__wrap_ReadSecMSG, id, 1);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, payload_len + 1);
    will_return(__wrap_ReadSecMSG, buffer);
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_function_call(__wrap_key_unlock);

    expect_string(__wrap__mdebug1, formatted_msg,
                  "Stripped 1 trailing null byte(s) from event payload of agent '001'");

    expect_value(__wrap_batch_queue_enqueue_ex, sched, events_queue);
    expect_string(__wrap_batch_queue_enqueue_ex, agent_key, "001");
    expect_check(__wrap_batch_queue_enqueue_ex, data, check_evt_item_trimmed, NULL);
    will_return(__wrap_batch_queue_enqueue_ex, -1);
    expect_value(__wrap_time, time, NULL);
    will_return(__wrap_time, 0);
    expect_function_call(__wrap_rem_inc_recv_events_failed);

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key->name);
    os_free(key->ip);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

// The legacy inventory_sync module retired, `s:`-headed stateful-sync messages are
// DISCARDED (the only stateful ingress is the module's POST /stateful)
void test_HandleSecureMessage_discard_legacy_stateful_sync(void** state)
{
    const char prefix[] = "s:fim:";
    const size_t prefix_len = sizeof(prefix) - 1; /* exclude the C-string NUL */
    const unsigned char legacy_flatbuf[] = {0xAB, 0xCD, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00};

    char buffer[OS_MAXSTR + 1];
    memset(buffer, 0xAA, sizeof(buffer));
    memcpy(buffer, prefix, prefix_len);
    memcpy(buffer + prefix_len, legacy_flatbuf, sizeof(legacy_flatbuf));
    size_t total_len = prefix_len + sizeof(legacy_flatbuf);

    message_t message = {.buffer = buffer, .size = total_len, .sock = 1};
    struct sockaddr_in peer_info;
    w_indexed_queue_t * control_msg_queue = indexed_queue_init(10);
    w_rr_queue_t * events_queue = batch_queue_init(10);
    batch_queue_set_dispose(events_queue, (void (*)(void *))dispose_evt_item);

    keyentry** keyentries;
    os_calloc(2, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry* key = NULL;
    os_calloc(1, sizeof(keyentry), key);
    os_calloc(1, sizeof(os_ip), key->ip);

    key->id = strdup("001");
    key->sock = 1;
    key->keyid = 1;
    key->rcvd = 0;
    key->ip->ip = "127.0.0.1";
    key->name = strdup("name");

    keys.keyentries[1] = key;

    global_counter = 0;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcpy(&message.addr, &peer_info, sizeof(peer_info));

    expect_function_call(__wrap_key_lock_read);

    expect_string(__wrap_OS_IsAllowedIP, srcip, "127.0.0.1");
    will_return(__wrap_OS_IsAllowedIP, 1);

    expect_value(__wrap_ReadSecMSG, keys, &keys);
    expect_any(__wrap_ReadSecMSG, buffer);
    expect_value(__wrap_ReadSecMSG, id, 1);
    expect_string(__wrap_ReadSecMSG, srcip, "127.0.0.1");
    will_return(__wrap_ReadSecMSG, total_len);
    will_return(__wrap_ReadSecMSG, buffer);
    will_return(__wrap_ReadSecMSG, KS_VALID);

    expect_function_call(__wrap_key_unlock);

    expect_string(__wrap__mdebug2,
                  formatted_msg,
                  "Discarding legacy stateful-sync message from agent '001' (since 5.x the manager only accepts "
                  "whole sessions over POST /stateful)");

    HandleSecureMessage(&message, control_msg_queue, events_queue);

    os_free(key->id);
    os_free(key->name);
    os_free(key->ip);
    os_free(key);
    os_free(keyentries);
    indexed_queue_free(control_msg_queue);
    batch_queue_free(events_queue);
}

void test_handle_new_tcp_connection_success(void** state)
{
    struct sockaddr_in peer_info;
    int sock_client = 12;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = 0x0A00A8C0;

    will_return(__wrap_accept, AF_INET);
    will_return(__wrap_accept, sock_client);

    // nb_open
    expect_value(__wrap_nb_open, sock, sock_client);
    expect_value(__wrap_nb_open, peer_info, (struct sockaddr_storage*)&peer_info);
    expect_value(__wrap_nb_open, sock, sock_client);
    expect_value(__wrap_nb_open, peer_info, (struct sockaddr_storage*)&peer_info);

    expect_function_call(__wrap_rem_inc_tcp);

    expect_string(__wrap__mdebug1, formatted_msg, "New TCP connection [12]");

    // wnotify_add
    expect_value(__wrap_wnotify_add, notify, notify);
    expect_value(__wrap_wnotify_add, fd, sock_client);
    expect_value(__wrap_wnotify_add, op, WO_READ);
    will_return(__wrap_wnotify_add, 0);

    handle_new_tcp_connection(notify, (struct sockaddr_storage*)&peer_info);
}

void test_handle_new_tcp_connection_wnotify_fail(void** state)
{
    struct sockaddr_in peer_info;
    int sock_client = 12;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = 0x0A00A8C0;

    will_return(__wrap_accept, AF_INET);
    will_return(__wrap_accept, sock_client);

    // nb_open
    expect_value(__wrap_nb_open, sock, sock_client);
    expect_value(__wrap_nb_open, peer_info, (struct sockaddr_storage*)&peer_info);
    expect_value(__wrap_nb_open, sock, sock_client);
    expect_value(__wrap_nb_open, peer_info, (struct sockaddr_storage*)&peer_info);

    expect_function_call(__wrap_rem_inc_tcp);

    expect_string(__wrap__mdebug1, formatted_msg, "New TCP connection [12]");

    // wnotify_add
    expect_value(__wrap_wnotify_add, notify, notify);
    expect_value(__wrap_wnotify_add, fd, sock_client);
    expect_value(__wrap_wnotify_add, op, WO_READ);
    will_return(__wrap_wnotify_add, -1);

    expect_string(__wrap__merror, formatted_msg, "wnotify_add(0, 12): Success (0)");

    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, sock_client);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, sock_client);
    expect_value(__wrap_nb_close, sock, sock_client);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, sock_client);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [12]");

    handle_new_tcp_connection(notify, (struct sockaddr_storage*)&peer_info);
}

void test_handle_new_tcp_connection_socket_fail(void** state)
{
    struct sockaddr_in peer_info;
    int sock_client = 12;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = 0x0A00A8C0;

    will_return(__wrap_accept, AF_INET);
    will_return(__wrap_accept, -1);
    errno = -1;
    expect_string(__wrap__merror, formatted_msg, "(1242): Couldn't accept TCP connections: Unknown error -1 (-1)");

    handle_new_tcp_connection(notify, (struct sockaddr_storage*)&peer_info);
}

void test_handle_new_tcp_connection_socket_fail_err(void** state)
{
    struct sockaddr_in peer_info;
    int sock_client = 12;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = 0x0A00A8C0;

    will_return(__wrap_accept, AF_INET);
    will_return(__wrap_accept, -1);
    errno = ECONNABORTED;
    expect_string(__wrap__mdebug1,
                  formatted_msg,
                  "(1242): Couldn't accept TCP connections: Software caused connection abort (103)");

    handle_new_tcp_connection(notify, (struct sockaddr_storage*)&peer_info);
}

void test_handle_incoming_data_from_udp_socket_0(void** state)
{
    struct sockaddr_in peer_info;
    logr.udp_sock = 1;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = 0x0A00A8C0;

    will_return(__wrap_recvfrom, 0);

    handle_incoming_data_from_udp_socket((struct sockaddr_storage*)&peer_info);
}

void test_handle_incoming_data_from_udp_socket_success(void** state)
{
    struct sockaddr_in peer_info;
    logr.udp_sock = 1;

    peer_info.sin_family = AF_INET;
    peer_info.sin_addr.s_addr = 0x0A00A8C0;

    will_return(__wrap_recvfrom, 10);

    expect_value(__wrap_rem_msgpush, size, 10);
    expect_value(__wrap_rem_msgpush, addr, (struct sockaddr_storage*)&peer_info);
    expect_value(__wrap_rem_msgpush, sock, USING_UDP_NO_CLIENT_SOCKET);
    will_return(__wrap_rem_msgpush, 0);

    expect_value(__wrap_rem_add_recv, bytes, 10);

    handle_incoming_data_from_udp_socket((struct sockaddr_storage*)&peer_info);
}

void test_handle_incoming_data_from_tcp_socket_too_big_message(void** state)
{
    int sock_client = 8;

    expect_value(__wrap_nb_recv, sock, sock_client);
    will_return(__wrap_nb_recv, -2);

    expect_string(__wrap__mwarn, formatted_msg, "Too big message size from socket [8].");

    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, sock_client);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, sock_client);
    expect_value(__wrap_nb_close, sock, sock_client);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, sock_client);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [8]");

    handle_incoming_data_from_tcp_socket(sock_client);
}

void test_handle_incoming_data_from_tcp_socket_case_0(void** state)
{
    int sock_client = 7;

    expect_value(__wrap_nb_recv, sock, sock_client);
    will_return(__wrap_nb_recv, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "handle incoming close socket [7].");

    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, sock_client);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, sock_client);
    expect_value(__wrap_nb_close, sock, sock_client);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, sock_client);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [7]");

    handle_incoming_data_from_tcp_socket(sock_client);
}

void test_handle_incoming_data_from_tcp_socket_case_1(void** state)
{
    int sock_client = 7;

    expect_value(__wrap_nb_recv, sock, sock_client);
    will_return(__wrap_nb_recv, -1);

    errno = ETIMEDOUT;

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer [7]: Connection timed out (110)");

    expect_string(__wrap__mdebug1, formatted_msg, "handle incoming close socket [7].");

    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, sock_client);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, sock_client);
    expect_value(__wrap_nb_close, sock, sock_client);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, sock_client);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [7]");

    handle_incoming_data_from_tcp_socket(sock_client);
}

void test_handle_incoming_data_from_tcp_socket_success(void** state)
{
    int sock_client = 12;

    expect_value(__wrap_nb_recv, sock, sock_client);
    will_return(__wrap_nb_recv, 100);

    expect_value(__wrap_rem_add_recv, bytes, 100);

    handle_incoming_data_from_tcp_socket(sock_client);
}

void test_handle_outgoing_data_to_tcp_socket_case_1_EAGAIN(void** state)
{
    int sock_client = 10;

    expect_value(__wrap_nb_send, sock, sock_client);
    will_return(__wrap_nb_send, -1);

    errno = EAGAIN;

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer [10]: Resource temporarily unavailable (11)");

    handle_outgoing_data_to_tcp_socket(sock_client);
}

void test_handle_outgoing_data_to_tcp_socket_case_1_EPIPE(void** state)
{
    int sock_client = 10;

    expect_value(__wrap_nb_send, sock, sock_client);
    will_return(__wrap_nb_send, -1);

    errno = EPIPE;

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer [10]: Broken pipe (32)");

    expect_string(__wrap__mdebug1, formatted_msg, "handle outgoing close socket [10].");

    expect_function_call(__wrap_key_lock_read);

    // OS_DeleteSocket
    expect_value(__wrap_OS_DeleteSocket, sock, sock_client);
    will_return(__wrap_OS_DeleteSocket, 0);

    expect_function_call(__wrap_key_unlock);

    will_return(__wrap_close, 0);

    // nb_close
    expect_value(__wrap_nb_close, sock, sock_client);
    expect_value(__wrap_nb_close, sock, sock_client);
    expect_function_call(__wrap_rem_dec_tcp);

    // rem_setCounter
    expect_value(__wrap_rem_setCounter, fd, sock_client);
    expect_value(__wrap_rem_setCounter, counter, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "TCP peer disconnected [10]");

    handle_outgoing_data_to_tcp_socket(sock_client);
}

void test_handle_outgoing_data_to_tcp_socket_success(void** state)
{
    int sock_client = 10;

    expect_value(__wrap_nb_send, sock, sock_client);
    will_return(__wrap_nb_send, 100);

    expect_value(__wrap_rem_add_send, bytes, 100);

    handle_outgoing_data_to_tcp_socket(sock_client);
}

// Tests remoted_module_https_config
//
// getDefine_Int_default() is wrapped as a plain FIFO mock (see
// validate_op_wrappers.c), so these tests only verify that each internal option's
// value lands in the right remoted_module_config_t field, in the fixed call order
// remoted_module_https_config() uses. The "invalid value -> process exits" behavior
// itself lives entirely in the real (unwrapped) getDefine_Int_default()/
// parse_define_int_value() and is not reachable through this mock.

void test_remoted_module_https_config_defaults(void** state)
{
    (void) state;
    remoted_module_config_t rm_config = {0};

    // __wrap_getDefine_Int_default is a plain FIFO mock(), so these MUST stay in the same order
    // as the getDefine_Int_default() calls in remoted_module_https_config(): 13 http_*, then
    // 3 memory-management, then 7 downstream_*, then 3 auth_*. Adding an option there without
    // adding a value here makes the queue run dry and cmocka aborts the test.
    // http_*
    will_return(__wrap_getDefine_Int_default, 0); // http_io_threads (0 = auto, cpp_get_nproc())
    will_return(__wrap_getDefine_Int_default, 0); // http_worker_threads (0 = auto)
    will_return(__wrap_getDefine_Int_default, 10);
    will_return(__wrap_getDefine_Int_default, 10);
    will_return(__wrap_getDefine_Int_default, 30);
    will_return(__wrap_getDefine_Int_default, 2048);
    will_return(__wrap_getDefine_Int_default, 256);
    will_return(__wrap_getDefine_Int_default, 8192);
    will_return(__wrap_getDefine_Int_default, 64);
    will_return(__wrap_getDefine_Int_default, 4);
    will_return(__wrap_getDefine_Int_default, 2);
    will_return(__wrap_getDefine_Int_default, 8192);
    will_return(__wrap_getDefine_Int_default, 65536); // http_stream_chunk_size
    will_return(__wrap_getDefine_Int_default, 1);     // http_content_encoding_enabled (1 = enabled)
    // memory-management
    will_return(__wrap_getDefine_Int_default, 268435456);
    will_return(__wrap_getDefine_Int_default, 512);
    will_return(__wrap_getDefine_Int_default, 256);
    // downstream_*
    will_return(__wrap_getDefine_Int_default, 2);
    will_return(__wrap_getDefine_Int_default, 5);
    will_return(__wrap_getDefine_Int_default, 5);
    will_return(__wrap_getDefine_Int_default, 20); // downstream_stateful_response_timeout
    will_return(__wrap_getDefine_Int_default, 0); // downstream_io_threads (0 = auto)
    will_return(__wrap_getDefine_Int_default, 0); // downstream_post_process_threads (0 = auto)
    will_return(__wrap_getDefine_Int_default, 10485760);
    // auth_*
    will_return(__wrap_getDefine_Int_default, 300);
    will_return(__wrap_getDefine_Int_default, 30);
    will_return(__wrap_getDefine_Int_default, 10485760);

    remoted_module_https_config(&rm_config);

    // port and http_max_body_size are not read here -- they come from
    // wazuh-manager.conf (<remote>), not internal options; untouched means 0.
    assert_int_equal(rm_config.port, 0);
    assert_int_equal(rm_config.io_threads, 0);
    assert_int_equal(rm_config.http_worker_threads, 0);
    assert_int_equal(rm_config.http_max_body_size, 0);
    assert_int_equal(rm_config.http_read_timeout, 10);
    assert_int_equal(rm_config.http_write_timeout, 10);
    assert_int_equal(rm_config.http_request_timeout, 30);
    assert_int_equal(rm_config.http_max_url_size, 2048);
    assert_int_equal(rm_config.http_max_header_name_size, 256);
    assert_int_equal(rm_config.http_max_header_value_size, 8192);
    assert_int_equal(rm_config.http_max_header_count, 64);
    assert_int_equal(rm_config.http_max_pipelined_requests, 4);
    assert_int_equal(rm_config.http_concurrent_accepts, 2);
    assert_int_equal(rm_config.http_buffer_size, 8192);
    assert_int_equal(rm_config.max_inflight_bytes, 268435456);
    assert_int_equal(rm_config.max_parallel_connections, 512);
    assert_int_equal(rm_config.max_deferred_requests, 256);
    assert_int_equal(rm_config.downstream_connect_timeout, 2);
    assert_int_equal(rm_config.downstream_write_timeout, 5);
    assert_int_equal(rm_config.downstream_response_timeout, 5);
    assert_int_equal(rm_config.downstream_stateful_response_timeout, 20);
    assert_int_equal(rm_config.downstream_io_threads, 0);
    assert_int_equal(rm_config.downstream_post_process_threads, 0);
    assert_int_equal(rm_config.downstream_max_response_body_size, 10485760);
    assert_int_equal(rm_config.auth_max_request_age, 300);
    assert_int_equal(rm_config.auth_max_future_skew, 30);
    assert_int_equal(rm_config.auth_max_body_size, 10485760);
    assert_true(rm_config.http_content_encoding_enabled);
}

void test_remoted_module_https_config_custom_values(void** state)
{
    (void) state;
    remoted_module_config_t rm_config = {0};

    // Same FIFO ordering constraint as the defaults test above. Every value is distinct from
    // that option's built-in default, so a field wired to the wrong queue slot shows up as a
    // mismatched assert instead of silently passing.
    // http_*
    will_return(__wrap_getDefine_Int_default, 8);
    will_return(__wrap_getDefine_Int_default, 16);
    will_return(__wrap_getDefine_Int_default, 20);
    will_return(__wrap_getDefine_Int_default, 15);
    will_return(__wrap_getDefine_Int_default, 60);
    will_return(__wrap_getDefine_Int_default, 4096);
    will_return(__wrap_getDefine_Int_default, 512);
    will_return(__wrap_getDefine_Int_default, 16384);
    will_return(__wrap_getDefine_Int_default, 128);
    will_return(__wrap_getDefine_Int_default, 8);
    will_return(__wrap_getDefine_Int_default, 4);
    will_return(__wrap_getDefine_Int_default, 16384);
    will_return(__wrap_getDefine_Int_default, 131072); // http_stream_chunk_size
    will_return(__wrap_getDefine_Int_default, 0);       // http_content_encoding_enabled: 0 = disabled, the
                                                       // opposite of its default, so a field wired to the
                                                       // wrong queue slot fails the assert below
    // memory-management
    will_return(__wrap_getDefine_Int_default, 33554432);
    will_return(__wrap_getDefine_Int_default, 256);
    will_return(__wrap_getDefine_Int_default, 128);
    // downstream_*
    will_return(__wrap_getDefine_Int_default, 7);
    will_return(__wrap_getDefine_Int_default, 11);
    will_return(__wrap_getDefine_Int_default, 13);
    will_return(__wrap_getDefine_Int_default, 45); // downstream_stateful_response_timeout
    will_return(__wrap_getDefine_Int_default, 6);
    will_return(__wrap_getDefine_Int_default, 9);
    will_return(__wrap_getDefine_Int_default, 20971520);
    // auth_*
    will_return(__wrap_getDefine_Int_default, 600);
    will_return(__wrap_getDefine_Int_default, 45);
    will_return(__wrap_getDefine_Int_default, 31457280);

    remoted_module_https_config(&rm_config);

    // port and http_max_body_size are not read here -- they come from
    // wazuh-manager.conf (<remote>), not internal options; untouched means 0.
    assert_int_equal(rm_config.port, 0);
    assert_int_equal(rm_config.io_threads, 8);
    assert_int_equal(rm_config.http_worker_threads, 16);
    assert_int_equal(rm_config.http_max_body_size, 0);
    assert_int_equal(rm_config.http_read_timeout, 20);
    assert_int_equal(rm_config.http_write_timeout, 15);
    assert_int_equal(rm_config.http_request_timeout, 60);
    assert_int_equal(rm_config.http_max_url_size, 4096);
    assert_int_equal(rm_config.http_max_header_name_size, 512);
    assert_int_equal(rm_config.http_max_header_value_size, 16384);
    assert_int_equal(rm_config.http_max_header_count, 128);
    assert_int_equal(rm_config.http_max_pipelined_requests, 8);
    assert_int_equal(rm_config.http_concurrent_accepts, 4);
    assert_int_equal(rm_config.http_buffer_size, 16384);
    assert_int_equal(rm_config.max_inflight_bytes, 33554432);
    assert_int_equal(rm_config.max_parallel_connections, 256);
    assert_int_equal(rm_config.max_deferred_requests, 128);
    assert_int_equal(rm_config.downstream_connect_timeout, 7);
    assert_int_equal(rm_config.downstream_write_timeout, 11);
    assert_int_equal(rm_config.downstream_response_timeout, 13);
    assert_int_equal(rm_config.downstream_stateful_response_timeout, 45);
    assert_int_equal(rm_config.downstream_io_threads, 6);
    assert_int_equal(rm_config.downstream_post_process_threads, 9);
    assert_int_equal(rm_config.downstream_max_response_body_size, 20971520);
    assert_int_equal(rm_config.auth_max_request_age, 600);
    assert_int_equal(rm_config.auth_max_future_skew, 45);
    assert_int_equal(rm_config.auth_max_body_size, 31457280);
    assert_false(rm_config.http_content_encoding_enabled);
}

/* Tests w_remoted_build_module_config */
//
// w_remoted_build_module_config() calls remoted_module_https_config() internally, so
// each test below must queue the same 25 __wrap_getDefine_Int_default return values
// (13 http_*, then 3 memory-management, then 6 downstream_*, then 3 auth_*, in that
// fixed order) as the remoted_module_https_config tests above, even though these
// tests assert on the <https>-driven fields instead.

void test_w_remoted_build_module_config_all_fields_populated(void** state)
{
    (void) state;
    remoted test_logr;
    memset(&test_logr, 0, sizeof(test_logr));
    test_logr.worker_node = true;
    test_logr.https.port = 9443;
    test_logr.https.bind_addr = "0.0.0.0";
    test_logr.https.certificate = "/etc/remoted-https/server.crt";
    test_logr.https.key = "/etc/remoted-https/server.key";
    test_logr.https.ca = "/etc/remoted-https/ca.crt";
    test_logr.https.ciphers = "HIGH:!ADH";
    test_logr.https.verification_mode = REMOTED_HTTPS_VERIFY_CERTIFICATE;
    test_logr.https.max_body_size = 12345;
    test_logr.https.dual_stack = REMOTED_HTTPS_DUAL_STACK_YES;

    // http_*
    will_return(__wrap_getDefine_Int_default, 0);
    will_return(__wrap_getDefine_Int_default, 0);
    will_return(__wrap_getDefine_Int_default, 10);
    will_return(__wrap_getDefine_Int_default, 10);
    will_return(__wrap_getDefine_Int_default, 30);
    will_return(__wrap_getDefine_Int_default, 2048);
    will_return(__wrap_getDefine_Int_default, 256);
    will_return(__wrap_getDefine_Int_default, 8192);
    will_return(__wrap_getDefine_Int_default, 64);
    will_return(__wrap_getDefine_Int_default, 4);
    will_return(__wrap_getDefine_Int_default, 2);
    will_return(__wrap_getDefine_Int_default, 8192);
    will_return(__wrap_getDefine_Int_default, 65536); // http_stream_chunk_size
    will_return(__wrap_getDefine_Int_default, 1);     // http_content_encoding_enabled (1 = enabled)
    // memory-management
    will_return(__wrap_getDefine_Int_default, 268435456);
    will_return(__wrap_getDefine_Int_default, 512);
    will_return(__wrap_getDefine_Int_default, 256);
    // downstream_*
    will_return(__wrap_getDefine_Int_default, 2);
    will_return(__wrap_getDefine_Int_default, 5);
    will_return(__wrap_getDefine_Int_default, 5);
    will_return(__wrap_getDefine_Int_default, 20); // downstream_stateful_response_timeout
    will_return(__wrap_getDefine_Int_default, 0);
    will_return(__wrap_getDefine_Int_default, 0);
    will_return(__wrap_getDefine_Int_default, 10485760);
    // auth_*
    will_return(__wrap_getDefine_Int_default, 300);
    will_return(__wrap_getDefine_Int_default, 30);
    will_return(__wrap_getDefine_Int_default, 10485760);

    remoted_module_config_t rm_config;
    w_remoted_build_module_config(&test_logr, &rm_config);

    assert_int_equal(rm_config.port, 9443);
    assert_true(rm_config.worker_node);
    assert_int_equal(rm_config.verification_mode, REMOTED_HTTPS_VERIFY_CERTIFICATE);
    assert_int_equal(rm_config.http_max_body_size, 12345);
    assert_int_equal(rm_config.dual_stack, REMOTED_HTTPS_DUAL_STACK_YES);
    assert_string_equal(rm_config.bind_address, "0.0.0.0");
    assert_string_equal(rm_config.certificate_path, "/etc/remoted-https/server.crt");
    assert_string_equal(rm_config.private_key_path, "/etc/remoted-https/server.key");
    assert_string_equal(rm_config.ca_path, "/etc/remoted-https/ca.crt");
    assert_string_equal(rm_config.ciphers, "HIGH:!ADH");
    // cluster_name is populated by HandleSecure() itself, not this helper.
    assert_string_equal(rm_config.cluster_name, "");
}

void test_w_remoted_build_module_config_null_https_strings_leave_buffers_empty(void** state)
{
    (void) state;
    remoted test_logr;
    memset(&test_logr, 0, sizeof(test_logr));
    test_logr.https.verification_mode = REMOTED_HTTPS_VERIFY_UNSET;
    // bind_addr/certificate/key/ca/ciphers left NULL, as when <https> is entirely absent.

    will_return(__wrap_getDefine_Int_default, 0);
    will_return(__wrap_getDefine_Int_default, 0);
    will_return(__wrap_getDefine_Int_default, 10);
    will_return(__wrap_getDefine_Int_default, 10);
    will_return(__wrap_getDefine_Int_default, 30);
    will_return(__wrap_getDefine_Int_default, 2048);
    will_return(__wrap_getDefine_Int_default, 256);
    will_return(__wrap_getDefine_Int_default, 8192);
    will_return(__wrap_getDefine_Int_default, 64);
    will_return(__wrap_getDefine_Int_default, 4);
    will_return(__wrap_getDefine_Int_default, 2);
    will_return(__wrap_getDefine_Int_default, 8192);
    will_return(__wrap_getDefine_Int_default, 65536); // http_stream_chunk_size
    will_return(__wrap_getDefine_Int_default, 1);      // http_content_encoding_enabled
    will_return(__wrap_getDefine_Int_default, 268435456);
    will_return(__wrap_getDefine_Int_default, 512);
    will_return(__wrap_getDefine_Int_default, 256);
    will_return(__wrap_getDefine_Int_default, 2);
    will_return(__wrap_getDefine_Int_default, 5);
    will_return(__wrap_getDefine_Int_default, 5);
    will_return(__wrap_getDefine_Int_default, 20); // downstream_stateful_response_timeout
    will_return(__wrap_getDefine_Int_default, 0);
    will_return(__wrap_getDefine_Int_default, 0);
    will_return(__wrap_getDefine_Int_default, 10485760);
    will_return(__wrap_getDefine_Int_default, 300);
    will_return(__wrap_getDefine_Int_default, 30);
    will_return(__wrap_getDefine_Int_default, 10485760);

    remoted_module_config_t rm_config;
    w_remoted_build_module_config(&test_logr, &rm_config);

    assert_int_equal(rm_config.port, 0);
    assert_int_equal(rm_config.verification_mode, REMOTED_HTTPS_VERIFY_UNSET);
    assert_int_equal(rm_config.dual_stack, REMOTED_HTTPS_DUAL_STACK_UNSET);
    assert_string_equal(rm_config.bind_address, "");
    assert_string_equal(rm_config.certificate_path, "");
    assert_string_equal(rm_config.private_key_path, "");
    assert_string_equal(rm_config.ca_path, "");
    assert_string_equal(rm_config.ciphers, "");
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests close_fp_main
        cmocka_unit_test_setup_teardown(test_close_fp_main_queue_empty, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_close_fp_main_first_node_no_close_first, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_close_fp_main_close_first, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_close_fp_main_close_first_queue_2, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_close_fp_main_close_first_queue_2_close_2, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_close_fp_main_close_fp_null, setup_config, teardown_config),
        // Tests HandleSecureMessage
        cmocka_unit_test(test_HandleSecureMessage_invalid_family_address_af_unspec),
        cmocka_unit_test(test_HandleSecureMessage_invalid_family_address_af_netlink),
        cmocka_unit_test(test_HandleSecureMessage_invalid_family_address_af_unix),
        cmocka_unit_test(test_HandleSecureMessage_invalid_family_address_af_x25),
        cmocka_unit_test(test_HandleSecureMessage_invalid_family_address_not_found),
        cmocka_unit_test(test_HandleSecureMessage_invalid_message),
        cmocka_unit_test(test_HandleSecureMessage_shutdown_message),
        cmocka_unit_test(test_HandleSecureMessage_HC_req_message),
        cmocka_unit_test(test_HandleSecureMessage_invalid_HC_req_message),
        cmocka_unit_test(test_HandleSecureMessage_NewMessage_NoShutdownMessage),
        cmocka_unit_test(test_HandleSecureMessage_OldMessage_NoShutdownMessage),
        cmocka_unit_test(test_HandleSecureMessage_different_sock),
        cmocka_unit_test(test_HandleSecureMessage_different_sock_2),
        cmocka_unit_test(test_HandleSecureMessage_conflict_first_seen),
        cmocka_unit_test(test_HandleSecureMessage_conflict_persists),
        cmocka_unit_test(test_HandleSecureMessage_close_idle_sock),
        cmocka_unit_test(test_HandleSecureMessage_close_idle_sock_2),
        cmocka_unit_test(test_HandleSecureMessage_close_idle_sock_disabled),
        cmocka_unit_test(test_HandleSecureMessage_close_idle_sock_disabled_2),
        cmocka_unit_test(test_HandleSecureMessage_close_idle_sock_recv_fail),
        cmocka_unit_test(test_HandleSecureMessage_close_idle_sock_decrypt_fail),
        cmocka_unit_test(test_HandleSecureMessage_close_idle_sock_control_msg_succes),
        cmocka_unit_test(test_HandleSecureMessage_close_same_sock),
        cmocka_unit_test(test_HandleSecureMessage_close_same_sock_2),
        cmocka_unit_test(test_HandleSecureMessage_upgrade_ack_success_forwarded),
        cmocka_unit_test(test_HandleSecureMessage_upgrade_ack_missing_dependency_forwarded),
        cmocka_unit_test(test_HandleSecureMessage_upgrade_ack_failed_forwarded),
        cmocka_unit_test(test_discard_legacy_agent_message_upgrade_ack_returns_false),
        cmocka_unit_test(test_HandleSecureMessage_event_enqueue_failed),
        cmocka_unit_test(test_HandleSecureMessage_discard_dbsync_message),
        cmocka_unit_test(test_HandleSecureMessage_event_without_trailing_null),
        cmocka_unit_test(test_HandleSecureMessage_event_enqueue_success),
        cmocka_unit_test(test_HandleSecureMessage_event_with_trailing_null),
        cmocka_unit_test(test_HandleSecureMessage_discard_legacy_stateful_sync),
        // Tests handle_new_tcp_connection
        cmocka_unit_test_setup_teardown(test_handle_new_tcp_connection_success, setup_new_tcp, teardown_new_tcp),
        cmocka_unit_test_setup_teardown(test_handle_new_tcp_connection_wnotify_fail, setup_new_tcp, teardown_new_tcp),
        cmocka_unit_test_setup_teardown(test_handle_new_tcp_connection_socket_fail, setup_new_tcp, teardown_new_tcp),
        cmocka_unit_test_setup_teardown(
            test_handle_new_tcp_connection_socket_fail_err, setup_new_tcp, teardown_new_tcp),
        // Tests handle_incoming_data_from_udp_socket
        cmocka_unit_test(test_handle_incoming_data_from_udp_socket_0),
        cmocka_unit_test(test_handle_incoming_data_from_udp_socket_success),
        // Tests handle_incoming_data_from_tcp_socket
        cmocka_unit_test(test_handle_incoming_data_from_tcp_socket_too_big_message),
        cmocka_unit_test(test_handle_incoming_data_from_tcp_socket_case_0),
        cmocka_unit_test(test_handle_incoming_data_from_tcp_socket_case_1),
        cmocka_unit_test(test_handle_incoming_data_from_tcp_socket_success),
        // Tests handle_outgoing_data_to_tcp_socket
        cmocka_unit_test(test_handle_outgoing_data_to_tcp_socket_case_1_EAGAIN),
        cmocka_unit_test(test_handle_outgoing_data_to_tcp_socket_case_1_EPIPE),
        cmocka_unit_test(test_handle_outgoing_data_to_tcp_socket_success),
        // Tests remoted_module_https_config
        cmocka_unit_test(test_remoted_module_https_config_defaults),
        cmocka_unit_test(test_remoted_module_https_config_custom_values),
        // Tests w_remoted_build_module_config
        cmocka_unit_test(test_w_remoted_build_module_config_all_fields_populated),
        cmocka_unit_test(test_w_remoted_build_module_config_null_https_strings_leave_buffers_empty)};
    return cmocka_run_group_tests(tests, NULL, NULL);
}
