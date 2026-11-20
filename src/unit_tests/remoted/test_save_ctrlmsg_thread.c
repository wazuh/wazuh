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

#include "../../headers/shared.h"
#include "../../remoted/remoted.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/wazuh/shared/queue_linked_op_wrappers.h"

#include "../wrappers/wazuh/remoted/queue_wrappers.h"
#include "../wrappers/wazuh/remoted/manager_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_global_helpers_wrappers.h"
#include "../../remoted/secure.c"

void * save_control_thread(void * control_msg_queue);

void test_save_control_message_empty(void **state)
{
    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_indexed_queue_pop_ex, (w_linked_queue_t *) 0);
    expect_value(__wrap_indexed_queue_pop_ex, queue, 0x1);


    will_return(__wrap_FOREVER, 0);

    assert_null(save_control_thread((void *) 0x1));
}


void test_save_control_message_ok(void **state)
{
    w_indexed_queue_t * queue = indexed_queue_init(10);
    assert_non_null(queue);

    w_ctrl_msg_data_t * ctrl_msg_data;
    os_calloc(sizeof(w_ctrl_msg_data_t), 1, ctrl_msg_data);
    os_calloc(sizeof(keyentry), 1, ctrl_msg_data->key);

    size_t len = strlen("test message") + 1;
    os_calloc(len, sizeof(char), ctrl_msg_data->message);
    memcpy(ctrl_msg_data->message, "test message", len);

    indexed_queue_push(queue, "001", ctrl_msg_data);

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_indexed_queue_pop_ex, (void *) ctrl_msg_data);
    expect_value(__wrap_indexed_queue_pop_ex, queue, queue);

    expect_value(__wrap_save_controlmsg, key, ctrl_msg_data->key);
    expect_value(__wrap_save_controlmsg, r_msg, ctrl_msg_data->message);
    expect_any(__wrap_save_controlmsg, wdb_sock);

    will_return(__wrap_FOREVER, 0);

    assert_null(save_control_thread((void *) queue));
    indexed_queue_free(queue);    
}

/* Pops a close notice of agent 001, whose keystore entry has the given shutdown flag and whose database row has
 * the given connection status. A NULL sync_status expects no status update. */
static void run_closed_connection(bool worker_node, bool shutdown_received, const char * db_status, const char * sync_status, agent_status_code_t status_code)
{
    keyentry * entry = NULL;
    os_calloc(1, sizeof(keyentry), entry);
    entry->id = "001";
    entry->keyid = 0;
    entry->shutdown_received = shutdown_received;

    keys.keyentries = &entry;
    keys.keysize = 1;
    keys.keytree_id = rbtree_init();
    rbtree_insert(keys.keytree_id, entry->id, entry);

    w_ctrl_msg_data_t * ctrl_msg_data;
    os_calloc(1, sizeof(w_ctrl_msg_data_t), ctrl_msg_data);
    os_calloc(1, sizeof(keyentry), ctrl_msg_data->key);
    ctrl_msg_data->key->id = strdup("001");
    ctrl_msg_data->is_closed = true;

    logr.worker_node = worker_node;

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_indexed_queue_pop_ex, (void *) ctrl_msg_data);
    expect_value(__wrap_indexed_queue_pop_ex, queue, 0x1);

    cJSON * agent_info = cJSON_CreateArray();
    cJSON * row = cJSON_CreateObject();
    cJSON_AddStringToObject(row, "connection_status", db_status);
    cJSON_AddItemToArray(agent_info, row);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, agent_info);

    if (sync_status) {
        expect_value(__wrap_wdb_update_agent_connection_status, id, 1);
        expect_string(__wrap_wdb_update_agent_connection_status, connection_status, AGENT_CS_DISCONNECTED);
        expect_string(__wrap_wdb_update_agent_connection_status, sync_status, sync_status);
        expect_value(__wrap_wdb_update_agent_connection_status, status_code, status_code);
        will_return(__wrap_wdb_update_agent_connection_status, OS_SUCCESS);
    }

    will_return(__wrap_FOREVER, 0);

    assert_null(save_control_thread((void *) 0x1));

    rbtree_destroy(keys.keytree_id);
    keys.keytree_id = NULL;
    keys.keyentries = NULL;
    keys.keysize = 0;
    logr.worker_node = false;
    os_free(entry);
}

void test_save_control_message_connection_closed(void **state)
{
    run_closed_connection(false, false, AGENT_CS_ACTIVE, "synced", CONNECTION_CLOSED);
}

void test_save_control_message_connection_closed_pending(void **state)
{
    run_closed_connection(false, false, AGENT_CS_PENDING, "synced", CONNECTION_CLOSED);
}

// The close of the connection that sent the shutdown keeps the shutdown as the reason, whatever the queue order.
void test_save_control_message_connection_closed_after_shutdown(void **state)
{
    run_closed_connection(false, true, AGENT_CS_ACTIVE, "synced", HC_SHUTDOWN_RECV);
}

void test_save_control_message_connection_closed_worker(void **state)
{
    run_closed_connection(true, false, AGENT_CS_ACTIVE, "syncreq_status", CONNECTION_CLOSED);
}

// An agent rejected on startup (e.g. invalid version) keeps never_connected and its status code.
void test_save_control_message_connection_closed_never_connected(void **state)
{
    run_closed_connection(false, false, AGENT_CS_NEVER_CONNECTED, NULL, CONNECTION_CLOSED);
}

// A row already disconnected keeps its status code and disconnection time.
void test_save_control_message_connection_closed_already_disconnected(void **state)
{
    run_closed_connection(false, false, AGENT_CS_DISCONNECTED, NULL, CONNECTION_CLOSED);
}


int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_save_control_message_empty),
        cmocka_unit_test(test_save_control_message_ok),
        cmocka_unit_test(test_save_control_message_connection_closed),
        cmocka_unit_test(test_save_control_message_connection_closed_after_shutdown),
        cmocka_unit_test(test_save_control_message_connection_closed_worker),
        cmocka_unit_test(test_save_control_message_connection_closed_pending),
        cmocka_unit_test(test_save_control_message_connection_closed_never_connected),
        cmocka_unit_test(test_save_control_message_connection_closed_already_disconnected),
        };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
