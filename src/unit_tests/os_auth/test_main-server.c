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

#include "shared.h"
#include "../../os_auth/auth.h"
#include "../../addagent/manage_agents.h"
#include "../../headers/sec.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"

/* main-server.c is compiled with WAZUH_UNIT_TESTING, which turns its file-scope
 * `static` declarations into externally-linkable ones (see auth.c for the same
 * pattern). g_client_pool, sweep_idle_clients() and enqueue_pending_key() have no
 * header of their own, so they are declared here directly. */
extern struct client * g_client_pool[AUTH_POOL];
extern void sweep_idle_clients(void);
extern void enqueue_pending_key(int ret, uint32_t index_client);

/* Same minimal reimplementation of keys_init() as test_auth_add.c: it's a
 * file-local helper in auth.c with no header, so every test file that needs a
 * real keystore copies it. */
void keys_init(keystore *keys, key_mode_t key_mode, int save_removed) {
    keys->keytree_id = rbtree_init();
    keys->keytree_ip = rbtree_init();
    keys->keytree_sock = rbtree_init();

    if (!(keys->keytree_id && keys->keytree_ip && keys->keytree_sock)) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    os_calloc(1, sizeof(keyentry*), keys->keyentries);
    keys->keysize = 0;
    keys->id_counter = 0;
    keys->flags.key_mode = key_mode;
    keys->flags.save_removed = save_removed;

    os_calloc(1, sizeof(keyentry), keys->keyentries[keys->keysize]);
    w_mutex_init(&keys->keyentries[keys->keysize]->mutex, NULL);
}

extern struct keynode *queue_insert;
extern struct keynode * volatile *insert_tail;

#define TEST_SLOT 1

time_t __wrap_w_get_monotonic_time(void) {
    return mock_type(time_t);
}

static struct client * make_client(bool handshake_done, time_t connected_at, int read_offset, int write_len) {
    struct client * client;

    os_calloc(1, sizeof(struct client), client);
    client->socket = -1;
    client->index = TEST_SLOT;
    client->is_ipv6 = FALSE;
    client->addr4 = NULL;
    client->ssl = NULL;
    client->handshake_done = handshake_done;
    client->connected_at = connected_at;
    client->read_offset = read_offset;
    client->write_len = write_len;
    strncpy(client->ip, "127.0.0.1", IPSIZE);
    client->read_buffer = NULL;
    client->write_buffer = NULL;
    client->agentname = NULL;
    client->centralized_group = NULL;
    client->new_id = NULL;

    return client;
}

static int teardown_pool(void ** state) {
    for (int i = 1; i < AUTH_POOL; i++) {
        if (g_client_pool[i]) {
            os_free(g_client_pool[i]);
            g_client_pool[i] = NULL;
        }
    }
    return 0;
}

/* setup/teardown for enqueue_pending_key(): a real keystore with two agents
 * (agent-a added first, agent-b second, so agent-a is never the last entry),
 * and a pool client standing in for agent-a's connection. */
static int setup_pending_key(void ** state) {
    config.worker_node = FALSE;

    keys_init(&keys, W_RAW_KEY, 0);

    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);
    OS_AddNewAgent(&keys, NULL, "agent-a", "10.0.0.1", NULL);

    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);
    OS_AddNewAgent(&keys, NULL, "agent-b", "10.0.0.2", NULL);

    insert_tail = &queue_insert;

    g_client_pool[TEST_SLOT] = make_client(TRUE, 0, 0, 0);
    g_client_pool[TEST_SLOT]->enrollment_ok = true;
    os_strdup("agent-a", g_client_pool[TEST_SLOT]->agentname);
    os_strdup(keys.keyentries[0]->id, g_client_pool[TEST_SLOT]->new_id);

    return 0;
}

static int teardown_pending_key(void ** state) {
    teardown_pool(state);

    struct keynode *cur, *next;
    for (cur = queue_insert; cur; cur = next) {
        next = cur->next;
        os_free(cur->id);
        os_free(cur->name);
        os_free(cur->ip);
        os_free(cur->raw_key);
        os_free(cur->group);
        os_free(cur);
    }
    queue_insert = NULL;

    OS_FreeKeys(&keys);

    return 0;
}

/* tests */

static void test_sweep_idle_clients_closes_stale_pre_handshake(void ** state) {
    g_client_pool[TEST_SLOT] = make_client(FALSE, 1000, 0, 0);

    will_return(__wrap_w_get_monotonic_time, 1000 + AUTH_IDLE_CONN_TIMEOUT);
    expect_string(__wrap__mdebug2, formatted_msg,
                  "Closing idle enrolment connection from 127.0.0.1 (slot 1)");

    sweep_idle_clients();

    assert_null(g_client_pool[TEST_SLOT]);
}

static void test_sweep_idle_clients_skips_recent_connection(void ** state) {
    g_client_pool[TEST_SLOT] = make_client(FALSE, 1000, 0, 0);

    will_return(__wrap_w_get_monotonic_time, 1000 + AUTH_IDLE_CONN_TIMEOUT - 1);

    sweep_idle_clients();

    assert_non_null(g_client_pool[TEST_SLOT]);
    assert_false(g_client_pool[TEST_SLOT]->handshake_done);
}

static void test_sweep_idle_clients_skips_completed_handshake_with_response_queued(void ** state) {
    g_client_pool[TEST_SLOT] = make_client(TRUE, 1000, 1, 42);

    will_return(__wrap_w_get_monotonic_time, 1000 + AUTH_IDLE_CONN_TIMEOUT + 1000);

    sweep_idle_clients();

    assert_non_null(g_client_pool[TEST_SLOT]);
    assert_true(g_client_pool[TEST_SLOT]->handshake_done);
}

static void test_sweep_idle_clients_closes_completed_handshake_with_no_data(void ** state) {
    g_client_pool[TEST_SLOT] = make_client(TRUE, 1000, 0, 0);

    will_return(__wrap_w_get_monotonic_time, 1000 + AUTH_IDLE_CONN_TIMEOUT);
    expect_string(__wrap__mdebug2, formatted_msg,
                  "Closing idle enrolment connection from 127.0.0.1 (slot 1)");

    sweep_idle_clients();

    assert_null(g_client_pool[TEST_SLOT]);
}

static void test_sweep_idle_clients_closes_completed_handshake_with_partial_request(void ** state) {
    /* Handshake finished and a byte arrived, but no '\n' yet: process_message() never ran,
     * so write_len is still 0. This is the case that used to stay exempt forever. */
    g_client_pool[TEST_SLOT] = make_client(TRUE, 1000, 1, 0);

    will_return(__wrap_w_get_monotonic_time, 1000 + AUTH_IDLE_CONN_TIMEOUT);
    expect_string(__wrap__mdebug2, formatted_msg,
                  "Closing idle enrolment connection from 127.0.0.1 (slot 1)");

    sweep_idle_clients();

    assert_null(g_client_pool[TEST_SLOT]);
}

/* Backport of PR #39651 (authd key-indexing fix, Jota's blocking review S3): both cases
 * fit the 4.14.9 scaffolding above without new wrappers, and both fail with the old
 * `keys.keyentries[keys.keysize - 1]` indexing because agent-a is never the last entry. */

static void test_enqueue_pending_key_inserts_own_key(void ** state) {
    enqueue_pending_key(1, TEST_SLOT);

    assert_non_null(queue_insert);
    assert_string_equal(queue_insert->name, "agent-a");
    assert_null(g_client_pool[TEST_SLOT]);
}

static void test_enqueue_pending_key_rollback_keeps_other_key(void ** state) {
    expect_string(__wrap__merror, formatted_msg, "SSL write error (-1)");
    expect_string(__wrap__merror, formatted_msg, "Agent key not saved for agent-a");

    enqueue_pending_key(-1, TEST_SLOT);

    assert_int_equal(keys.keysize, 1);
    assert_string_equal(keys.keyentries[0]->name, "agent-b");
    assert_null(g_client_pool[TEST_SLOT]);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_sweep_idle_clients_closes_stale_pre_handshake, teardown_pool),
        cmocka_unit_test_teardown(test_sweep_idle_clients_skips_recent_connection, teardown_pool),
        cmocka_unit_test_teardown(test_sweep_idle_clients_skips_completed_handshake_with_response_queued, teardown_pool),
        cmocka_unit_test_teardown(test_sweep_idle_clients_closes_completed_handshake_with_no_data, teardown_pool),
        cmocka_unit_test_teardown(test_sweep_idle_clients_closes_completed_handshake_with_partial_request, teardown_pool),
        cmocka_unit_test_setup_teardown(test_enqueue_pending_key_inserts_own_key, setup_pending_key, teardown_pending_key),
        cmocka_unit_test_setup_teardown(test_enqueue_pending_key_rollback_keeps_other_key, setup_pending_key, teardown_pending_key),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
