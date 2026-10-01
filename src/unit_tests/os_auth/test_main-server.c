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

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* main-server.c is compiled with WAZUH_UNIT_TESTING, which turns its file-scope
 * `static` declarations into externally-linkable ones (see auth.c for the same
 * pattern). g_client_pool and sweep_idle_clients() have no header of their own,
 * so they are declared here directly. */
extern struct client * g_client_pool[AUTH_POOL];
extern void sweep_idle_clients(void);

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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_sweep_idle_clients_closes_stale_pre_handshake, teardown_pool),
        cmocka_unit_test_teardown(test_sweep_idle_clients_skips_recent_connection, teardown_pool),
        cmocka_unit_test_teardown(test_sweep_idle_clients_skips_completed_handshake_with_response_queued, teardown_pool),
        cmocka_unit_test_teardown(test_sweep_idle_clients_closes_completed_handshake_with_no_data, teardown_pool),
        cmocka_unit_test_teardown(test_sweep_idle_clients_closes_completed_handshake_with_partial_request, teardown_pool),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
