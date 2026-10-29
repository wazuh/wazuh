/*
 * Copyright (C) Wazuh Inc.
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
#include "request.c"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* req_dispatch(): a non-JSON message on remote.sock is "<agent id> <payload>", forwarded to a 4.x
 * agent over the legacy channel. Every way it can fail answers the local caller with an `err ...`
 * line; these cases pin the two that used to close the connection with no answer at all. The
 * request table is the real one (req_init()); only the keystore lookup, its lock and the socket
 * write are wrapped. */

#define TEST_PEER -1 /* req_free() closes only a non-negative socket */

void __wrap_key_lock_read(void) { }
void __wrap_key_unlock(void) { }

int __wrap_w_get_agent_net_protocol_from_keystore(__attribute__((unused)) keystore * keys, const char * agent_id) {
    check_expected(agent_id);
    return mock();
}

static req_node_t * add_request(const char * counter, const char * buffer) {
    req_node_t * node = req_create(TEST_PEER, counter, "", buffer, strlen(buffer));

    assert_int_equal(OSHash_Add(req_table, counter, node), 2);
    return node;
}

static int setup_request_table(void ** state) {
    (void) state;
    req_init();
    return 0;
}

static void expect_answer(const char * answer) {
    expect_value(__wrap_OS_SendSecureTCP, sock, TEST_PEER);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(answer));
    expect_string(__wrap_OS_SendSecureTCP, msg, answer);
    will_return(__wrap_OS_SendSecureTCP, 0);
}

void test_req_dispatch_unknown_agent_is_answered(void ** state) {
    (void) state;
    req_node_t * node = add_request("a1", "999 #!-test");

    expect_string(__wrap__mdebug2, formatted_msg, "Running request dispatcher thread. Counter=a1");
    expect_string(__wrap__mdebug2, formatted_msg, "Sending request: '#!-req a1 #!-test'");
    expect_string(__wrap_w_get_agent_net_protocol_from_keystore, agent_id, "999");
    will_return(__wrap_w_get_agent_net_protocol_from_keystore, -1);
    // Debug: the caller is answered with the reason
    expect_string(__wrap__mdebug1, formatted_msg, "(1320): Agent '999' not found.");
    expect_answer("err Agent not found");

    req_dispatch(node);
}

void test_req_dispatch_request_without_agent_id_is_answered(void ** state) {
    (void) state;
    req_node_t * node = add_request("a2", "no-agent-id");

    expect_string(__wrap__mdebug2, formatted_msg, "Running request dispatcher thread. Counter=a2");
    expect_string(__wrap__mdebug1, formatted_msg, "Request has no agent id.");
    expect_answer("err Request has no agent id");

    req_dispatch(node);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_req_dispatch_unknown_agent_is_answered),
        cmocka_unit_test(test_req_dispatch_request_without_agent_id_is_answered),
    };

    return cmocka_run_group_tests(tests, setup_request_table, NULL);
}
