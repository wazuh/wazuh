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

#include "../../client-agent/agentd.h"
#include "../../headers/request_op.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"

static agent_server servers[1];
static agent global_config;

bool req_counter_is_valid(const char * counter);
int req_build_header(const char * counter, char * output, size_t size);

int __wrap_send_msg(const char *msg, __attribute__((unused)) ssize_t msg_length) {
    check_expected(msg);
    return 0;
}

/* Heap copy of a request as the receiver hands it over: "<counter> <target> <payload>",
 * allocated to its exact size so any read past the message is caught by the sanitizer. */
static char *request(const char *text) {
    size_t len = strlen(text) + 1;
    char *buffer = malloc(len);
    memcpy(buffer, text, len);
    return buffer;
}

/* A hexadecimal counter of the given length, followed by " <rest>". */
static char *request_with_counter(size_t length, const char *rest) {
    size_t rest_len = strlen(rest);
    char *buffer = malloc(length + 1 + rest_len + 1);
    for (size_t i = 0; i < length; i++) {
        buffer[i] = "0123456789abcdef"[i % 16];
    }
    buffer[length] = ' ';
    memcpy(buffer + length + 1, rest, rest_len + 1);
    return buffer;
}

// Keeps the socket names req_init() registers, so they stay owned for the whole run.
static OSHash *allowed_sockets_mock;

// Creates the request table once, as wazuh-agentd does at startup.
static int group_setup(void **state) {
    if (setup_hashmap(state) != 0) {
        return -1;
    }
    will_return_count(__wrap_getDefine_Int, 16, 4);
    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);
    expect_string(__wrap_OSHash_Add, key, SOCKET_LOGCOLLECTOR);
    will_return(__wrap_OSHash_Add, 2);
    expect_string(__wrap_OSHash_Add, key, SOCKET_SYSCHECK);
    will_return(__wrap_OSHash_Add, 2);
    expect_string(__wrap_OSHash_Add, key, SOCKET_WMODULES);
    will_return(__wrap_OSHash_Add, 2);
    expect_string(__wrap_OSHash_Add, key, SOCKET_AGENT);
    will_return(__wrap_OSHash_Add, 2);
    req_init();

    allowed_sockets_mock = mock_hashmap;
    mock_hashmap = NULL;
    return 0;
}

static int setup(void **state) {
    (void)state;
    memset(&global_config, 0, sizeof(global_config));
    memset(servers, 0, sizeof(servers));
    agt = &global_config;
    agt->server = servers;
    agt->rip_id = 0;
    agt->server[0].protocol = IPPROTO_TCP;
    test_mode = 0;
    return 0;
}

static int teardown(void **state) {
    (void)state;
    test_mode = 0;
    return 0;
}

/* req_counter_is_valid */

static void test_req_counter_is_valid_accepts_manager_counters(void **state) {
    (void)state;
    assert_true(req_counter_is_valid("0"));
    assert_true(req_counter_is_valid("1a2b3c4d"));
    assert_true(req_counter_is_valid("ffffffff"));
    assert_true(req_counter_is_valid("ABCDEF09"));
}

static void test_req_counter_is_valid_rejects_bad_counters(void **state) {
    (void)state;
    assert_false(req_counter_is_valid(""));
    assert_false(req_counter_is_valid("123456789"));
    assert_false(req_counter_is_valid("1a2b-3c4"));
    assert_false(req_counter_is_valid("0x10"));
    assert_false(req_counter_is_valid("abc g"));
}

/* req_build_header */

static void test_req_build_header_fits(void **state) {
    (void)state;
    char output[REQ_RESPONSE_LENGTH];

    assert_int_equal(req_build_header("1a2b3c4d", output, sizeof(output)), strlen("#!-req 1a2b3c4d "));
    assert_string_equal(output, "#!-req 1a2b3c4d ");
}

static void test_req_build_header_does_not_fit(void **state) {
    (void)state;
    char output[REQ_RESPONSE_LENGTH];
    char counter[REQ_RESPONSE_LENGTH];

    // "#!-req " + 56 characters + " " fills the buffer with no room for the terminator.
    memset(counter, 'a', 56);
    counter[56] = '\0';

    assert_int_equal(req_build_header(counter, output, sizeof(output)), -1);
}

/* req_push */

static void test_req_push_valid_counter(void **state) {
    (void)state;
    char *buffer = request("1a2b3c4d agent getstate");

    // The node reaches the table. A duplicate answer makes req_push() free it itself.
    expect_string(__wrap_OSHash_Add, key, "1a2b3c4d");
    will_return(__wrap_OSHash_Add, 1);
    expect_string(__wrap__mdebug1, formatted_msg, "Duplicated counter. RTO too short?");

    assert_int_equal(req_push(buffer, strlen(buffer)), 0);
    free(buffer);
}


static void test_req_push_counter_too_long(void **state) {
    (void)state;
    char *buffer = request_with_counter(9, "agent getstate");

    expect_string(__wrap__merror, formatted_msg, "Invalid request counter.");

    assert_int_equal(req_push(buffer, strlen(buffer)), -1);
    free(buffer);
}

static void test_req_push_counter_oversized(void **state) {
    (void)state;
    char *buffer = request_with_counter(1000, "agent getstate");

    expect_string(__wrap__merror, formatted_msg, "Invalid request counter.");

    assert_int_equal(req_push(buffer, strlen(buffer)), -1);
    free(buffer);
}

static void test_req_push_counter_not_hex(void **state) {
    (void)state;
    char *buffer = request("1a2b-3c4 agent getstate");

    expect_string(__wrap__merror, formatted_msg, "Invalid request counter.");

    assert_int_equal(req_push(buffer, strlen(buffer)), -1);
    free(buffer);
}

static void test_req_push_counter_empty(void **state) {
    (void)state;
    char *buffer = request(" agent getstate");

    expect_string(__wrap__merror, formatted_msg, "Invalid request counter.");

    assert_int_equal(req_push(buffer, strlen(buffer)), -1);
    free(buffer);
}

static void test_req_push_counter_oversized_udp_no_ack(void **state) {
    (void)state;
    char *buffer = request_with_counter(57, "agent getstate");
    agt->server[0].protocol = IPPROTO_UDP;

    // Rejected before the UDP ack is sent: nothing goes back to the manager.
    expect_string(__wrap__merror, formatted_msg, "Invalid request counter.");

    assert_int_equal(req_push(buffer, strlen(buffer)), -1);
    free(buffer);
}

static void test_req_push_ack_updates_node_with_ack_only(void **state) {
    (void)state;
    char *buffer = request("1a2b3c4d ack");
    req_node_t *node = req_create(-1, "1a2b3c4d", "agent", "getstate", strlen("getstate"));

    test_mode = 1;
    expect_any(__wrap_OSHash_Get, self);
    expect_string(__wrap_OSHash_Get, key, "1a2b3c4d");
    will_return(__wrap_OSHash_Get, node);

    assert_int_equal(req_push(buffer, strlen(buffer)), 0);
    test_mode = 0;

    // The node must hold "ack" and nothing read past the message.
    assert_int_equal(node->length, 3);
    assert_string_equal(node->buffer, "ack");

    req_free(node);
    free(buffer);
}

static void test_req_push_ack_oversized_counter(void **state) {
    (void)state;
    char *buffer = request_with_counter(1000, "ack");

    expect_string(__wrap__merror, formatted_msg, "Invalid request counter.");

    assert_int_equal(req_push(buffer, strlen(buffer)), -1);
    free(buffer);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_req_counter_is_valid_accepts_manager_counters),
        cmocka_unit_test(test_req_counter_is_valid_rejects_bad_counters),
        cmocka_unit_test(test_req_build_header_fits),
        cmocka_unit_test(test_req_build_header_does_not_fit),
        cmocka_unit_test_setup_teardown(test_req_push_valid_counter, setup, teardown),
        cmocka_unit_test_setup_teardown(test_req_push_counter_too_long, setup, teardown),
        cmocka_unit_test_setup_teardown(test_req_push_counter_oversized, setup, teardown),
        cmocka_unit_test_setup_teardown(test_req_push_counter_not_hex, setup, teardown),
        cmocka_unit_test_setup_teardown(test_req_push_counter_empty, setup, teardown),
        cmocka_unit_test_setup_teardown(test_req_push_counter_oversized_udp_no_ack, setup, teardown),
        cmocka_unit_test_setup_teardown(test_req_push_ack_updates_node_with_ack_only, setup, teardown),
        cmocka_unit_test_setup_teardown(test_req_push_ack_oversized_counter, setup, teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, NULL);
}
