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
#include <errno.h>

#include "../wrappers/common.h"
#include "../wrappers/wazuh/os_crypto/msgs_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/posix/pthread_wrappers.h"

#include "agentd.h"
#include "state.h"
#include "sendmsg.h"

/* ── globals required by send_msg() ─────────────────────────────────────── */
agent *agt;
keystore keys;

void w_agentd_state_update(w_agentd_state_update_t type, void *data) {
    /* no-op: state tracking is not under test here */
}

/* ── helpers ─────────────────────────────────────────────────────────────── */

static int setup(void **state) {
    test_mode = 1;
    os_calloc(1, sizeof(agent), agt);
    os_calloc(1, sizeof(agent_server), agt->server);
    agt->server[0].port = 1514;
    agt->sock = 5; /* valid fd */
    agt->rip_id = 0;
    sender_init();
    return 0;
}

static int teardown(void **state) {
    test_mode = 0;
    os_free(agt->server);
    os_free(agt);
    return 0;
}

/* Helper: set up the common will_return() chain for CreateSecMSG */
static void expect_create_sec_msg_ok(void) {
    expect_any(__wrap_CreateSecMSG, msg);
    expect_any(__wrap_CreateSecMSG, msg_length);
    expect_any(__wrap_CreateSecMSG, id);
    will_return(__wrap_CreateSecMSG, 64);  /* size: non-zero → success */
    will_return(__wrap_CreateSecMSG, "X"); /* msg_encrypted content */
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
}

static void expect_create_sec_msg_fail(void) {
    expect_any(__wrap_CreateSecMSG, msg);
    expect_any(__wrap_CreateSecMSG, msg_length);
    expect_any(__wrap_CreateSecMSG, id);
    will_return(__wrap_CreateSecMSG, 0);   /* size: zero → failure */
    will_return(__wrap_CreateSecMSG, ""); /* mock_type(char*) still consumed */
}

/* ── test cases ──────────────────────────────────────────────────────────── */

/* CreateSecMSG fails → send_msg returns -1 without touching the socket */
static void test_send_msg_create_sec_msg_fail(void **state) {
    expect_create_sec_msg_fail();
    expect_any(__wrap__merror, formatted_msg);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, -1);
    assert_int_equal(agt->sock, 5); /* socket untouched */
}

/* Socket already invalidated (-1) → early return without calling OS_SendSecureTCP */
static void test_send_msg_socket_already_invalid(void **state) {
    agt->sock = -1;
    expect_create_sec_msg_ok();

    /* OS_SendSecureTCP must NOT be called */
    int ret = send_msg("hello", -1);
    assert_int_equal(ret, -1);
}

/* Successful send → returns 0, socket stays open */
static void test_send_msg_success(void **state) {
    expect_create_sec_msg_ok();
    expect_any(__wrap_OS_SendSecureTCP, sock);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, 0);
    assert_int_equal(agt->sock, 5);
}

/* EPIPE → socket invalidated, mdebug2 emitted */
static void test_send_msg_epipe(void **state) {
    expect_create_sec_msg_ok();
    errno = EPIPE;
    expect_any(__wrap_OS_SendSecureTCP, sock);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, -1);
    expect_value(__wrap_OS_CloseSocket, sock, 5);
    will_return(__wrap_OS_CloseSocket, 0);
    expect_any(__wrap__mdebug2, formatted_msg);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, -1);
    assert_int_equal(agt->sock, -1);
}

/* ECONNRESET → socket invalidated, mdebug2 emitted */
static void test_send_msg_econnreset(void **state) {
    expect_create_sec_msg_ok();
    errno = ECONNRESET;
    expect_any(__wrap_OS_SendSecureTCP, sock);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, -1);
    expect_value(__wrap_OS_CloseSocket, sock, 5);
    will_return(__wrap_OS_CloseSocket, 0);
    expect_any(__wrap__mdebug2, formatted_msg);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, -1);
    assert_int_equal(agt->sock, -1);
}

/* EAGAIN (SO_SNDTIMEO expiry) → socket invalidated, mdebug2 emitted */
static void test_send_msg_eagain(void **state) {
    expect_create_sec_msg_ok();
    errno = EAGAIN;
    expect_any(__wrap_OS_SendSecureTCP, sock);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, -1);
    expect_value(__wrap_OS_CloseSocket, sock, 5);
    will_return(__wrap_OS_CloseSocket, 0);
    expect_any(__wrap__mdebug2, formatted_msg);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, -1);
    assert_int_equal(agt->sock, -1);
}

/* ETIMEDOUT → socket invalidated, mdebug2 emitted */
static void test_send_msg_etimedout(void **state) {
    expect_create_sec_msg_ok();
    errno = ETIMEDOUT;
    expect_any(__wrap_OS_SendSecureTCP, sock);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, -1);
    expect_value(__wrap_OS_CloseSocket, sock, 5);
    will_return(__wrap_OS_CloseSocket, 0);
    expect_any(__wrap__mdebug2, formatted_msg);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, -1);
    assert_int_equal(agt->sock, -1);
}

/* ECONNREFUSED → socket invalidated, mdebug2 emitted */
static void test_send_msg_econnrefused(void **state) {
    expect_create_sec_msg_ok();
    errno = ECONNREFUSED;
    expect_any(__wrap_OS_SendSecureTCP, sock);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, -1);
    expect_value(__wrap_OS_CloseSocket, sock, 5);
    will_return(__wrap_OS_CloseSocket, 0);
    expect_any(__wrap__mdebug2, formatted_msg);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, -1);
    assert_int_equal(agt->sock, -1);
}

/* ENOTCONN → socket invalidated, mdebug2 emitted */
static void test_send_msg_enotconn(void **state) {
    expect_create_sec_msg_ok();
    errno = ENOTCONN;
    expect_any(__wrap_OS_SendSecureTCP, sock);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, -1);
    expect_value(__wrap_OS_CloseSocket, sock, 5);
    will_return(__wrap_OS_CloseSocket, 0);
    expect_any(__wrap__mdebug2, formatted_msg);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, -1);
    assert_int_equal(agt->sock, -1);
}

/* Unknown/transient error (e.g. ENOMEM) → socket NOT invalidated, mwarn emitted */
static void test_send_msg_unknown_error_keeps_socket(void **state) {
    expect_create_sec_msg_ok();
    errno = ENOMEM;
    expect_any(__wrap_OS_SendSecureTCP, sock);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, -1);
    expect_any(__wrap__mwarn, formatted_msg);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, -1);
    assert_int_equal(agt->sock, 5); /* socket must NOT be closed */
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_send_msg_create_sec_msg_fail,        setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_socket_already_invalid,     setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_success,                    setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_epipe,                      setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_econnreset,                 setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_eagain,                     setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_etimedout,                  setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_econnrefused,               setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_enotconn,                   setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_unknown_error_keeps_socket, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
