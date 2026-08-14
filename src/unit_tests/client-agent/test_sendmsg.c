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

#include "../client-agent/agentd.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/os_crypto/msgs_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"

#define DUMMY_VALID_SOCKET_FD 5

void __wrap_w_agentd_state_update(w_agentd_state_update_t type, void *data) {
    check_expected(type);
}

static agent_server servers[1];
static agent global_config;

static int setup(void **state) {
    memset(&global_config, 0, sizeof(global_config));
    memset(servers, 0, sizeof(servers));
    agt = &global_config;
    agt->server = servers;
    agt->rip_id = 0;
    agt->server[0].protocol = IPPROTO_TCP;
    agt->sock = DUMMY_VALID_SOCKET_FD;
    sender_init();
    errno = 0;
    return 0;
}

static int teardown(void **state) {
    return 0;
}

/* Helper: common expectation chain for a CreateSecMSG call that succeeds */
static void expect_create_sec_msg_ok(void) {
    expect_any(__wrap_CreateSecMSG, msg);
    expect_any(__wrap_CreateSecMSG, msg_length);
    expect_any(__wrap_CreateSecMSG, id);
    will_return(__wrap_CreateSecMSG, 64);  /* size: non-zero -> success */
    will_return(__wrap_CreateSecMSG, "X"); /* msg_encrypted content */
}

static void expect_create_sec_msg_fail(void) {
    expect_any(__wrap_CreateSecMSG, msg);
    expect_any(__wrap_CreateSecMSG, msg_length);
    expect_any(__wrap_CreateSecMSG, id);
    will_return(__wrap_CreateSecMSG, 0);  /* size: zero -> failure */
    will_return(__wrap_CreateSecMSG, ""); /* mock_type(char*) still consumed */
}

/* ── test cases (TCP path) ─────────────────────────────────────────────── */

/* CreateSecMSG fails -> send_msg returns -1 without ever taking send_mutex
 * or touching the socket. */
static void test_send_msg_create_sec_msg_fail(void **state) {
    expect_create_sec_msg_fail();
    expect_any(__wrap__merror, formatted_msg);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, -1);
    assert_int_equal(agt->sock, DUMMY_VALID_SOCKET_FD);
}

/* Socket already invalidated (-1) by another thread: send_mutex is still
 * taken (unlike an ad-hoc check before locking) so the check itself can't
 * race with a concurrent sender, but OS_SendSecureTCP is never reached. */
static void test_send_msg_socket_already_invalid(void **state) {
    agt->sock = -1;
    expect_create_sec_msg_ok();
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, -1);
    assert_int_equal(agt->sock, -1);
}

/* Successful send -> returns 0, state updated, socket stays open. */
static void test_send_msg_success(void **state) {
    expect_create_sec_msg_ok();
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_any(__wrap_OS_SendSecureTCP, sock);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, 0);
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_MSG_SEND);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, 0);
    assert_int_equal(agt->sock, DUMMY_VALID_SOCKET_FD);
}

/* Shared body for the "fatal" errno cases: OS_SendSecureTCP fails, the
 * socket is closed and invalidated, and the failure is logged. */
static void run_fatal_error_case(int err, void (*expect_log)(void)) {
    expect_create_sec_msg_ok();
    expect_function_call(__wrap_pthread_mutex_lock);
    errno = err;
    expect_any(__wrap_OS_SendSecureTCP, sock);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, -1);
    expect_value(__wrap_OS_CloseSocket, sock, DUMMY_VALID_SOCKET_FD);
    will_return(__wrap_OS_CloseSocket, 0);
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_log();
    expect_value(__wrap_sleep, seconds, 1);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, -1);
    assert_int_equal(agt->sock, -1);
}

static void expect_mdebug2_any(void) {
    expect_any(__wrap__mdebug2, formatted_msg);
}

static void expect_mwarn_any(void) {
    expect_any(__wrap__mwarn, formatted_msg);
}

/* EPIPE: manager closed the connection -> socket invalidated */
static void test_send_msg_epipe(void **state) {
    run_fatal_error_case(EPIPE, expect_mdebug2_any);
}

/* ECONNRESET: reset by manager -> socket invalidated */
static void test_send_msg_econnreset(void **state) {
    run_fatal_error_case(ECONNRESET, expect_mdebug2_any);
}

/* ENOTCONN: kernel already tore the connection down -> socket invalidated */
static void test_send_msg_enotconn(void **state) {
    run_fatal_error_case(ENOTCONN, expect_mdebug2_any);
}

/* ECONNREFUSED -> socket invalidated */
static void test_send_msg_econnrefused(void **state) {
    run_fatal_error_case(ECONNREFUSED, expect_mdebug2_any);
}

/* ETIMEDOUT (retransmission exhausted, or SO_SNDTIMEO expiry) -> invalidated */
static void test_send_msg_etimedout(void **state) {
    run_fatal_error_case(ETIMEDOUT, expect_mwarn_any);
}

/* EAGAIN (SO_SNDTIMEO expiry on a blocking socket) -> invalidated.
 * This is the case this whole fix exists for: it turns an indefinitely
 * blocked send() into a bounded, detected failure. */
static void test_send_msg_eagain(void **state) {
    run_fatal_error_case(EAGAIN, expect_mwarn_any);
}

/* Unknown/transient error (e.g. ENOMEM) -> socket must NOT be invalidated:
 * only errors that mean the connection itself is dead should tear it down. */
static void test_send_msg_unknown_error_keeps_socket(void **state) {
    expect_create_sec_msg_ok();
    expect_function_call(__wrap_pthread_mutex_lock);
    errno = ENOMEM;
    expect_any(__wrap_OS_SendSecureTCP, sock);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, -1);
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_any(__wrap__mwarn, formatted_msg);
    expect_value(__wrap_sleep, seconds, 1);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, -1);
    assert_int_equal(agt->sock, DUMMY_VALID_SOCKET_FD); /* socket must NOT be closed */
}

/* ── test cases (UDP path, unaffected by this fix) ────────────────────── */

static void test_send_msg_udp_success(void **state) {
    agt->server[0].protocol = IPPROTO_UDP;
    expect_create_sec_msg_ok();
    expect_any(__wrap_OS_SendUDPbySize, sock);
    expect_any(__wrap_OS_SendUDPbySize, size);
    expect_any(__wrap_OS_SendUDPbySize, msg);
    will_return(__wrap_OS_SendUDPbySize, 0);
    expect_value(__wrap_w_agentd_state_update, type, INCREMENT_MSG_SEND);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, 0);
    /* UDP errors never invalidate agt->sock: there's no dead-socket detection
     * for a connectionless protocol. */
    assert_int_equal(agt->sock, DUMMY_VALID_SOCKET_FD);
}

static void test_send_msg_udp_error_keeps_socket(void **state) {
    agt->server[0].protocol = IPPROTO_UDP;
    expect_create_sec_msg_ok();
    errno = ECONNREFUSED;
    expect_any(__wrap_OS_SendUDPbySize, sock);
    expect_any(__wrap_OS_SendUDPbySize, size);
    expect_any(__wrap_OS_SendUDPbySize, msg);
    will_return(__wrap_OS_SendUDPbySize, -1);
    expect_any(__wrap__mdebug2, formatted_msg);
    expect_value(__wrap_sleep, seconds, 1);

    int ret = send_msg("hello", -1);
    assert_int_equal(ret, -1);
    assert_int_equal(agt->sock, DUMMY_VALID_SOCKET_FD);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_send_msg_create_sec_msg_fail, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_socket_already_invalid, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_success, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_epipe, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_econnreset, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_enotconn, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_econnrefused, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_etimedout, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_eagain, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_unknown_error_keeps_socket, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_udp_success, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_msg_udp_error_keeps_socket, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
