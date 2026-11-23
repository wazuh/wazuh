/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

/* Every header main.c includes, first: they are guarded, so the names redirected below are
 * replaced in main.c's own code only, never in a declaration. */
#include "wazuhdb_op.h"
#include "wdb_state.h"
#include "http/wdb_http.h"
#include "os_net.h"
#include "config.h"
#include "wazuh_db-config.h"
#include "mconf-config.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#define LISTEN_FD 5
#define MAX_RECORDED 8

static int test_bind(const char * path, int type, int max_msg_size);
static int test_select(int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, struct timeval * timeout);
static int test_accept(int fd, struct sockaddr * addr, socklen_t * addr_len);
static int test_wnotify_add(wnotify_t * notify, int fd, const woperation_t op);
static int test_close(int fd);
static int test_unlink(const char * path);
/* The HTTP listener is C++ (wdb_http.cpp) and would pull uds_http_server into this C test. */
static void test_http_start(full_log_fnc_t callback_log, const char * socket_path);
static void test_http_stop(void);

#undef select
/* The daemon's name comes from its CMake target (-DARGV0), which this test does not build. */
#ifndef ARGV0
#define ARGV0 "wazuh-manager-db"
#endif

#define OS_BindUnixDomain test_bind
#define select test_select
#define accept test_accept
#define wnotify_add test_wnotify_add
#define close test_close
#define unlink test_unlink
#define wdb_http_start test_http_start
#define wdb_http_stop test_http_stop
#define main wazuh_db_main
#include "../../wazuh_db/src/main.c"
#undef main
#undef wdb_http_stop
#undef wdb_http_start
#undef unlink
#undef close
#undef wnotify_add
#undef accept
#undef select
#undef OS_BindUnixDomain

/* What the dealer did, recorded by the fakes. */
static int select_calls;
static int accept_calls;
static int added_fds[MAX_RECORDED];
static int added_count;
static int closed_fds[MAX_RECORDED];
static int closed_count;
static int unlink_calls;

static void test_http_start(__attribute__((unused)) full_log_fnc_t callback_log,
                            __attribute__((unused)) const char * socket_path) {}

static void test_http_stop(void) {}

static int test_bind(const char * path, int type, __attribute__((unused)) int max_msg_size) {
    assert_string_equal(path, WDB_LOCAL_SOCK);
    assert_int_equal(type, SOCK_STREAM);
    return LISTEN_FD;
}

/* Two peers arrive, then the daemon is told to stop. */
static int test_select(__attribute__((unused)) int nfds, __attribute__((unused)) fd_set * readfds,
                       __attribute__((unused)) fd_set * writefds, __attribute__((unused)) fd_set * exceptfds,
                       __attribute__((unused)) struct timeval * timeout) {
    if (++select_calls > 2) {
        running = 0;
        return 0;
    }

    return 1;
}

/* Peers 7 and 8. */
static int test_accept(int fd, __attribute__((unused)) struct sockaddr * addr, __attribute__((unused)) socklen_t * addr_len) {
    assert_int_equal(fd, LISTEN_FD);
    return 6 + ++accept_calls;
}

/* The first peer cannot be queued; the second one can. */
static int test_wnotify_add(__attribute__((unused)) wnotify_t * notify, int fd, const woperation_t op) {
    assert_int_equal(op, WO_READ);
    assert_true(added_count < MAX_RECORDED);
    added_fds[added_count++] = fd;

    if (added_count == 1) {
        errno = ENOMEM;
        return -1;
    }

    return 0;
}

static int test_close(int fd) {
    assert_true(closed_count < MAX_RECORDED);
    closed_fds[closed_count++] = fd;
    return 0;
}

static int test_unlink(const char * path) {
    assert_string_equal(path, WDB_LOCAL_SOCK);
    unlink_calls++;
    return 0;
}

static int setup(__attribute__((unused)) void ** state) {
    running = 1;
    select_calls = accept_calls = added_count = closed_count = unlink_calls = 0;
    return 0;
}

/* A peer that cannot be added to the notify queue is dropped on its own: the dealer closes it, keeps
 * listening and serves the next peer. The socket is closed and unlinked only when the daemon stops. */
static void test_run_dealer_drops_only_the_peer_it_cannot_queue(__attribute__((unused)) void ** state) {
    expect_string(__wrap__merror, formatted_msg, "at run_dealer(): wnotify_add(7): Cannot allocate memory (12)");
    expect_string(__wrap__mdebug1, formatted_msg, "New client connected (8).");

    assert_null(run_dealer(NULL));

    // Both peers were accepted and offered to the queue: the failure did not end the loop.
    assert_int_equal(accept_calls, 2);
    assert_int_equal(added_count, 2);
    assert_int_equal(added_fds[0], 7);
    assert_int_equal(added_fds[1], 8);

    // The loop ran until it was told to stop.
    assert_int_equal(select_calls, 3);

    // Only the refused peer was closed while running; the listening socket goes last, at stop.
    assert_int_equal(closed_count, 2);
    assert_int_equal(closed_fds[0], 7);
    assert_int_equal(closed_fds[1], LISTEN_FD);
    assert_int_equal(unlink_calls, 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_run_dealer_drops_only_the_peer_it_cannot_queue, setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
