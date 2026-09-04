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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wazuhdb_op.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

// Tests

void test_ok_query(void **state)
{
    int ret = 0;
    int wdb_sock = -1;
    char *query = "agent 001 syscheck save file 0:0:0:0:0:0:0:0:0:0:0:0:0!0:0 /tmp/test.file";
    char response[OS_SIZE_6144];
    char *message;

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 65555);

    expect_value(__wrap_OS_SendSecureTCP, sock, 65555);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(query) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, query);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 65555);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    assert_int_equal(wdbc_query_ex(&wdb_sock, query, response, OS_SIZE_6144), 0);
    assert_int_equal(wdbc_parse_result(response, &message), WDBC_OK);
}

void test_ok2_query(void **state)
{
    int ret = 0;
    int wdb_sock = -1;
    char *query = "agent 001 syscheck delete /tmp/test.file";
    char response[OS_SIZE_6144];
    char *message;

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 65555);

    expect_value(__wrap_OS_SendSecureTCP, sock, 65555);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(query) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, query);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 65555);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    assert_int_equal(wdbc_query_ex(&wdb_sock, query, response, OS_SIZE_6144), 0);
    assert_int_equal(wdbc_parse_result(response, &message), WDBC_OK);
}

void test_okmsg_query(void **state)
{
    int ret = 0;
    int wdb_sock = -1;
    char *query = "agent 001 syscheck scan_info_get start_scan";
    char response[OS_SIZE_6144];
    char *message;

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 65555);

    expect_value(__wrap_OS_SendSecureTCP, sock, 65555);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(query) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, query);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 65555);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    assert_int_equal(wdbc_query_ex(&wdb_sock, query, response, OS_SIZE_6144), 0);
    assert_int_equal(wdbc_parse_result(response, &message), WDBC_OK);
}

void test_err_query(void **state)
{
    int ret = 0;
    int wdb_sock = -1;
    char *query = "agent 001";
    char response[OS_SIZE_6144];
    char *message;

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 65555);

    expect_value(__wrap_OS_SendSecureTCP, sock, 65555);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(query) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, query);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 65555);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "err");
    will_return(__wrap_OS_RecvSecureTCP, 3);

    assert_int_equal(wdbc_query_ex(&wdb_sock, query, response, OS_SIZE_6144), 0);
    assert_int_equal(wdbc_parse_result(response, &message), WDBC_ERROR);
}

void test_query_ex_timeout_bounds_the_socket(void **state)
{
    int ret = 0;
    int wdb_sock = -1;
    char *query = "global sql SELECT 1;";
    char response[OS_SIZE_6144];

    // One connect attempt, not wdbc_connect()'s ladder of five with 1, 2, 3, 4 and 5 second
    // sleeps between them: a caller that asked for a deadline has its own retry schedule.
    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 65555);

    will_return(__wrap_OS_SetSendTimeout, 0);
    will_return(__wrap_OS_SetRecvTimeout, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, 65555);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(query) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, query);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 65555);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok {}");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    ret = wdbc_query_ex_timeout(&wdb_sock, query, response, OS_SIZE_6144, 10);

    assert_int_equal(0, ret);
    assert_string_equal("ok {}", response);
}

void test_query_ex_timeout_fails_when_deadline_cannot_be_set(void **state)
{
    int ret = 0;
    int wdb_sock = -1;
    char *query = "global sql SELECT 1;";
    char response[OS_SIZE_6144];

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 65555);

    will_return(__wrap_OS_SetSendTimeout, -1);

    // The first message embeds strerror(errno), which the wrapped setsockopt leaves untouched, so
    // only its emission is asserted.
    expect_any(__wrap__merror, formatted_msg);
    expect_string(__wrap__merror, formatted_msg, "Unable to connect to socket 'queue/sockets/wdb.sock'.");

    // The socket is closed and the call fails rather than proceeding unbounded: silently falling
    // back to no deadline is the one outcome a caller asking for one cannot detect.
    ret = wdbc_query_ex_timeout(&wdb_sock, query, response, OS_SIZE_6144, 10);

    assert_int_equal(-2, ret);
    assert_int_equal(-1, wdb_sock);
}

void test_query_ex_zero_timeout_keeps_the_unbounded_path(void **state)
{
    int ret = 0;
    int wdb_sock = -1;
    char *query = "agent 001 syscheck save file";
    char response[OS_SIZE_6144];

    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 65555);

    expect_value(__wrap_OS_SendSecureTCP, sock, 65555);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(query) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, query);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 65555);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok");
    will_return(__wrap_OS_RecvSecureTCP, 2);

    // No OS_SetSendTimeout or OS_SetRecvTimeout is queued. Every existing caller reaches this
    // path through wdbc_query_ex(), and imposing a deadline on them would touch every daemon in
    // the tree, syscollector's long-running sync queries included.
    ret = wdbc_query_ex_timeout(&wdb_sock, query, response, OS_SIZE_6144, 0);

    assert_int_equal(0, ret);
}

/**
 * @brief One reconnect-and-retry cycle: connect, send, the reply is lost, reconnect, send again.
 *
 * @param reset_errno How the lost connection is reported -- ECONNRESET or EPIPE, which differ only
 *                    in whether wazuh-db had unread data queued when it closed.
 */
static void expect_lost_connection_retry(const char *query, int reset_errno)
{
    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 65555);
    will_return(__wrap_OS_SetSendTimeout, 0);
    will_return(__wrap_OS_SetRecvTimeout, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, 65555);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(query) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, query);
    will_return(__wrap_OS_SendSecureTCP, 0);

    // The send landed; the answer never came, which is what a peer closing mid-reply looks like.
    expect_value(__wrap_OS_RecvSecureTCP, sock, 65555);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "");
    will_return(__wrap_OS_RecvSecureTCP, -1);
    expect_any(__wrap__merror, formatted_msg); // cannot receive: the reset itself
    expect_string(__wrap__merror, formatted_msg, "Connection with wazuh-manager-db lost. Reconnecting.");

    // The second attempt, on a fresh socket. One attempt, not wdbc_connect()'s sleeping ladder,
    // because this caller asked for a deadline.
    expect_string(__wrap_OS_ConnectUnixDomain, path, WDB_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_SIZE_6144);
    will_return(__wrap_OS_ConnectUnixDomain, 65556);
    will_return(__wrap_OS_SetSendTimeout, 0);
    will_return(__wrap_OS_SetRecvTimeout, 0);

    expect_value(__wrap_OS_SendSecureTCP, sock, 65556);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(query) + 1);
    expect_string(__wrap_OS_SendSecureTCP, msg, query);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 65556);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_SIZE_6144);
    will_return(__wrap_OS_RecvSecureTCP, "ok {}");
    will_return(__wrap_OS_RecvSecureTCP, 5);

    // Last, so nothing between here and the call can overwrite it: the branch under test is
    // selected by the errno wdbc_query() leaves behind, and the wrapped socket calls do not set it.
    errno = reset_errno;
}

void test_query_ex_retries_once_after_a_connection_reset(void **state)
{
    int wdb_sock = -1;
    char *query = "global sql SELECT 1;";
    char response[OS_SIZE_6144];

    // ECONNRESET, not EPIPE: a wazuh-db that closed with a queued query unread reports this one,
    // and it used to fall into the catch-all and fail the query outright -- on exactly the path
    // this reconnect exists for.
    expect_lost_connection_retry(query, ECONNRESET);

    assert_int_equal(0, wdbc_query_ex_timeout(&wdb_sock, query, response, OS_SIZE_6144, 10));
    assert_string_equal("ok {}", response);
    assert_int_equal(65556, wdb_sock);
}

void test_query_ex_retries_once_after_a_broken_pipe(void **state)
{
    int wdb_sock = -1;
    char *query = "global sql SELECT 1;";
    char response[OS_SIZE_6144];

    // The sibling errno, pinned alongside it so the two cannot drift apart again.
    expect_lost_connection_retry(query, EPIPE);

    assert_int_equal(0, wdbc_query_ex_timeout(&wdb_sock, query, response, OS_SIZE_6144, 10));
    assert_string_equal("ok {}", response);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ok_query),
        cmocka_unit_test(test_ok2_query),
        cmocka_unit_test(test_okmsg_query),
        cmocka_unit_test(test_err_query),
        cmocka_unit_test(test_query_ex_timeout_bounds_the_socket),
        cmocka_unit_test(test_query_ex_timeout_fails_when_deadline_cannot_be_set),
        cmocka_unit_test(test_query_ex_retries_once_after_a_connection_reset),
        cmocka_unit_test(test_query_ex_retries_once_after_a_broken_pipe),
        cmocka_unit_test(test_query_ex_zero_timeout_keeps_the_unbounded_path),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
