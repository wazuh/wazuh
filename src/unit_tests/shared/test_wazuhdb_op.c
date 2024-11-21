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
#include <string.h>

#include "../../headers/wazuhdb_op.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"

// Tests

void test_ok_query(void **state)
{
    int ret = 0;
    int wdb_sock = -1;
    char *query = "agent 000 syscheck save file 0:0:0:0:0:0:0:0:0:0:0:0:0!0:0 /tmp/test.file";
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
    char *query = "agent 000 syscheck delete /tmp/test.file";
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
    char *query = "agent 000 syscheck scan_info_get start_scan";
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
    char *query = "agent 000";
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

void test_invalid_component(void** state)
{
    char* query = "random_component";

    assert_int_equal(wdbc_validate_component(query), WB_COMP_INVALID);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ok_query),
        cmocka_unit_test(test_ok2_query),
        cmocka_unit_test(test_okmsg_query),
        cmocka_unit_test(test_err_query),
        cmocka_unit_test(test_invalid_component)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
