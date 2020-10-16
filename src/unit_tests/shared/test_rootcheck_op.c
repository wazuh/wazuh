/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "shared.h"

#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"

/* setup/teardown */

/* tests */
void test_rk_get_file_start1(void **state) {
    char *file_str = rk_get_file("File: /file/path.");
    assert_string_equal(file_str, "/file/path");
}

void test_rk_get_file_start2(void **state) {
    char *file_str = rk_get_file("File: /file/path");
    assert_ptr_equal(file_str, NULL);
}

void test_rk_get_file_start3(void **state) {
    char *file_str = rk_get_file("File '/var/lib/docker/tmp/linkfile' is owned by root and has written permissions to anyone.");
    assert_string_equal(file_str, "/var/lib/docker/tmp/linkfile");
}

void test_rk_get_file_start4(void **state) {
    char *file_str = rk_get_file("File '/var/lib/docker/tmp/linkfile is owned by root and has written permissions to anyone.");
    assert_ptr_equal(file_str, NULL);
}

void test_send_rootcheck_bad_query(void **state) {
    char response[OS_SIZE_6144] = {'\0'};
    const char* agent_id = "015";
    long int date = 10552;
    const char* log = "Test query log";
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, "agent 015 rootcheck save 10552 Test query log");
    expect_value(__wrap_wdbc_query_ex, len, OS_SIZE_6144);
    will_return(__wrap_wdbc_query_ex, "error Message");
    will_return(__wrap_wdbc_query_ex, -2);
    expect_string(__wrap__merror, formatted_msg, "Bad load query: 'agent 015 rootcheck save 10552 Test query log'.");
    int ret = send_rootcheck_log(agent_id, date, log, response);
    assert_int_equal(ret, -2);
    assert_string_equal(response, "error Message");
}

void test_send_rootcheck(void **state) {
    char response[OS_SIZE_6144] = {'\0'};
    const char* agent_id = "015";
    long int date = 10552;
    const char* log = "Test query log";
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, "agent 015 rootcheck save 10552 Test query log");
    expect_value(__wrap_wdbc_query_ex, len, OS_SIZE_6144);
    will_return(__wrap_wdbc_query_ex, "ok Message");
    will_return(__wrap_wdbc_query_ex, 0);
    int ret = send_rootcheck_log(agent_id, date, log, response);
    assert_int_equal(ret, 0);
    assert_string_equal(response, "ok Message");
}

/* ***************** */
int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_rk_get_file_start1),
        cmocka_unit_test(test_rk_get_file_start2),
        cmocka_unit_test(test_rk_get_file_start3),
        cmocka_unit_test(test_rk_get_file_start4),
        cmocka_unit_test(test_send_rootcheck_bad_query),
        cmocka_unit_test(test_send_rootcheck),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
