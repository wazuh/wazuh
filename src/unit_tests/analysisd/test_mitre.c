/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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

#include "../analysisd/mitre.h"

/* redefinitons/wrapping */

int __wrap_wdbc_query_ex(int *sock, const char *query, char *response, const int len)
{   
    int option;

    option = mock_type(int);
    if (option == 0) {
        snprintf(response, len, "%s", mock_ptr_type(char*));
    } else {
        response = NULL;
    }

    return mock();
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

/* tests */

void test_queryid_error_socket(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_wdbc_query_ex, -2);
    will_return(__wrap_wdbc_query_ex, -2);
    expect_string(__wrap__merror, formatted_msg, "Unable to connect to socket '/queue/db/wdb'");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-2, ret);
}

void test_queryid_no_response(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_wdbc_query_ex, -1);
    will_return(__wrap_wdbc_query_ex, -1);
    expect_string(__wrap__merror, formatted_msg, "No response or bad response from wazuh-db: ''");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_queryid_bad_response(void **state)
{
    (void) state;
    int ret;

    char *response_ids = "Bad response";
    will_return(__wrap_wdbc_query_ex, 0);
    will_return(__wrap_wdbc_query_ex, response_ids);
    will_return(__wrap_wdbc_query_ex, -1);

    expect_string(__wrap__merror, formatted_msg, "No response or bad response from wazuh-db: 'Bad response'");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_queryid_error_parse(void **state)
{
    (void) state;
    int ret;

    char *response_ids = " ";
    will_return(__wrap_wdbc_query_ex, 0);    
    will_return(__wrap_wdbc_query_ex, response_ids);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed: ' '");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_queryid_empty_array(void **state)
{
    (void) state;
    int ret;

    char *response_ids = "ok []";
    will_return(__wrap_wdbc_query_ex, 0);    
    will_return(__wrap_wdbc_query_ex, response_ids);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database has 0 elements.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_queryid_error_parse_ids(void **state)
{
    (void) state;
    int ret;

    char *response_ids = "ok [{\"ids\":\"T1001\"},{\"ids\":\"T1002\"}]";
    will_return(__wrap_wdbc_query_ex, 0);    
    will_return(__wrap_wdbc_query_ex, response_ids);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap__merror, formatted_msg, "It was not possible to get Mitre techniques information.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_querytactics_error_socket(void **state)
{
    (void) state;
    int ret;

    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1002\"}]";

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_ex, 0);    
    will_return(__wrap_wdbc_query_ex, response_ids);
    will_return(__wrap_wdbc_query_ex, 0);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_ex, -2);
    will_return(__wrap_wdbc_query_ex, -2);

    expect_string(__wrap__merror, formatted_msg, "Unable to connect to socket '/queue/db/wdb'");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-2, ret);
}

void test_querytactics_no_response(void **state)
{
    (void) state;
    int ret;

    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1002\"}]";
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_ex, 0);    
    will_return(__wrap_wdbc_query_ex, response_ids);
    will_return(__wrap_wdbc_query_ex, 0);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_ex, -1);
    will_return(__wrap_wdbc_query_ex, -1);

    expect_string(__wrap__merror, formatted_msg, "No response or bad response from wazuh-db: 'ok [{\"id\":\"T1001\"},{\"id\":\"T1002\"}]'");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_querytactics_bad_response(void **state)
{
    (void) state;
    int ret;

    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1002\"}]";
    char *response_tactics = "Bad response";
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_ex, 0);    
    will_return(__wrap_wdbc_query_ex, response_ids);
    will_return(__wrap_wdbc_query_ex, 0);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_ex, 0);
    will_return(__wrap_wdbc_query_ex, response_tactics);
    will_return(__wrap_wdbc_query_ex, -1);

    expect_string(__wrap__merror, formatted_msg, "No response or bad response from wazuh-db: 'Bad response'");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_querytactics_error_parse(void **state)
{
    (void) state;
    int ret;

    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1002\"}]";
    char *response_tactics = " ";
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_ex, 0);    
    will_return(__wrap_wdbc_query_ex, response_ids);
    will_return(__wrap_wdbc_query_ex, 0);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_ex, 0);
    will_return(__wrap_wdbc_query_ex, response_tactics);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap__merror, formatted_msg, "It was not possible to get MITRE tactics information.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_querytactics_empty_array(void **state)
{
    (void) state;
    int ret;

    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1002\"}]";
    char *response_tactics = "ok [ ]";
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_ex, 0);    
    will_return(__wrap_wdbc_query_ex, response_ids);
    will_return(__wrap_wdbc_query_ex, 0);
    
    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_ex, 0);
    will_return(__wrap_wdbc_query_ex, response_tactics);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database has 0 elements.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_querytactics_error_parse_tactics(void **state)
{
    (void) state;
    int ret;

    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1002\"}]";
    char *response_tactics = "ok [{\"phase\":\"Discovery\"}]";
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_ex, 0);    
    will_return(__wrap_wdbc_query_ex, response_ids);
    will_return(__wrap_wdbc_query_ex, 0);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_ex, 0);
    will_return(__wrap_wdbc_query_ex, response_tactics);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap__merror, formatted_msg, "It was not possible to get MITRE tactics information.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_querytactics_repeated_id(void **state)
{
    (void) state;
    int ret;

    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1001\"}]";
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_ex, 0);    
    will_return(__wrap_wdbc_query_ex, response_ids);
    will_return(__wrap_wdbc_query_ex, 0);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_ex, 0);
    will_return(__wrap_wdbc_query_ex, "ok [{\"phase_name\":\"Discovery\"}]");
    will_return(__wrap_wdbc_query_ex, 0);

    will_return(__wrap_wdbc_query_ex, 0);
    will_return(__wrap_wdbc_query_ex, "ok [{\"phase_name\":\"Lateral Movement\"}]");
    will_return(__wrap_wdbc_query_ex, 0);

    ret = mitre_load("test");
    assert_int_equal(0, ret);
}

void test_querytactics_success(void **state)
{
    (void) state;
    int ret;
    
    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1002\"}]";
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_ex, 0);    
    will_return(__wrap_wdbc_query_ex, response_ids);
    will_return(__wrap_wdbc_query_ex, 0);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_ex, 0);
    will_return(__wrap_wdbc_query_ex, "ok [{\"phase_name\":\"Discovery\"}]");
    will_return(__wrap_wdbc_query_ex, 0);

    will_return(__wrap_wdbc_query_ex, 0);
    will_return(__wrap_wdbc_query_ex, "ok [{\"phase_name\":\"Lateral Movement\"}]");
    will_return(__wrap_wdbc_query_ex, 0);

    ret = mitre_load("test");
    assert_int_equal(0, ret);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_queryid_error_socket),
        cmocka_unit_test(test_queryid_no_response),
        cmocka_unit_test(test_queryid_bad_response),
        cmocka_unit_test(test_queryid_error_parse),
        cmocka_unit_test(test_queryid_empty_array),
        cmocka_unit_test(test_queryid_error_parse_ids),
        cmocka_unit_test(test_querytactics_error_socket),
        cmocka_unit_test(test_querytactics_no_response),
        cmocka_unit_test(test_querytactics_bad_response),
        cmocka_unit_test(test_querytactics_error_parse),
        cmocka_unit_test(test_querytactics_empty_array),
        cmocka_unit_test(test_querytactics_error_parse_tactics),
        cmocka_unit_test(test_querytactics_repeated_id),
        cmocka_unit_test(test_querytactics_success),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
