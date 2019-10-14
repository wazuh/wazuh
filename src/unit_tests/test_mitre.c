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

int __wrap_wdb_send_query(char * wazuhdb_query, char** response)
{   int option;

    option = mock_type(int);
    if (option == 0) {
        *response = strdup(mock_type(char *));
    } else {
        *response = NULL;
    }
    
    return mock();
}

/* tests */

void test_queryid_error_socket(void **state)
{
    (void) state;
    int ret;
    
    will_return(__wrap_wdb_send_query, -2);
    will_return(__wrap_wdb_send_query, -2);

    ret = mitre_load();
    assert_int_equal(-2, ret);
}

void test_queryid_no_response(void **state)
{
    (void) state;
    int ret;
    
    will_return(__wrap_wdb_send_query, -1);
    will_return(__wrap_wdb_send_query, -1);

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_queryid_bad_response(void **state)
{
    (void) state;
    int ret;
    
    char *response_ids = "Bad response";
    will_return(__wrap_wdb_send_query, 0);
    will_return(__wrap_wdb_send_query, response_ids);
    will_return(__wrap_wdb_send_query, -1);

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_queryid_error_parse(void **state)
{
    (void) state;
    int ret;
    
    char *response_ids = " ";
    will_return(__wrap_wdb_send_query, 0);    
    will_return(__wrap_wdb_send_query, response_ids);
    will_return(__wrap_wdb_send_query, 0);

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_queryid_empty_array(void **state)
{
    (void) state;
    int ret;
    
    char *response_ids = "ok []";
    will_return(__wrap_wdb_send_query, 0);    
    will_return(__wrap_wdb_send_query, response_ids);
    will_return(__wrap_wdb_send_query, 0);

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_queryid_error_parse_ids(void **state)
{
    (void) state;
    int ret;
    
    char *response_ids = "ok [{\"ids\":\"T1001\"},{\"ids\":\"T1002\"}]";
    will_return(__wrap_wdb_send_query, 0);    
    will_return(__wrap_wdb_send_query, response_ids);
    will_return(__wrap_wdb_send_query, 0);

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_querytactics_error_socket(void **state)
{
    (void) state;
    int ret;
    
    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1002\"}]";
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdb_send_query, 0);    
    will_return(__wrap_wdb_send_query, response_ids);
    will_return(__wrap_wdb_send_query, 0);
    
    /* Mitre's tactics query */
    will_return(__wrap_wdb_send_query, -2);
    will_return(__wrap_wdb_send_query, -2);

    ret = mitre_load();
    assert_int_equal(-2, ret);
}

void test_querytactics_no_response(void **state)
{
    (void) state;
    int ret;
    
    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1002\"}]";
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdb_send_query, 0);    
    will_return(__wrap_wdb_send_query, response_ids);
    will_return(__wrap_wdb_send_query, 0);
    
    /* Mitre's tactics query */
    will_return(__wrap_wdb_send_query, -1);
    will_return(__wrap_wdb_send_query, -1);

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_querytactics_bad_response(void **state)
{
    (void) state;
    int ret;
    
    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1002\"}]";
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdb_send_query, 0);    
    will_return(__wrap_wdb_send_query, response_ids);
    will_return(__wrap_wdb_send_query, 0);
    
    /* Mitre's tactics query */
    will_return(__wrap_wdb_send_query, 0);
    will_return(__wrap_wdb_send_query, "Bad response");
    will_return(__wrap_wdb_send_query, -1);

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_querytactics_error_parse(void **state)
{
    (void) state;
    int ret;
    
    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1002\"}]";
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdb_send_query, 0);    
    will_return(__wrap_wdb_send_query, response_ids);
    will_return(__wrap_wdb_send_query, 0);
    
    /* Mitre's tactics query */
    will_return(__wrap_wdb_send_query, 0);
    will_return(__wrap_wdb_send_query, " ");
    will_return(__wrap_wdb_send_query, 0);

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_querytactics_empty_array(void **state)
{
    (void) state;
    int ret;
    
    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1002\"}]";
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdb_send_query, 0);    
    will_return(__wrap_wdb_send_query, response_ids);
    will_return(__wrap_wdb_send_query, 0);
    
    /* Mitre's tactics query */
    will_return(__wrap_wdb_send_query, 0);
    will_return(__wrap_wdb_send_query, "ok [ ]");
    will_return(__wrap_wdb_send_query, 0);

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_querytactics_error_parse_tactics(void **state)
{
    (void) state;
    int ret;
    
    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1002\"}]";
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdb_send_query, 0);    
    will_return(__wrap_wdb_send_query, response_ids);
    will_return(__wrap_wdb_send_query, 0);
    
    /* Mitre's tactics query */
    will_return(__wrap_wdb_send_query, 0);
    will_return(__wrap_wdb_send_query, "ok [{\"phase\":\"Discovery\"}]");
    will_return(__wrap_wdb_send_query, 0);

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_querytactics_repeated_id(void **state)
{
    (void) state;
    int ret;
    
    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1001\"}]";
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdb_send_query, 0);    
    will_return(__wrap_wdb_send_query, response_ids);
    will_return(__wrap_wdb_send_query, 0);
    
    /* Mitre's tactics query */
    will_return(__wrap_wdb_send_query, 0);
    will_return(__wrap_wdb_send_query, "ok [{\"phase_name\":\"Discovery\"}]");
    will_return(__wrap_wdb_send_query, 0);

    will_return(__wrap_wdb_send_query, 0);
    will_return(__wrap_wdb_send_query, "ok [{\"phase_name\":\"Lateral Movement\"}]");
    will_return(__wrap_wdb_send_query, 0);

    ret = mitre_load();
    assert_int_equal(0, ret);
}

void test_querytactics_success(void **state)
{
    (void) state;
    int ret;
    
    char *response_ids = "ok [{\"id\":\"T1001\"},{\"id\":\"T1002\"}]";
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdb_send_query, 0);    
    will_return(__wrap_wdb_send_query, response_ids);
    will_return(__wrap_wdb_send_query, 0);
    
    /* Mitre's tactics query */
    will_return(__wrap_wdb_send_query, 0);
    will_return(__wrap_wdb_send_query, "ok [{\"phase_name\":\"Discovery\"}]");
    will_return(__wrap_wdb_send_query, 0);

    will_return(__wrap_wdb_send_query, 0);
    will_return(__wrap_wdb_send_query, "ok [{\"phase_name\":\"Lateral Movement\"}]");
    will_return(__wrap_wdb_send_query, 0);

    ret = mitre_load();
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
