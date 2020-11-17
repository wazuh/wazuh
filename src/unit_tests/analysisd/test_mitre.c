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

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"

#include "../analysisd/mitre.h"

/* tests */

void test_queryid_error_socket(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = NULL;

    will_return(__wrap_wdbc_query_parse_json, -2);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_string(__wrap__merror, formatted_msg, "Unable to connect to socket '/queue/db/wdb'");
    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_queryid_no_response(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = NULL;

    will_return(__wrap_wdbc_query_parse_json, -1);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_string(__wrap__merror, formatted_msg, "No response from wazuh-db.");
    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_queryid_bad_response(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = NULL;

    char *response_ids = "err not found";
    will_return(__wrap_wdbc_query_parse_json, 1);
    will_return(__wrap_wdbc_query_parse_json, response_ids);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_string(__wrap__merror, formatted_msg, "Bad response from wazuh-db: not found");
    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_queryid_error_parse(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":}]");

    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_queryid_empty_array(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[ ]");

    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database has 0 elements.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_queryid_error_parse_ids(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"ids\":\"T1001\"},{\"ids\":\"T1002\"}]");

    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_string(__wrap__merror, formatted_msg, "It was not possible to get Mitre techniques information.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_querytactics_error_socket(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"T1001\"},{\"id\":\"T1002\"}]");
    cJSON * tactic_array = NULL;

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, -2);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    expect_string(__wrap__merror, formatted_msg, "Unable to connect to socket '/queue/db/wdb'");
    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_querytactics_no_response(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"T1001\"},{\"id\":\"T1002\"}]");
    cJSON * tactic_array = NULL;

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, -1);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    expect_string(__wrap__merror, formatted_msg, "No response from wazuh-db.");
    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_querytactics_bad_response(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"T1001\"},{\"id\":\"T1002\"}]");
    cJSON * tactic_array = NULL;
    char * response_tactics = "err not found";

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 1);
    will_return(__wrap_wdbc_query_parse_json, response_tactics);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    expect_string(__wrap__merror, formatted_msg, "Bad response from wazuh-db: not found");
    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_querytactics_error_parse(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"T1001\"},{\"id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"phase_name\":}]");

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_querytactics_empty_array(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"T1001\"},{\"id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[ ]");

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database has 0 elements.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_querytactics_error_parse_tactics(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"T1001\"},{\"id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"phase\":\"Discovery\"}]");

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    expect_string(__wrap__merror, formatted_msg, "It was not possible to get MITRE tactics information.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_queryname_error_socket(void **state) {
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"T1001\"},{\"id\":\"T1001\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"phase_name\":\"Command And Control\"}]");

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    /* Mitre technique's name query */
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, "");
    will_return(__wrap_wdbc_query_ex, -2);

    expect_string(__wrap__merror, formatted_msg, "Unable to connect to socket '/queue/db/wdb'");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-2, ret);
}


void test_queryname_no_response(void **state) {
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"T1001\"},{\"id\":\"T1001\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"phase_name\":\"Command And Control\"}]");

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    /* Mitre technique's name query */
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, "");
    will_return(__wrap_wdbc_query_ex, -1);

    expect_string(__wrap__merror, formatted_msg, "No response from wazuh-db.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_queryname_bad_response(void **state) {
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"T1001\"},{\"id\":\"T1001\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"phase_name\":\"Command And Control\"}]");

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    /* Mitre technique's name query */
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_any(__wrap_wdbc_query_ex, len);
    // will_return(__wrap_wdbc_query_ex, 0);
    will_return(__wrap_wdbc_query_ex, "err not found");
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap__merror, formatted_msg, "Bad response from wazuh-db: not found");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load("test");
    assert_int_equal(-1, ret);
}

void test_querytactics_repeated_id(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"T1001\"},{\"id\":\"T1001\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"phase_name\":\"Command And Control\"}]");
    cJSON * tactic_array_2 = cJSON_Parse("[{\"phase_name\":\"Command And Control\"}]");

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    /* Mitre technique's name query */
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_any(__wrap_wdbc_query_ex, len);
    // will_return(__wrap_wdbc_query_ex, 0);
    will_return(__wrap_wdbc_query_ex, "ok Data Obfuscation");
    will_return(__wrap_wdbc_query_ex, 0);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array_2);

    /* Mitre technique's name query */
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, "ok Data Obfuscation");
    will_return(__wrap_wdbc_query_ex, 0);

    ret = mitre_load("test");
    assert_int_equal(0, ret);
}

void test_querytactics_success(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"T1001\"},{\"id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"phase_name\":\"Command And Control\"}]");
    cJSON * tactic_array_2 = cJSON_Parse("[{\"phase_name\":\"Exfiltration\"}]");

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    /* Mitre technique's name query */
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, "ok Data Obfuscation");
    will_return(__wrap_wdbc_query_ex, 0);

    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array_2);

    /* Mitre technique's name query */
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, "ok Data Compressed");
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
        cmocka_unit_test(test_queryname_error_socket),
        cmocka_unit_test(test_queryname_no_response),
        cmocka_unit_test(test_queryname_bad_response),
        cmocka_unit_test(test_querytactics_repeated_id),
        cmocka_unit_test(test_querytactics_success),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
