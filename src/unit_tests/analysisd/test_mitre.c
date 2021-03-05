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

    ret = mitre_load();
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

    ret = mitre_load();
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

    ret = mitre_load();
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

    ret = mitre_load();
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

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_queryid_error_parse_technique_id(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"ids\":\"technique-0001\"},{\"ids\":\"technique-0002\"}]");

    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_string(__wrap__merror, formatted_msg, "It was not possible to get Mitre technique ID.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_queryid_error_parse_technique_name(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\"},{\"id\":\"technique-0002\"}]");

    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_string(__wrap__merror, formatted_msg, "It was not possible to get Mitre technique name.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_queryid_error_parse_technique_external_id(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\"}]");

    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_string(__wrap__merror, formatted_msg, "It was not possible to get Mitre technique external ID.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_querytactics_error_socket(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
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

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_querytactics_no_response(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
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

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_querytactics_bad_response(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
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

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_querytactics_error_parse(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"phase_name\":}]");

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_querytactics_empty_array(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[ ]");

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database has 0 elements.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_querytactics_error_parse_tactics(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"phase\":\"Discovery\"}]");

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    expect_string(__wrap__merror, formatted_msg, "It was not possible to get MITRE tactic ID.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_queryname_error_socket(void **state) {
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"tactic_id\":\"tactic-0001\"}]");
    cJSON * tactic_info_array = NULL;

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    /* Mitre tactic's information query */
    will_return(__wrap_wdbc_query_parse_json, -2);
    will_return(__wrap_wdbc_query_parse_json, tactic_info_array);

    expect_string(__wrap__merror, formatted_msg, "Unable to connect to socket '/queue/db/wdb'");
    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);
}


void test_queryname_no_response(void **state) {
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"tactic_id\":\"tactic-0001\"}]");
    cJSON * tactic_info_array = NULL;

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    /* Mitre tactic's information query */
    will_return(__wrap_wdbc_query_parse_json, -1);
    will_return(__wrap_wdbc_query_parse_json, tactic_info_array);

    expect_string(__wrap__merror, formatted_msg, "No response from wazuh-db.");
    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_queryname_bad_response(void **state) {
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"tactic_id\":\"tactic-0001\"}]");
    cJSON * tactic_info_array = NULL;
    char * response_tactics = "err not found";

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    /* Mitre tactic's information query */
    will_return(__wrap_wdbc_query_parse_json, 1);
    will_return(__wrap_wdbc_query_parse_json, response_tactics);
    will_return(__wrap_wdbc_query_parse_json, tactic_info_array);

    expect_string(__wrap__merror, formatted_msg, "Bad response from wazuh-db: not found");
    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_queryname_error_parse(void **state) {
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"tactic_id\":\"tactic-0001\"}]");
    cJSON * tactic_info_array = cJSON_Parse("[{\"info\":}]");

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    /* Mitre tactic's information query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_info_array);

    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_queryname_error_parse_technique_name(void **state) {
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"tactic_id\":\"tactic-0001\"}]");
    cJSON * tactic_info_array = cJSON_Parse("[{\"info\":\"Tactic1\"}]");

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    /* Mitre tactic's information query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_info_array);

    expect_string(__wrap__merror, formatted_msg, "It was not possible to get Mitre tactic name.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);
}

void test_queryname_error_parse_technique_external_id(void **state) {
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"tactic_id\":\"tactic-0001\"}]");
    cJSON * tactic_info_array = cJSON_Parse("[{\"name\":\"Tactic1\"}]");

    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    /* Mitre tactic's information query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_info_array);

    expect_string(__wrap__merror, formatted_msg, "It was not possible to get Mitre tactic external ID.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_queryid_error_socket),
        cmocka_unit_test(test_queryid_no_response),
        cmocka_unit_test(test_queryid_bad_response),
        cmocka_unit_test(test_queryid_error_parse),
        cmocka_unit_test(test_queryid_empty_array),
        cmocka_unit_test(test_queryid_error_parse_technique_id),
        cmocka_unit_test(test_queryid_error_parse_technique_name),
        cmocka_unit_test(test_queryid_error_parse_technique_external_id),
        cmocka_unit_test(test_querytactics_error_socket),
        cmocka_unit_test(test_querytactics_no_response),
        cmocka_unit_test(test_querytactics_bad_response),
        cmocka_unit_test(test_querytactics_error_parse),
        cmocka_unit_test(test_querytactics_empty_array),
        cmocka_unit_test(test_querytactics_error_parse_tactics),
        cmocka_unit_test(test_queryname_error_socket),
        cmocka_unit_test(test_queryname_no_response),
        cmocka_unit_test(test_queryname_bad_response),
        cmocka_unit_test(test_queryname_error_parse),
        cmocka_unit_test(test_queryname_error_parse_technique_name),
        cmocka_unit_test(test_queryname_error_parse_technique_external_id),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
