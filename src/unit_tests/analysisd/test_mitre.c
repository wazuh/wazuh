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

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"


#include "../analysisd/mitre.h"

extern OSHash *techniques_table;

/* setup/teardown */

static int setup_group(void **state) {
    if (setup_hashmap(state) != 0) {
        return 1;
    }

    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;

    if (teardown_hashmap(NULL) != 0) {
        return -1;
    }

    return 0;
}

static int teardown_techniques_table(void **state) {
    OSHash_Free(techniques_table);
    return 0;
}

/* tests */

void test_queryid_error_socket(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = NULL;

    will_return(__wrap_wdbc_connect_with_attempts, -2);


    expect_string(__wrap__merror, formatted_msg, "Unable to connect to Wazuh-DB for Mitre matrix information.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);

}

void test_queryid_no_response(void **state)
{
    (void) state;
    int ret;
    cJSON * id_array = NULL;

    will_return(__wrap_wdbc_connect_with_attempts, 1);
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

    will_return(__wrap_wdbc_connect_with_attempts, 1);
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

    will_return(__wrap_wdbc_connect_with_attempts, 1);
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

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database has 0 elements.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);

}

void test_queryid_error_parse_technique_id(void **state) {
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"ids\":\"technique-0001\"},{\"ids\":\"technique-0002\"}]");

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    expect_string(__wrap__merror, formatted_msg, "It was not possible to get Mitre technique ID.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);

}

void test_queryid_error_parse_technique_name(void **state) {
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\"},{\"id\":\"technique-0002\"}]");

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    expect_string(__wrap__merror, formatted_msg, "It was not possible to get Mitre technique name.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);

}

void test_queryid_error_parse_technique_external_id(void **state) {
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\"}]");

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    expect_string(__wrap__merror, formatted_msg, "It was not possible to get Mitre technique external ID.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);

}

void test_querytactics_error_socket(void **state) {
    (void) state;
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = NULL;

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, -2);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    expect_string(__wrap__merror, formatted_msg, "Unable to connect to socket 'queue/db/wdb'");
    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);

}

void test_querytactics_no_response(void **state) {
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = NULL;

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, -1);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    expect_string(__wrap__merror, formatted_msg, "No response from wazuh-db.");
    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);

}

void test_querytactics_bad_response(void **state) {
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = NULL;
    char * response_tactics = "err not found";

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

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

void test_querytactics_error_parse(void **state) {
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"phase_name\":}]");

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);

}

void test_querytactics_empty_array(void **state) {
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[ ]");

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database has 0 elements.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);

}

void test_querytactics_error_parse_tactics(void **state) {
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"phase\":\"Discovery\"}]");

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    expect_string(__wrap__merror, formatted_msg, "It was not possible to get MITRE tactic ID.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);

}

void test_queryname_error_socket(void **state) {
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"tactic_id\":\"tactic-0001\"}]");
    cJSON * tactic_info_array = NULL;

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    /* Mitre tactic's information query */
    will_return(__wrap_wdbc_query_parse_json, -2);
    will_return(__wrap_wdbc_query_parse_json, tactic_info_array);

    expect_string(__wrap__merror, formatted_msg, "Unable to connect to socket 'queue/db/wdb'");
    expect_string(__wrap__merror, formatted_msg, "Response from the Mitre database cannot be parsed.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);

}

void test_queryname_no_response(void **state) {
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"tactic_id\":\"tactic-0001\"}]");
    cJSON * tactic_info_array = NULL;

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

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
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"tactic_id\":\"tactic-0001\"}]");
    cJSON * tactic_info_array = NULL;
    char * response_tactics = "err not found";

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

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
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"tactic_id\":\"tactic-0001\"}]");
    cJSON * tactic_info_array = cJSON_Parse("[{\"info\":}]");

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

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
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"tactic_id\":\"tactic-0001\"}]");
    cJSON * tactic_info_array = cJSON_Parse("[{\"info\":\"Tactic1\"}]");

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

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
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"},{\"id\":\"technique-0002\",\"name\":\"Technique2\",\"external_id\":\"T1002\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"tactic_id\":\"tactic-0001\"}]");
    cJSON * tactic_info_array = cJSON_Parse("[{\"name\":\"Tactic1\"}]");

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

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

void test_query_tactics_error_filling_technique(void **state) {
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"tactic_id\":\"tactic-0001\"}]");
    cJSON * tactic_info_array = cJSON_Parse("[{\"name\":\"Tactic1\",\"external_id\":\"TA001\"}]");

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    /* Mitre tactic's information query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_info_array);

    /* OSHash  */
    expect_string(__wrap_OSHash_Add,  key, "T1001");
    will_return(__wrap_OSHash_Add, 0);

    expect_string(__wrap__merror, formatted_msg, "Mitre techniques hash table adding failed. Mitre Technique ID 'T1001' cannot be stored.");
    expect_string(__wrap__merror, formatted_msg, "Mitre matrix information could not be loaded.");

    ret = mitre_load();
    assert_int_equal(-1, ret);

}

void test_query_tactics_success(void **state) {
    int ret;
    cJSON * id_array = cJSON_Parse("[{\"id\":\"technique-0001\",\"name\":\"Technique1\",\"external_id\":\"T1001\"}]");
    cJSON * tactic_array = cJSON_Parse("[{\"tactic_id\":\"tactic-0001\"}]");
    cJSON * tactic_info_array = cJSON_Parse("[{\"name\":\"Tactic1\",\"external_id\":\"TA001\"}]");
    cJSON * technique_last = cJSON_Parse(" ");

    will_return(__wrap_wdbc_connect_with_attempts, 1);
    /* Mitre's techniques IDs query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, id_array);

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, mock_hashmap);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    /* Mitre's tactics query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_array);

    /* Mitre tactic's information query */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, tactic_info_array);

    /* OSHash  */
    expect_string(__wrap_OSHash_Add,  key, "T1001");
    will_return(__wrap_OSHash_Add, 1);

    /* Last Getting technique ID and name from Mitre's database in Wazuh-DB  */
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, technique_last);

    ret = mitre_load();
    assert_int_equal(0, ret);

}

void test_mitre_get_attack(void **state) {
    technique_data tech;
    technique_data tech_rec;
    technique_data *p_tech;
    char *mitre_id = "T1001";
    p_tech = &tech_rec;

    tech.technique_id = mitre_id;
    tech.technique_name = "Technique1";

    /* set string to receive*/
    expect_any(__wrap_OSHash_Get,  self);
    expect_string(__wrap_OSHash_Get,  key, mitre_id);
    will_return(__wrap_OSHash_Get, &tech);

    p_tech = mitre_get_attack((const char *)mitre_id);
    /* compare name string searched by id */
    assert_string_equal(tech.technique_name, p_tech->technique_name);
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
        cmocka_unit_test(test_query_tactics_error_filling_technique),
        cmocka_unit_test(test_query_tactics_success),
        cmocka_unit_test(test_mitre_get_attack),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
