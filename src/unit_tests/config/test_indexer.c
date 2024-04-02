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
#include <time.h>

#include "../../config/config.h"
#include "../../config/indexer-config.h"


typedef struct test_structure {
    OS_XML xml;
    XML_NODE nodes;
} test_structure;

static const XML_NODE string_to_xml_node(const char * string, OS_XML *_lxml){
    XML_NODE nodes;
    OS_ReadXMLString(string, _lxml);
    nodes = OS_GetElementsbyNode(_lxml, NULL);
    return nodes;
}

static int setup_test_read(void **state) {
    indexer_config = NULL;
    test_structure *test;
    os_calloc(1, sizeof(test_structure), test);
    *state = test;
    return 0;
}

static int teardown_test_read(void **state) {
    test_structure *test = *state;
    OS_ClearNode(test->nodes);
    OS_ClearXML(&(test->xml));
    os_free(test);

    if (indexer_config) {
        cJSON_Delete(indexer_config);
    }
    return 0;
}

void test_read_full_configuration(void **state) {
    const char *string =
        "<enabled>yes</enabled>"
        "<hosts>"
            "<host>http://10.2.20.2:9200</host>"
            "<host>https://10.2.20.42:9200</host>"
        "</hosts>"
        "<ssl>"
        "<certificate_authorities>"
            "<ca>/var/ossec/</ca>"
            "<ca>/var/ossec_cert/</ca>"
        "</certificate_authorities>"
        "<certificate>cert</certificate>"
        "<key>key_example</key>"
        "</ssl>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(Read_Indexer(&(test->xml), test->nodes), 0);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{\"enabled\":\"yes\",\"hosts\":[\"http://10.2.20.2:9200\",\"https://10.2.20.42:9200\"],\"ssl\":{\"certificate_authorities\":[\"/var/ossec/\",\"/var/ossec_cert/\"],\"certificate\":\"cert\",\"key\":\"key_example\"}}");
    cJSON_free(json_result);
}

void test_read_duplicate_configuration(void **state) {
    const char *string =
        "<enabled>yes</enabled>"
        "<hosts>"
        "<host>http://10.2.20.2:9200</host>"
        "<host>https://10.2.20.42:9200</host>"
        "</hosts>"
        "<ssl>"
        "<certificate_authorities>"
        "<ca>/var/ossec/</ca>"
        "<ca>/var/ossec_cert/</ca>"
        "</certificate_authorities>"
        "<certificate>cert</certificate>"
        "<key>key_example</key>"
        "</ssl>"
        "<enabled>yes</enabled>"
        "<hosts>"
        "<host>http://10.2.20.2:9200</host>"
        "<host>https://10.2.20.42:9200</host>"
        "</hosts>"
        "<ssl>"
        "<certificate_authorities>"
        "<ca>/var/ossec/</ca>"
        "<ca>/var/ossec_cert/</ca>"
        "</certificate_authorities>"
        "<certificate>cert</certificate>"
        "<key>key_example</key>"
        "</ssl>"
        ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(Read_Indexer(&(test->xml), test->nodes), 0);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{\"enabled\":\"yes\",\"hosts\":[\"http://10.2.20.2:9200\",\"https://10.2.20.42:9200\"],\"ssl\":{\"certificate_authorities\":[\"/var/ossec/\",\"/var/ossec_cert/\"],\"certificate\":\"cert\",\"key\":\"key_example\"}}");
    cJSON_free(json_result);
}

void test_read_multiple_configuration(void **state) {
    const char *string =
        "<enabled>yes</enabled>"
        "<hosts>"
        "<host>http://10.1.10.1:9200</host>"
        "<host>https://10.1.10.41:9200</host>"
        "</hosts>"
        "<ssl>"
        "<certificate_authorities>"
        "<ca>/var/ossec/</ca>"
        "<ca>/var/ossec_cert/</ca>"
        "</certificate_authorities>"
        "<certificate>cert</certificate>"
        "<key>key_example</key>"
        "</ssl>"
        "<enabled>yes</enabled>"
        "<hosts>"
        "<host>http://10.2.20.2:9200</host>"
        "<host>https://10.2.20.42:9200</host>"
        "</hosts>"
        "<ssl>"
        "<certificate_authorities>"
        "<ca>/var/ossec2/</ca>"
        "<ca>/var/ossec_cert2/</ca>"
        "</certificate_authorities>"
        "<certificate>cert_2</certificate>"
        "<key>key_example_2</key>"
        "</ssl>"
        ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(Read_Indexer(&(test->xml), test->nodes), 0);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{\"enabled\":\"yes\",\"hosts\":[\"http://10.2.20.2:9200\",\"https://10.2.20.42:9200\"],\"ssl\":{\"certificate_authorities\":[\"/var/ossec2/\",\"/var/ossec_cert2/\"],\"certificate\":\"cert_2\",\"key\":\"key_example_2\"}}");
    cJSON_free(json_result);
}

void test_read_empty_configuration(void **state) {
    const char *string = "";
    test_structure *test = *state;
    expect_string(__wrap__mdebug1, formatted_msg, "Empty configuration for module 'indexer'");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(Read_Indexer(&(test->xml), test->nodes), 0);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{}");
    cJSON_free(json_result);
}

void test_read_empty_field_configuration(void **state) {
    const char *string =
        "<enabled>yes</enabled>"
        "<hosts>"
            "<host>http://10.2.20.2:9200</host>"
            "<host>https://10.2.20.42:9200</host>"
        "</hosts>"
        "<ssl>"
        "<certificate_authorities>"
            "<ca>/var/ossec/</ca>"
            "<ca>/var/ossec_cert/</ca>"
        "</certificate_authorities>"
        "<certificate>cert</certificate>"
        "<key></key>"
        "</ssl>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(Read_Indexer(&(test->xml), test->nodes), 0);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{\"enabled\":\"yes\",\"hosts\":[\"http://10.2.20.2:9200\",\"https://10.2.20.42:9200\"],\"ssl\":{\"certificate_authorities\":[\"/var/ossec/\",\"/var/ossec_cert/\"],\"certificate\":\"cert\",\"key\":\"\"}}");
    cJSON_free(json_result);
}

void test_read_field_host_0_entries_configuration_fail(void **state) {
    const char *string =
        "<enabled>yes</enabled>"
        "<hosts>"
        "</hosts>"
        "<ssl>"
        "<certificate_authorities>"
            "<ca>/var/ossec/</ca>"
            "<ca>/var/ossec_cert/</ca>"
        "</certificate_authorities>"
        "<certificate>cert</certificate>"
        "<key>key_example</key>"
        "</ssl>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "indexer.hosts is empty in module 'indexer'. Check configuration");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(Read_Indexer(&(test->xml), test->nodes), OS_MISVALUE);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{\"enabled\":\"yes\"}");
    cJSON_free(json_result);
}

void test_read_field_host_1_entries_configuration(void **state) {
    const char *string =
        "<enabled>yes</enabled>"
        "<hosts>"
            "<host>http://10.2.20.2:9200</host>"
        "</hosts>"
        "<ssl>"
        "<certificate_authorities>"
            "<ca>/var/ossec/</ca>"
            "<ca>/var/ossec_cert/</ca>"
        "</certificate_authorities>"
        "<certificate>cert</certificate>"
        "<key>key_example</key>"
        "</ssl>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(Read_Indexer(&(test->xml), test->nodes), 0);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{\"enabled\":\"yes\",\"hosts\":[\"http://10.2.20.2:9200\"],\"ssl\":{\"certificate_authorities\":[\"/var/ossec/\",\"/var/ossec_cert/\"],\"certificate\":\"cert\",\"key\":\"key_example\"}}");
    cJSON_free(json_result);
}

void test_read_field_certificate_authorities_0_entries_configuration_fail(void **state) {
    const char *string =
        "<enabled>yes</enabled>"
        "<hosts>"
            "<host>http://10.2.20.2:9200</host>"
            "<host>https://10.2.20.42:9200</host>"
        "</hosts>"
        "<ssl>"
        "<certificate_authorities>"
        "</certificate_authorities>"
        "<certificate>cert</certificate>"
        "<key>key_example</key>"
        "</ssl>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "indexer.ssl.certificate_authorities is empty in module 'indexer'. Check configuration");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(Read_Indexer(&(test->xml), test->nodes), 0);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{\"enabled\":\"yes\",\"hosts\":[\"http://10.2.20.2:9200\",\"https://10.2.20.42:9200\"],\"ssl\":{}}");
    cJSON_free(json_result);
}

void test_read_field_certificate_authorities_1_entries_configuration(void **state) {
    const char *string =
        "<enabled>yes</enabled>"
        "<hosts>"
            "<host>http://10.2.20.2:9200</host>"
            "<host>https://10.2.20.42:9200</host>"
        "</hosts>"
        "<ssl>"
        "<certificate_authorities>"
            "<ca>/var/ossec/</ca>"
        "</certificate_authorities>"
        "<certificate>cert</certificate>"
        "<key>key_example</key>"
        "</ssl>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(Read_Indexer(&(test->xml), test->nodes), 0);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{\"enabled\":\"yes\",\"hosts\":[\"http://10.2.20.2:9200\",\"https://10.2.20.42:9200\"],\"ssl\":{\"certificate_authorities\":[\"/var/ossec/\"],\"certificate\":\"cert\",\"key\":\"key_example\"}}");
    cJSON_free(json_result);
}

int main(void) {
    const struct CMUnitTest tests_configuration[] = {
        cmocka_unit_test_setup_teardown(test_read_full_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_duplicate_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_multiple_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_empty_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_empty_field_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_field_host_0_entries_configuration_fail, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_field_host_1_entries_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_field_certificate_authorities_0_entries_configuration_fail, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_field_certificate_authorities_1_entries_configuration, setup_test_read, teardown_test_read),
    };
    return cmocka_run_group_tests(tests_configuration, NULL, NULL);
}
