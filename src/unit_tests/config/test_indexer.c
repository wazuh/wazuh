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

static char * test_path = "test_output.conf";

extern int __real_Read_Indexer(const char* config_file);
int __wrap_Read_Indexer(const char* config_file) {
    check_expected(config_file);
    return __real_Read_Indexer(test_path);
}

extern char* __real_get_indexer_cnf(const char* cnf_file, char* err_buf, size_t err_buf_size);
char* __wrap_get_indexer_cnf(const char* cnf_file, char* err_buf, size_t err_buf_size) {
    check_expected(cnf_file);
    return __real_get_indexer_cnf(test_path, err_buf, err_buf_size);
}

static const XML_NODE string_to_xml_node(const char * string, OS_XML *_lxml){
    XML_NODE nodes;
    OS_ReadXMLString(string, _lxml);
    nodes = OS_GetElementsbyNode(_lxml, NULL);
    return nodes;
}

static int setup_test_read(void **state) {
    indexer_config = NULL;
    return 0;
}

static int teardown_test_read(void **state) {
    if (indexer_config) {
        cJSON_Delete(indexer_config);
    }
    unlink(test_path);
    return 0;
}

void test_read_full_configuration(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
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
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    assert_int_equal(Read_Indexer(OSSECCONF), OS_SUCCESS);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{\"enabled\":\"yes\",\"hosts\":[\"http://10.2.20.2:9200\",\"https://10.2.20.42:9200\"],\"ssl\":{\"certificate_authorities\":[\"/var/ossec/\",\"/var/ossec_cert/\"],\"certificate\":\"cert\",\"key\":\"key_example\"}}");
    cJSON_free(json_result);
}

void test_read_duplicate_configuration(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
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
        "</indexer>"
        "<indexer>"
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
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    assert_int_equal(Read_Indexer(OSSECCONF), OS_SUCCESS);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{\"enabled\":\"yes\",\"hosts\":[\"http://10.2.20.2:9200\",\"https://10.2.20.42:9200\"],\"ssl\":{\"certificate_authorities\":[\"/var/ossec/\",\"/var/ossec_cert/\"],\"certificate\":\"cert\",\"key\":\"key_example\"}}");
    cJSON_free(json_result);
}

void test_read_multiple_configuration(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
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
        "</indexer>"
        "<indexer>"
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
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    assert_int_equal(Read_Indexer(OSSECCONF), OS_SUCCESS);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{\"enabled\":\"yes\",\"hosts\":[\"http://10.2.20.2:9200\",\"https://10.2.20.42:9200\"],\"ssl\":{\"certificate_authorities\":[\"/var/ossec2/\",\"/var/ossec_cert2/\"],\"certificate\":\"cert_2\",\"key\":\"key_example_2\"}}");
    cJSON_free(json_result);
}

void test_read_empty_configuration(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__mdebug1, formatted_msg, "Empty configuration for module 'indexer'");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{}");
    cJSON_free(json_result);
}

void test_read_empty_field_configuration(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
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
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__mwarn, formatted_msg, "Configuration field 'indexer.ssl.key' has an empty value in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_SUCCESS);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{\"enabled\":\"yes\",\"hosts\":[\"http://10.2.20.2:9200\",\"https://10.2.20.42:9200\"],\"ssl\":{\"certificate_authorities\":[\"/var/ossec/\",\"/var/ossec_cert/\"],\"certificate\":\"cert\",\"key\":\"\"}}");
    cJSON_free(json_result);
}

void test_read_field_host_0_entries_configuration_fail(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
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
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__mwarn, formatted_msg, "Configuration array 'indexer.hosts' is empty in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_SUCCESS);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{\"enabled\":\"yes\",\"hosts\":[],\"ssl\":{\"certificate_authorities\":[\"/var/ossec/\",\"/var/ossec_cert/\"],\"certificate\":\"cert\",\"key\":\"key_example\"}}");
    cJSON_free(json_result);
}

void test_read_field_host_1_entries_configuration(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
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
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    assert_int_equal(Read_Indexer(OSSECCONF), OS_SUCCESS);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{\"enabled\":\"yes\",\"hosts\":[\"http://10.2.20.2:9200\"],\"ssl\":{\"certificate_authorities\":[\"/var/ossec/\",\"/var/ossec_cert/\"],\"certificate\":\"cert\",\"key\":\"key_example\"}}");
    cJSON_free(json_result);
}

void test_read_field_certificate_authorities_0_entries_configuration_fail(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
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
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__mwarn, formatted_msg, "Configuration array 'indexer.ssl.certificate_authorities' is empty in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_SUCCESS);
    char * json_result = cJSON_PrintUnformatted(indexer_config);
    assert_string_equal(json_result, "{\"enabled\":\"yes\",\"hosts\":[\"http://10.2.20.2:9200\",\"https://10.2.20.42:9200\"],\"ssl\":{\"certificate_authorities\":[],\"certificate\":\"cert\",\"key\":\"key_example\"}}" );
    cJSON_free(json_result);
}

void test_read_field_certificate_authorities_1_entries_configuration(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
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
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    assert_int_equal(Read_Indexer(OSSECCONF), OS_SUCCESS);
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
