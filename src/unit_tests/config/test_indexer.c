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
#include "../wrappers/externals/pcre2/pcre2_wrappers.h"

static char * test_path = "test_output.conf";
static char * test_cacerts[2] = {"cacert1.pem", "cacert2.pem"};
static char * test_cert = "cert.pem";
static char * test_key = "key.pem";

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
    w_test_pcre2_wrappers(false);
    FILE * file;
    for (int i = 0; i < 2; i++) {
        file = fopen(test_cacerts[i], "w");
        fclose(file);
    }
    file = fopen(test_cert, "w");
    fclose(file);
    file = fopen(test_key, "w");
    fclose(file);
    return 0;
}

static int teardown_test_read(void **state) {
    if (indexer_config) {
        cJSON_Delete(indexer_config);
    }
    unlink(test_path);
    for (int i = 0; i < 2; i++) {
        unlink(test_cacerts[i]);
    }
    unlink(test_cert);
    unlink(test_key);
    return 0;
}

void test_success_valid_configuration_host_IP(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://10.2.20.2:9200</host>"
                "<host>https://10.2.20.42:9200</host>"
            "</hosts>"
            "<ssl>"
                "<certificate_authorities>"
                    "<ca>cacert1.pem</ca>"
                    "<ca>cacert2.pem</ca>"
                "</certificate_authorities>"
                "<certificate>cert.pem</certificate>"
                "<key>key.pem</key>"
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
    assert_string_equal(json_result, "{\"hosts\":[\"http://10.2.20.2:9200\",\"https://10.2.20.42:9200\"],\"ssl\":{\"certificate_authorities\":[\"cacert1.pem\",\"cacert2.pem\"],\"certificate\":\"cert.pem\",\"key\":\"key.pem\"}}");
    cJSON_free(json_result);
}

void test_success_valid_configuration_host_hostname(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://hostname1:9200</host>"
                "<host>https://hostname2:9200</host>"
            "</hosts>"
            "<ssl>"
                "<certificate_authorities>"
                    "<ca>cacert1.pem</ca>"
                    "<ca>cacert2.pem</ca>"
                "</certificate_authorities>"
                "<certificate>cert.pem</certificate>"
                "<key>key.pem</key>"
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
    assert_string_equal(json_result, "{\"hosts\":[\"http://hostname1:9200\",\"https://hostname2:9200\"],\"ssl\":{\"certificate_authorities\":[\"cacert1.pem\",\"cacert2.pem\"],\"certificate\":\"cert.pem\",\"key\":\"key.pem\"}}");
    cJSON_free(json_result);
}

void test_success_valid_configuration_missing_certificate_key_settings(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://hostname1:9200</host>"
                "<host>https://hostname2:9200</host>"
            "</hosts>"
            "<ssl>"
                "<certificate_authorities>"
                    "<ca>cacert1.pem</ca>"
                    "<ca>cacert2.pem</ca>"
                "</certificate_authorities>"
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
    assert_string_equal(json_result, "{\"hosts\":[\"http://hostname1:9200\",\"https://hostname2:9200\"],\"ssl\":{\"certificate_authorities\":[\"cacert1.pem\",\"cacert2.pem\"]}}");
    cJSON_free(json_result);
}

void test_fail_invalid_enabled_setting(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<enabled>yes</enabled>"
            "<hosts>"
                "<host>http://hostname1:9200</host>"
                "<host>https://hostname2:9200</host>"
            "</hosts>"
            "<ssl>"
                "<certificate_authorities>"
                    "<ca>cacert1.pem</ca>"
                    "<ca>cacert2.pem</ca>"
                "</certificate_authorities>"
                "<certificate>cert.pem</certificate>"
                "<key>key.pem</key>"
            "</ssl>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__merror, formatted_msg, "Invalid element in the configuration: 'indexer.enabled'");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_fail_missing_ssl_section(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://hostname1:9200</host>"
                "<host>https://hostname2:9200</host>"
            "</hosts>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__merror, formatted_msg, "Missing required configuration in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_fail_missing_hosts_setting(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<ssl>"
                "<certificate_authorities>"
                    "<ca>cacert1.pem</ca>"
                    "<ca>cacert2.pem</ca>"
                "</certificate_authorities>"
                "<certificate>cert.pem</certificate>"
                "<key>key.pem</key>"
            "</ssl>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__merror, formatted_msg, "Missing required configuration in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_fail_invalid_host_setting_value(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>https://invalid/hostname:9200</host>"
            "</hosts>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__merror, formatted_msg, "Invalid host 'https://invalid/hostname:9200' in configuration array 'indexer.hosts' in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_fail_empty_host_setting_value(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host></host>"
            "</hosts>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__merror, formatted_msg, "Invalid host '' in configuration array 'indexer.hosts' in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_fail_empty_hostname_setting_value(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://:9200</host>"
            "</hosts>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__merror, formatted_msg, "Invalid host 'http://:9200' in configuration array 'indexer.hosts' in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_fail_missing_port_setting_value(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://hostname</host>"
            "</hosts>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__merror, formatted_msg, "Invalid host 'http://hostname' in configuration array 'indexer.hosts' in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_fail_missing_port_setting_value_with_port_separator(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://hostname:</host>"
            "</hosts>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__merror, formatted_msg, "Invalid host 'http://hostname:' in configuration array 'indexer.hosts' in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_fail_invalid_port_setting_value(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://hostname:port</host>"
            "</hosts>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__merror, formatted_msg, "Invalid host 'http://hostname:port' in configuration array 'indexer.hosts' in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_fail_missing_protocol_setting_value(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>hostname:9200</host>"
            "</hosts>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__merror, formatted_msg, "Invalid host 'hostname:9200' in configuration array 'indexer.hosts' in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_fail_empty_certificate_file_path(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://hostname1:9200</host>"
            "</hosts>"
            "<ssl>"
                "<certificate_authorities>"
                    "<ca></ca>"
                "</certificate_authorities>"
                "<certificate>cert.pem</certificate>"
                "<key>key.pem</key>"
            "</ssl>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__merror, formatted_msg, "File '' not found for 'indexer.ssl.certificate_authorities' in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_fail_non_existent_certificate_file(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://10.2.20.2:9200</host>"
                "<host>https://10.2.20.42:9200</host>"
            "</hosts>"
            "<ssl>"
                "<certificate_authorities>"
                    "<ca>/var/wazuh-manager/cacert1.pem</ca>"
                "</certificate_authorities>"
                "<certificate>cert.pem</certificate>"
                "<key>key.pem</key>"
            "</ssl>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__merror, formatted_msg, "File '/var/wazuh-manager/cacert1.pem' not found for 'indexer.ssl.certificate_authorities' in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_success_duplicate_configuration_block(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://10.2.20.2:9200</host>"
                "<host>https://10.2.20.42:9200</host>"
            "</hosts>"
            "<ssl>"
                "<certificate_authorities>"
                    "<ca>cacert1.pem</ca>"
                    "<ca>cacert2.pem</ca>"
                "</certificate_authorities>"
                "<certificate>cert.pem</certificate>"
                "<key>key.pem</key>"
            "</ssl>"
        "</indexer>"
        "<indexer>"
            "<hosts>"
                "<host>http://10.2.20.2:9200</host>"
                "<host>https://10.2.20.42:9200</host>"
            "</hosts>"
            "<ssl>"
                "<certificate_authorities>"
                    "<ca>cacert1.pem</ca>"
                    "<ca>cacert2.pem</ca>"
                "</certificate_authorities>"
                "<certificate>cert.pem</certificate>"
                "<key>key.pem</key>"
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
    assert_string_equal(json_result, "{\"hosts\":[\"http://10.2.20.2:9200\",\"https://10.2.20.42:9200\"],\"ssl\":{\"certificate_authorities\":[\"cacert1.pem\",\"cacert2.pem\"],\"certificate\":\"cert.pem\",\"key\":\"key.pem\"}}");
    cJSON_free(json_result);
}

void test_success_multiple_configuration_blocks(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://10.1.10.1:9200</host>"
                "<host>https://10.1.10.41:9200</host>"
            "</hosts>"
            "<ssl>"
                "<certificate_authorities>"
                    "<ca>cacert1.pem</ca>"
                "</certificate_authorities>"
                "<certificate>cert.pem</certificate>"
                "<key>key.pem</key>"
            "</ssl>"
        "</indexer>"
        "<indexer>"
            "<hosts>"
                "<host>http://10.2.20.2:9200</host>"
                "<host>https://10.2.20.42:9200</host>"
            "</hosts>"
            "<ssl>"
                "<certificate_authorities>"
                    "<ca>cacert2.pem</ca>"
                "</certificate_authorities>"
                "<certificate>cert.pem</certificate>"
                "<key>key.pem</key>"
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
    assert_string_equal(json_result, "{\"hosts\":[\"http://10.2.20.2:9200\",\"https://10.2.20.42:9200\"],\"ssl\":{\"certificate_authorities\":[\"cacert2.pem\"],\"certificate\":\"cert.pem\",\"key\":\"key.pem\"}}");
    cJSON_free(json_result);
}

void test_fail_empty_indexer_configuration_block(void **state) {
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

    expect_string(__wrap__merror, formatted_msg, "Empty configuration for module 'indexer'");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_fail_empty_key_setting_value(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://10.2.20.2:9200</host>"
                "<host>https://10.2.20.42:9200</host>"
            "</hosts>"
            "<ssl>"
                "<certificate_authorities>"
                    "<ca>cacert1.pem</ca>"
                    "<ca>cacert2.pem</ca>"
                "</certificate_authorities>"
                "<certificate>cert.pem</certificate>"
                "<key></key>"
            "</ssl>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__merror, formatted_msg, "Configuration field 'indexer.ssl.key' has an empty value in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_fail_host_0_entries(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
            "</hosts>"
            "<ssl>"
                "<certificate_authorities>"
                    "<ca>cacert1.pem</ca>"
                    "<ca>cacert2.pem</ca>"
                "</certificate_authorities>"
                "<certificate>cert.pem</certificate>"
                "<key>key.pem</key>"
            "</ssl>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__merror, formatted_msg, "Configuration array 'indexer.hosts' is empty in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_success_host_1_entry(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://10.2.20.2:9200</host>"
            "</hosts>"
            "<ssl>"
                "<certificate_authorities>"
                    "<ca>cacert1.pem</ca>"
                    "<ca>cacert2.pem</ca>"
                "</certificate_authorities>"
                "<certificate>cert.pem</certificate>"
                "<key>key.pem</key>"
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
    assert_string_equal(json_result, "{\"hosts\":[\"http://10.2.20.2:9200\"],\"ssl\":{\"certificate_authorities\":[\"cacert1.pem\",\"cacert2.pem\"],\"certificate\":\"cert.pem\",\"key\":\"key.pem\"}}");
    cJSON_free(json_result);
}

void test_fail_certificate_authorities_0_entries(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://10.2.20.2:9200</host>"
                "<host>https://10.2.20.42:9200</host>"
            "</hosts>"
            "<ssl>"
                "<certificate_authorities>"
                "</certificate_authorities>"
                "<certificate>cert.pem</certificate>"
                "<key>key.pem</key>"
            "</ssl>"
        "</indexer>"
    "</ossec_config>";

    FILE * output = fopen(test_path, "w");
    fwrite(string, 1, strlen(string), output);
    fclose(output);

    expect_string(__wrap_Read_Indexer, config_file, OSSECCONF);
    expect_string(__wrap_get_indexer_cnf, cnf_file, test_path);

    expect_string(__wrap__merror, formatted_msg, "Configuration array 'indexer.ssl.certificate_authorities' is empty in module 'indexer'. Check configuration");
    assert_int_equal(Read_Indexer(OSSECCONF), OS_INVALID);
    assert_null(indexer_config);
}

void test_success_certificate_authorities_1_entry(void **state) {
    const char *string =
    "<ossec_config>"
        "<indexer>"
            "<hosts>"
                "<host>http://10.2.20.2:9200</host>"
                "<host>https://10.2.20.42:9200</host>"
            "</hosts>"
            "<ssl>"
                "<certificate_authorities>"
                    "<ca>cacert1.pem</ca>"
                "</certificate_authorities>"
                "<certificate>cert.pem</certificate>"
                "<key>key.pem</key>"
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
    assert_string_equal(json_result, "{\"hosts\":[\"http://10.2.20.2:9200\",\"https://10.2.20.42:9200\"],\"ssl\":{\"certificate_authorities\":[\"cacert1.pem\"],\"certificate\":\"cert.pem\",\"key\":\"key.pem\"}}");
    cJSON_free(json_result);
}

int main(void) {
    const struct CMUnitTest tests_configuration[] = {
        cmocka_unit_test_setup_teardown(test_success_valid_configuration_host_IP, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_success_valid_configuration_host_hostname, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_success_valid_configuration_missing_certificate_key_settings, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_invalid_enabled_setting, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_missing_ssl_section, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_missing_hosts_setting, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_invalid_host_setting_value, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_empty_host_setting_value, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_empty_hostname_setting_value, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_missing_port_setting_value, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_missing_port_setting_value_with_port_separator, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_invalid_port_setting_value, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_missing_protocol_setting_value, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_empty_certificate_file_path, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_non_existent_certificate_file, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_success_duplicate_configuration_block, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_success_multiple_configuration_blocks, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_empty_indexer_configuration_block, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_empty_key_setting_value, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_host_0_entries, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_success_host_1_entry, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fail_certificate_authorities_0_entries, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_success_certificate_authorities_1_entry, setup_test_read, teardown_test_read),
    };
    return cmocka_run_group_tests(tests_configuration, NULL, NULL);
}
