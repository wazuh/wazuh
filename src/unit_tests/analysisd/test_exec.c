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

#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_agent_wrappers.h"
#include "../../analysisd/eventinfo.h"
#include "../../analysisd/config.h"
#include "../../analysisd/alerts/exec.h"
#include "../../config/active-response.h"

typedef struct test_struct {
    Eventinfo *lf;
    active_response *ar;
} test_struct_t;

// Setup / Teardown

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(Eventinfo),init_data->lf);
    os_calloc(1,sizeof(*init_data->lf->generated_rule),init_data->lf->generated_rule);
    os_calloc(1,sizeof(active_response),init_data->ar);
    os_calloc(1,sizeof(*init_data->ar->ar_cmd),init_data->ar->ar_cmd);

    init_data->lf->srcip = NULL;
    init_data->lf->dstuser = NULL;
    init_data->lf->filename = "/home/vagrant/file/n44.txt";
    init_data->lf->time.tv_sec = 160987966;
    init_data->lf->generated_rule->sigid = 554;
    init_data->lf->location = "(ubuntu) any->syscheck";

    init_data->ar->name = "restart-ossec0";
    init_data->ar->ar_cmd->expect = 0;
    init_data->ar->ar_cmd->extra_args = NULL;
    init_data->ar->location = 0;
    init_data->ar->agent_id = "002";
    init_data->ar->command = "restart-ossec";

    *state = init_data;
    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->lf->generated_rule);
    os_free(data->ar->ar_cmd);
    os_free(data->lf);
    os_free(data->ar);
    os_free(data);

    return OS_SUCCESS;
}

// Wrappers

int __wrap_OS_SendUnix(int socket, const char *msg, int size) {
    check_expected(socket);
    check_expected(msg);
    check_expected(size);

    return mock();
}

int __wrap_OS_ReadXML(const char *file, OS_XML *_lxml) {
    return mock();
}

char* __wrap_OS_GetOneContentforElement(OS_XML *_lxml, const char **element_name) {
    return mock_type(char *);
}

void __wrap_OS_ClearXML(OS_XML *_lxml) {
    return;
}

char * __wrap_Eventinfo_to_jsonstr(__attribute__((unused)) const Eventinfo *lf, __attribute__((unused)) bool force_full_log) {
    return mock_type(char*);
}

// Tests

static int test_setup_word_between_two_words(void **state) {
    char *word = NULL;
    *state = word;
    return OS_SUCCESS;
}

static int test_teardown_word_between_two_words(void **state) {
    char *word  = (char *)*state;
    os_free(word);
    return OS_SUCCESS;
}

void test_specific_agent_success_json(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;
    int exec_id = 2;

    char *version = "v4.2.0";
    data->ar->location = SPECIFIC_AGENT;

    cJSON *agent_info_array = cJSON_CreateArray();
    cJSON *agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info, "version", version);
    cJSON_AddItemToArray(agent_info_array, agent_info);

    char *exec_msg = "(ubuntu) any->syscheck NNS 002 {\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-analysisd\"},\"command\":\"restart-ossec0\",\"parameters\":{\"extra_args\":[],\"alert\":[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]}}";
    const char *alert_info = "[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]";
    char *node = NULL;

    os_strdup("node01", node);

    Config.ar = 1;

    expect_value(__wrap_wdb_get_agent_info, id, exec_id);
    will_return(__wrap_wdb_get_agent_info, agent_info_array);

    will_return(__wrap_Eventinfo_to_jsonstr, strdup(alert_info));

    will_return(__wrap_OS_ReadXML, 1);

    will_return(__wrap_OS_GetOneContentforElement, node);

    expect_value(__wrap_OS_SendUnix, socket, arq);
    expect_string(__wrap_OS_SendUnix, msg, exec_msg);
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 1);

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_specific_agent_success_string(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;
    int exec_id = 2;

    char *version = "v4.0.0";
    data->ar->location = SPECIFIC_AGENT;

    cJSON *agent_info_array = cJSON_CreateArray();
    cJSON *agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info, "version", version);
    cJSON_AddItemToArray(agent_info_array, agent_info);

    char *exec_msg = "(ubuntu) any->syscheck NNS 002 restart-ossec0 - - 160987966.80794 554 (ubuntu) any->syscheck - -";

    Config.ar = 1;
    __crt_ftell = 80794;

    expect_value(__wrap_wdb_get_agent_info, id, exec_id);
    will_return(__wrap_wdb_get_agent_info, agent_info_array);

    expect_value(__wrap_OS_SendUnix, socket, arq);
    expect_string(__wrap_OS_SendUnix, msg, exec_msg);
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 1);

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_specific_agent_success_fail_agt_info1(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;
    int exec_id = 2;

    data->ar->location = SPECIFIC_AGENT;

    Config.ar = 1;

    expect_value(__wrap_wdb_get_agent_info, id, exec_id);
    will_return(__wrap_wdb_get_agent_info, NULL);

    expect_string(__wrap__merror, formatted_msg, "Failed to get agent '2' information from Wazuh DB.");

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_remote_agent_success_json(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;
    int exec_id = 2;

    char *version = "v4.2.0";
    data->ar->location = REMOTE_AGENT;

    cJSON *agent_info_array = cJSON_CreateArray();
    cJSON *agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info, "version", version);
    cJSON_AddItemToArray(agent_info_array, agent_info);

    char *exec_msg = "(ubuntu) any->syscheck NRN 002 {\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-analysisd\"},\"command\":\"restart-ossec0\",\"parameters\":{\"extra_args\":[],\"alert\":[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]}}";
    const char *alert_info = "[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]";
    char *node = NULL;

    os_strdup("node01", node);

    Config.ar = 1;

    expect_string(__wrap_wdb_find_agent, name, "ubuntu");
    expect_string(__wrap_wdb_find_agent, ip, "any");
    will_return(__wrap_wdb_find_agent, exec_id);

    expect_value(__wrap_wdb_get_agent_info, id, exec_id);
    will_return(__wrap_wdb_get_agent_info, agent_info_array);

    expect_value(__wrap_OS_SendUnix, socket, arq);
    expect_string(__wrap_OS_SendUnix, msg, exec_msg);
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 1);

    will_return(__wrap_Eventinfo_to_jsonstr, strdup(alert_info));

    will_return(__wrap_OS_ReadXML, 1);

    will_return(__wrap_OS_GetOneContentforElement, node);

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_remote_agent_success_string(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;
    int exec_id = 2;

    char *version = "v4.0.0";
    data->ar->location = REMOTE_AGENT;

    cJSON *agent_info_array = cJSON_CreateArray();
    cJSON *agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info, "version", version);
    cJSON_AddItemToArray(agent_info_array, agent_info);

    char *exec_msg = "(ubuntu) any->syscheck NRN 002 restart-ossec0 - - 160987966.80794 554 (ubuntu) any->syscheck - -";

    Config.ar = 1;
    __crt_ftell = 80794;

    expect_string(__wrap_wdb_find_agent, name, "ubuntu");
    expect_string(__wrap_wdb_find_agent, ip, "any");
    will_return(__wrap_wdb_find_agent, exec_id);

    expect_value(__wrap_wdb_get_agent_info, id, exec_id);
    will_return(__wrap_wdb_get_agent_info, agent_info_array);

    expect_value(__wrap_OS_SendUnix, socket, arq);
    expect_string(__wrap_OS_SendUnix, msg, exec_msg);
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 1);

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_remote_agent_success_fail_agt_info1(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;
    int exec_id = 2;

    data->ar->location = REMOTE_AGENT;

    Config.ar = 1;

    expect_string(__wrap_wdb_find_agent, name, "ubuntu");
    expect_string(__wrap_wdb_find_agent, ip, "any");
    will_return(__wrap_wdb_find_agent, exec_id);

    expect_value(__wrap_wdb_get_agent_info, id, exec_id);
    will_return(__wrap_wdb_get_agent_info, NULL);

    expect_string(__wrap__merror, formatted_msg, "Failed to get agent '2' information from Wazuh DB.");

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_remote_agent_success_fail_find_agent1(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq;
    int arq = 11;
    int exec_id = 2;
    data->ar->location = REMOTE_AGENT;

    Config.ar = 1;

    expect_string(__wrap_wdb_find_agent, name, "ubuntu");
    expect_string(__wrap_wdb_find_agent, ip, "any");
    will_return(__wrap_wdb_find_agent, OS_INVALID);

    expect_string(__wrap__merror, formatted_msg, "Unable to get agent ID.");

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_extract_word_between_two_words_ok_1(void **state){

    char *word  = (char *)*state;
    char *s= "(ubuntu) any->syscheck";

    word = extract_word_between_two_words(s, "(", ")");
    assert_string_equal(word, "ubuntu");

    os_free(word);
}

void test_extract_word_between_two_words_ok_2(void **state){
    char *word  = (char *)*state;
    char *s= "(ubuntu) any->syscheck";

    word = extract_word_between_two_words(s, "any", "syscheck");
    assert_string_equal(word, "->");

    os_free(word);
}

void test_extract_word_between_two_words_fail_1(void **state){

    char *word = NULL;
    char *s= "(ubuntu) any->syscheck";

    word = extract_word_between_two_words(s, ")", "(");
    assert_null(word);
}

void test_extract_word_between_two_words_fail_2(void **state){

    char *word = NULL;
    char *s= "(ubuntu) any->syscheck";

    word = extract_word_between_two_words(s, "!", "(");
    assert_null(word);
}

void test_getActiveResponseInJSON_extra_args(void **state){
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_msj = NULL;

    char msg[OS_SIZE_8192 + 1];
    char *c_device = NULL;
    const char *alert_info = "[{\"test\":\"test\"}]";
    char *extra_args = "-arg1 --arg2 arg3 \\; cat /etc/passwd";
    char *result = "[\"-arg1\",\"--arg2\",\"arg3\",\"cat\",\"/etc/passwd\"]";
    char *node = NULL;

    os_strdup("node01", node);

    will_return(__wrap_Eventinfo_to_jsonstr, strdup(alert_info));

    will_return(__wrap_OS_ReadXML, 1);

    will_return(__wrap_OS_GetOneContentforElement, node);

    getActiveResponseInJSON(data->lf, data->ar, extra_args, msg);

    cJSON * root = cJSON_Parse(msg);
    cJSON * deviceData = cJSON_GetObjectItem(root,"parameters");
    if(deviceData) {
       cJSON *device = deviceData->child;
       if(device) {
           c_device = cJSON_PrintUnformatted(device);
       }
    }
    cJSON_Delete(root);

    assert_string_equal(c_device, result);

    os_free(c_device);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // SPECIFIC_AGENT
        cmocka_unit_test_setup_teardown(test_specific_agent_success_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_specific_agent_success_string, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_specific_agent_success_fail_agt_info1, test_setup, test_teardown),

        // REMOTE_AGENT
        cmocka_unit_test_setup_teardown(test_remote_agent_success_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_remote_agent_success_string, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_remote_agent_success_fail_agt_info1, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_remote_agent_success_fail_find_agent1, test_setup, test_teardown),

        // extract_word_between_two_words
        cmocka_unit_test_setup_teardown(test_extract_word_between_two_words_ok_1, test_setup_word_between_two_words, test_teardown_word_between_two_words),
        cmocka_unit_test_setup_teardown(test_extract_word_between_two_words_ok_2, test_setup_word_between_two_words, test_teardown_word_between_two_words),
        cmocka_unit_test(test_extract_word_between_two_words_fail_1),
        cmocka_unit_test(test_extract_word_between_two_words_fail_2),

        // getActiveResponseInJSON
        cmocka_unit_test_setup_teardown(test_getActiveResponseInJSON_extra_args, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}