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
#include "../wrappers/wazuh/shared/labels_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_global_helpers_wrappers.h"
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
    init_data->lf->agent_id = "001";

    init_data->ar->name = "restart-wazuh0";
    init_data->ar->ar_cmd->extra_args = NULL;
    init_data->ar->location = 0;
    init_data->ar->agent_id = "002";
    init_data->ar->command = "restart-wazuh";

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

// Tests

void test_server_success_json(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;

    data->ar->location = AS_ONLY;

    char *exec_msg = "{\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-analysisd\"},\"command\":\"restart-wazuh0\",\"parameters\":{\"extra_args\":[],\"alert\":[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]}}";
    const char *alert_info = "[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]";
    char *node = NULL;

    os_strdup("node01", node);

    Config.ar = 2;

    will_return(__wrap_Eventinfo_to_jsonstr, strdup(alert_info));

    will_return(__wrap_OS_ReadXML, 1);

    will_return(__wrap_OS_GetOneContentforElement, node);

    expect_value(__wrap_OS_SendUnix, socket, execq);
    expect_string(__wrap_OS_SendUnix, msg, exec_msg);
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 1);

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_all_agents_success_json_string(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;

    char *version_1 = "Wazuh v4.2.0";
    char *version_2 = "Wazuh v4.0.0";
    data->ar->location = ALL_AGENTS;

    char *exec_msg_1 = "(local_source) [] NNS 003 {\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-analysisd\"},\"command\":\"restart-wazuh0\",\"parameters\":{\"extra_args\":[],\"alert\":[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]}}";
    const char *alert_info_1 = "[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]";
    char *node_1 = NULL;

    os_strdup("node01", node_1);

    char *exec_msg = "(local_source) [] NNS 005 restart-wazuh0 - - 160987966.80794 554 (ubuntu) any->syscheck /home/vagrant/file/n44.txt -";

    Config.ar = 1;
    __crt_ftell = 80794;

    int *array = NULL;
    os_malloc(sizeof(int)*3, array);
    array[0] = 3;
    array[1] = 5;
    array[2] = OS_INVALID;

    expect_string(__wrap_wdb_get_agents_by_connection_status, status, AGENT_CS_ACTIVE);
    will_return(__wrap_wdb_get_agents_by_connection_status, array);

    // Alert 1

    wlabel_t *labels_1 = NULL;
    os_calloc(2, sizeof(wlabel_t), labels_1);

    os_strdup("_wazuh_version", labels_1[0].key);
    os_strdup(version_1, labels_1[0].value);

    expect_string(__wrap_labels_find, agent_id, "003");
    will_return(__wrap_labels_find, labels_1);

    expect_string(__wrap_labels_get, key, labels_1->key);
    will_return(__wrap_labels_get, labels_1->value);

    will_return(__wrap_Eventinfo_to_jsonstr, strdup(alert_info_1));

    will_return(__wrap_OS_ReadXML, 1);

    will_return(__wrap_OS_GetOneContentforElement, node_1);

    expect_value(__wrap_OS_SendUnix, socket, arq);
    expect_string(__wrap_OS_SendUnix, msg, exec_msg_1);
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 1);

    // Alert 2

    wlabel_t *labels_2 = NULL;
    os_calloc(2, sizeof(wlabel_t), labels_2);

    os_strdup("_wazuh_version", labels_2[0].key);
    os_strdup(version_2, labels_2[0].value);

    expect_string(__wrap_labels_find, agent_id, "005");
    will_return(__wrap_labels_find, labels_2);

    expect_string(__wrap_labels_get, key, labels_2->key);
    will_return(__wrap_labels_get, labels_2->value);

    expect_value(__wrap_OS_SendUnix, socket, arq);
    expect_string(__wrap_OS_SendUnix, msg, exec_msg);
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 1);

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_all_agents_success_json_string_wdb(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;

    char *version_1 = "Wazuh v4.2.0";
    char *version_2 = "Wazuh v4.0.0";
    data->ar->location = ALL_AGENTS;

    cJSON *agent_info_array_1 = cJSON_CreateArray();
    cJSON *agent_info_1 = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info_1, "version", version_1);
    cJSON_AddItemToArray(agent_info_array_1, agent_info_1);

    char *exec_msg_1 = "(local_source) [] NNS 003 {\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-analysisd\"},\"command\":\"restart-wazuh0\",\"parameters\":{\"extra_args\":[],\"alert\":[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]}}";
    const char *alert_info_1 = "[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]";
    char *node_1 = NULL;

    os_strdup("node01", node_1);

    cJSON *agent_info_array_2 = cJSON_CreateArray();
    cJSON *agent_info_2 = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info_2, "version", version_2);
    cJSON_AddItemToArray(agent_info_array_2, agent_info_2);

    char *exec_msg = "(local_source) [] NNS 005 restart-wazuh0 - - 160987966.80794 554 (ubuntu) any->syscheck /home/vagrant/file/n44.txt -";

    Config.ar = 1;
    __crt_ftell = 80794;

    int *array = NULL;
    os_malloc(sizeof(int)*3, array);
    array[0] = 3;
    array[1] = 5;
    array[2] = OS_INVALID;

    expect_string(__wrap_wdb_get_agents_by_connection_status, status, AGENT_CS_ACTIVE);
    will_return(__wrap_wdb_get_agents_by_connection_status, array);

    // Alert 1

    wlabel_t *labels_1 = NULL;
    os_calloc(1, sizeof(wlabel_t), labels_1);

    expect_string(__wrap_labels_find, agent_id, "003");
    will_return(__wrap_labels_find, labels_1);

    expect_string(__wrap_labels_get, key, "_wazuh_version");
    will_return(__wrap_labels_get, NULL);

    expect_value(__wrap_wdb_get_agent_info, id, array[0]);
    will_return(__wrap_wdb_get_agent_info, agent_info_array_1);

    will_return(__wrap_Eventinfo_to_jsonstr, strdup(alert_info_1));

    will_return(__wrap_OS_ReadXML, 1);

    will_return(__wrap_OS_GetOneContentforElement, node_1);

    expect_value(__wrap_OS_SendUnix, socket, arq);
    expect_string(__wrap_OS_SendUnix, msg, exec_msg_1);
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 1);

    // Alert 2

    wlabel_t *labels_2 = NULL;
    os_calloc(1, sizeof(wlabel_t), labels_2);

    expect_string(__wrap_labels_find, agent_id, "005");
    will_return(__wrap_labels_find, labels_2);

    expect_string(__wrap_labels_get, key, "_wazuh_version");
    will_return(__wrap_labels_get, NULL);

    expect_value(__wrap_wdb_get_agent_info, id, array[1]);
    will_return(__wrap_wdb_get_agent_info, agent_info_array_2);

    expect_value(__wrap_OS_SendUnix, socket, arq);
    expect_string(__wrap_OS_SendUnix, msg, exec_msg);
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 1);

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_all_agents_success_fail_agt_info1(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;

    data->ar->location = ALL_AGENTS;

    Config.ar = 1;

    int *array = NULL;
    os_malloc(sizeof(int)*3, array);
    array[0] = 3;
    array[1] = 5;
    array[2] = OS_INVALID;

    expect_string(__wrap_wdb_get_agents_by_connection_status, status, AGENT_CS_ACTIVE);
    will_return(__wrap_wdb_get_agents_by_connection_status, array);

    // Alert 1

    wlabel_t *labels_1 = NULL;
    os_calloc(1, sizeof(wlabel_t), labels_1);

    expect_string(__wrap_labels_find, agent_id, "003");
    will_return(__wrap_labels_find, labels_1);

    expect_string(__wrap_labels_get, key, "_wazuh_version");
    will_return(__wrap_labels_get, NULL);

    expect_value(__wrap_wdb_get_agent_info, id, array[0]);
    will_return(__wrap_wdb_get_agent_info, NULL);

    expect_string(__wrap__merror, formatted_msg, "Failed to get agent '3' information from Wazuh DB.");

    // Alert 2

    wlabel_t *labels_2 = NULL;
    os_calloc(1, sizeof(wlabel_t), labels_2);

    expect_string(__wrap_labels_find, agent_id, "005");
    will_return(__wrap_labels_find, labels_2);

    expect_string(__wrap_labels_get, key, "_wazuh_version");
    will_return(__wrap_labels_get, NULL);

    expect_value(__wrap_wdb_get_agent_info, id, array[1]);
    will_return(__wrap_wdb_get_agent_info, NULL);

    expect_string(__wrap__merror, formatted_msg, "Failed to get agent '5' information from Wazuh DB.");

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_specific_agent_success_json(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;

    char *version = "Wazuh v4.2.0";
    data->ar->location = SPECIFIC_AGENT;

    char *exec_msg = "(local_source) [] NNS 002 {\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-analysisd\"},\"command\":\"restart-wazuh0\",\"parameters\":{\"extra_args\":[],\"alert\":[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]}}";
    const char *alert_info = "[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]";
    char *node = NULL;

    os_strdup("node01", node);

    Config.ar = 1;

    wlabel_t *labels = NULL;
    os_calloc(2, sizeof(wlabel_t), labels);

    os_strdup("_wazuh_version", labels[0].key);
    os_strdup(version, labels[0].value);

    expect_string(__wrap_labels_find, agent_id, "002");
    will_return(__wrap_labels_find, labels);

    expect_string(__wrap_labels_get, key, labels->key);
    will_return(__wrap_labels_get, labels->value);

    will_return(__wrap_Eventinfo_to_jsonstr, strdup(alert_info));

    will_return(__wrap_OS_ReadXML, 1);

    will_return(__wrap_OS_GetOneContentforElement, node);

    expect_value(__wrap_OS_SendUnix, socket, arq);
    expect_string(__wrap_OS_SendUnix, msg, exec_msg);
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 1);

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_specific_agent_success_json_wdb(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;

    char *version = "Wazuh v4.2.0";
    data->ar->location = SPECIFIC_AGENT;

    cJSON *agent_info_array = cJSON_CreateArray();
    cJSON *agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info, "version", version);
    cJSON_AddItemToArray(agent_info_array, agent_info);

    char *exec_msg = "(local_source) [] NNS 002 {\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-analysisd\"},\"command\":\"restart-wazuh0\",\"parameters\":{\"extra_args\":[],\"alert\":[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]}}";
    const char *alert_info = "[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]";
    char *node = NULL;

    os_strdup("node01", node);

    Config.ar = 1;

    wlabel_t *labels = NULL;
    os_calloc(1, sizeof(wlabel_t), labels);

    expect_string(__wrap_labels_find, agent_id, "002");
    will_return(__wrap_labels_find, labels);

    expect_string(__wrap_labels_get, key, "_wazuh_version");
    will_return(__wrap_labels_get, NULL);

    expect_value(__wrap_wdb_get_agent_info, id, atoi(data->ar->agent_id));
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

    char *version = "Wazuh v4.0.0";
    data->ar->location = SPECIFIC_AGENT;

    char *exec_msg = "(local_source) [] NNS 002 restart-wazuh0 - - 160987966.80794 554 (ubuntu) any->syscheck /home/vagrant/file/n44.txt -";

    Config.ar = 1;
    __crt_ftell = 80794;

    wlabel_t *labels = NULL;
    os_calloc(2, sizeof(wlabel_t), labels);

    os_strdup("_wazuh_version", labels[0].key);
    os_strdup(version, labels[0].value);

    expect_string(__wrap_labels_find, agent_id, "002");
    will_return(__wrap_labels_find, labels);

    expect_string(__wrap_labels_get, key, labels->key);
    will_return(__wrap_labels_get, labels->value);

    expect_value(__wrap_OS_SendUnix, socket, arq);
    expect_string(__wrap_OS_SendUnix, msg, exec_msg);
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 1);

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_specific_agent_success_string_wdb(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;

    char *version = "Wazuh v4.0.0";
    data->ar->location = SPECIFIC_AGENT;

    cJSON *agent_info_array = cJSON_CreateArray();
    cJSON *agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info, "version", version);
    cJSON_AddItemToArray(agent_info_array, agent_info);

    char *exec_msg = "(local_source) [] NNS 002 restart-wazuh0 - - 160987966.80794 554 (ubuntu) any->syscheck /home/vagrant/file/n44.txt -";

    Config.ar = 1;
    __crt_ftell = 80794;

    wlabel_t *labels = NULL;
    os_calloc(1, sizeof(wlabel_t), labels);

    expect_string(__wrap_labels_find, agent_id, "002");
    will_return(__wrap_labels_find, labels);

    expect_string(__wrap_labels_get, key, "_wazuh_version");
    will_return(__wrap_labels_get, NULL);

    expect_value(__wrap_wdb_get_agent_info, id, atoi(data->ar->agent_id));
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

    data->ar->location = SPECIFIC_AGENT;

    Config.ar = 1;

    wlabel_t *labels = NULL;
    os_calloc(1, sizeof(wlabel_t), labels);

    expect_string(__wrap_labels_find, agent_id, "002");
    will_return(__wrap_labels_find, labels);

    expect_string(__wrap_labels_get, key, "_wazuh_version");
    will_return(__wrap_labels_get, NULL);

    expect_value(__wrap_wdb_get_agent_info, id, atoi(data->ar->agent_id));
    will_return(__wrap_wdb_get_agent_info, NULL);

    expect_string(__wrap__merror, formatted_msg, "Failed to get agent '2' information from Wazuh DB.");

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_remote_agent_success_json(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;

    char *version = "Wazuh v4.2.0";
    data->ar->location = REMOTE_AGENT;

    char *exec_msg = "(local_source) [] NRN 001 {\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-analysisd\"},\"command\":\"restart-wazuh0\",\"parameters\":{\"extra_args\":[],\"alert\":[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]}}";
    const char *alert_info = "[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]";
    char *node = NULL;

    os_strdup("node01", node);

    Config.ar = 1;

    wlabel_t *labels = NULL;
    os_calloc(2, sizeof(wlabel_t), labels);

    os_strdup("_wazuh_version", labels[0].key);
    os_strdup(version, labels[0].value);

    expect_string(__wrap_labels_find, agent_id, "001");
    will_return(__wrap_labels_find, labels);

    expect_string(__wrap_labels_get, key, labels->key);
    will_return(__wrap_labels_get, labels->value);

    expect_value(__wrap_OS_SendUnix, socket, arq);
    expect_string(__wrap_OS_SendUnix, msg, exec_msg);
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 1);

    will_return(__wrap_Eventinfo_to_jsonstr, strdup(alert_info));

    will_return(__wrap_OS_ReadXML, 1);

    will_return(__wrap_OS_GetOneContentforElement, node);

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_remote_agent_success_json_wdb(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;

    char *version = "Wazuh v4.2.0";
    data->ar->location = REMOTE_AGENT;

    cJSON *agent_info_array = cJSON_CreateArray();
    cJSON *agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info, "version", version);
    cJSON_AddItemToArray(agent_info_array, agent_info);

    char *exec_msg = "(local_source) [] NRN 001 {\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-analysisd\"},\"command\":\"restart-wazuh0\",\"parameters\":{\"extra_args\":[],\"alert\":[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]}}";
    const char *alert_info = "[{\"timestamp\":\"2021-01-05T15:23:00.547+0000\",\"rule\":{\"level\":5,\"description\":\"File added to the system.\",\"id\":\"554\"}}]";
    char *node = NULL;

    os_strdup("node01", node);

    Config.ar = 1;

    wlabel_t *labels = NULL;
    os_calloc(1, sizeof(wlabel_t), labels);

    expect_string(__wrap_labels_find, agent_id, "001");
    will_return(__wrap_labels_find, labels);

    expect_string(__wrap_labels_get, key, "_wazuh_version");
    will_return(__wrap_labels_get, NULL);

    expect_value(__wrap_wdb_get_agent_info, id, atoi(data->lf->agent_id));
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

    char *version = "Wazuh v4.0.0";
    data->ar->location = REMOTE_AGENT;

    char *exec_msg = "(local_source) [] NRN 001 restart-wazuh0 - - 160987966.80794 554 (ubuntu) any->syscheck /home/vagrant/file/n44.txt -";

    Config.ar = 1;
    __crt_ftell = 80794;

    wlabel_t *labels = NULL;
    os_calloc(2, sizeof(wlabel_t), labels);

    os_strdup("_wazuh_version", labels[0].key);
    os_strdup(version, labels[0].value);

    expect_string(__wrap_labels_find, agent_id, "001");
    will_return(__wrap_labels_find, labels);

    expect_string(__wrap_labels_get, key, labels->key);
    will_return(__wrap_labels_get, labels->value);

    expect_value(__wrap_OS_SendUnix, socket, arq);
    expect_string(__wrap_OS_SendUnix, msg, exec_msg);
    expect_value(__wrap_OS_SendUnix, size, 0);
    will_return(__wrap_OS_SendUnix, 1);

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_remote_agent_success_string_wdb(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    int execq = 10;
    int arq = 11;

    char *version = "Wazuh v4.0.0";
    data->ar->location = REMOTE_AGENT;

    cJSON *agent_info_array = cJSON_CreateArray();
    cJSON *agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info, "version", version);
    cJSON_AddItemToArray(agent_info_array, agent_info);

    char *exec_msg = "(local_source) [] NRN 001 restart-wazuh0 - - 160987966.80794 554 (ubuntu) any->syscheck /home/vagrant/file/n44.txt -";

    Config.ar = 1;
    __crt_ftell = 80794;

    wlabel_t *labels = NULL;
    os_calloc(1, sizeof(wlabel_t), labels);

    expect_string(__wrap_labels_find, agent_id, "001");
    will_return(__wrap_labels_find, labels);

    expect_string(__wrap_labels_get, key, "_wazuh_version");
    will_return(__wrap_labels_get, NULL);

    expect_value(__wrap_wdb_get_agent_info, id, atoi(data->lf->agent_id));
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

    data->ar->location = REMOTE_AGENT;

    Config.ar = 1;

    wlabel_t *labels = NULL;
    os_calloc(1, sizeof(wlabel_t), labels);

    expect_string(__wrap_labels_find, agent_id, "001");
    will_return(__wrap_labels_find, labels);

    expect_string(__wrap_labels_get, key, "_wazuh_version");
    will_return(__wrap_labels_get, NULL);

    expect_value(__wrap_wdb_get_agent_info, id, atoi(data->lf->agent_id));
    will_return(__wrap_wdb_get_agent_info, NULL);

    expect_string(__wrap__merror, formatted_msg, "Failed to get agent '1' information from Wazuh DB.");

    OS_Exec(execq, &arq, data->lf, data->ar);
}

void test_getActiveResponseInJSON_extra_args(void **state){
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_msj = NULL;

    char msg[OS_SIZE_8192 + 1];
    char *c_device = NULL;
    const char *alert_info = "[{\"test\":\"test\"}]";
    char *extra_args = "-arg1 --arg2 arg3 ; cat /etc/passwd";
    char *result = "[\"-arg1\",\"--arg2\",\"arg3\",\";\",\"cat\",\"/etc/passwd\"]";
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
        // LOCAL
        cmocka_unit_test_setup_teardown(test_server_success_json, test_setup, test_teardown),

        // ALL_AGENTS
        cmocka_unit_test_setup_teardown(test_all_agents_success_json_string, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_all_agents_success_json_string_wdb, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_all_agents_success_fail_agt_info1, test_setup, test_teardown),

        // SPECIFIC_AGENT
        cmocka_unit_test_setup_teardown(test_specific_agent_success_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_specific_agent_success_json_wdb, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_specific_agent_success_string, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_specific_agent_success_string_wdb, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_specific_agent_success_fail_agt_info1, test_setup, test_teardown),

        // REMOTE_AGENT
        cmocka_unit_test_setup_teardown(test_remote_agent_success_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_remote_agent_success_json_wdb, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_remote_agent_success_string, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_remote_agent_success_string_wdb, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_remote_agent_success_fail_agt_info1, test_setup, test_teardown),

        // getActiveResponseInJSON
        cmocka_unit_test_setup_teardown(test_getActiveResponseInJSON_extra_args, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}