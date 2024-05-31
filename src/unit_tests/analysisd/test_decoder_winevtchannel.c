/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

#include "../../config/global-config.h"
#include "../../analysisd/eventinfo.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/os_xml/os_xml_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"

#define TEST_AGENT_ID   "005"
#define TEST_TIME       10005
#define TEST_LOG_STRING "Test log string File 'file_name'"

#define FAIL_DECODE    1
#define SUCCESS_DECODE 0

extern int DecodeWinevt(Eventinfo * lf);
extern void w_free_event_info(Eventinfo * lf);
extern _Config Config;

int test_setup_global(void ** state) {
    expect_string(__wrap__mdebug1, formatted_msg, "WinevtInit completed.");
    Config.decoder_order_size = 32;
    WinevtInit();
    return 0;
}

int test_setup(void ** state) {
    Eventinfo * lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    os_strdup(TEST_AGENT_ID, lf->agent_id);
    os_strdup(TEST_LOG_STRING, lf->full_log);
    lf->log = lf->full_log;
    lf->time.tv_sec = (time_t) TEST_TIME;

    *state = lf;

    return 0;
}

int test_cleanup(void ** state) {
    Eventinfo * lf = *state;

    w_free_event_info(lf);
    return 0;
}

// TODO move
void * __wrap_JSON_Decoder_Exec(Eventinfo * lf, __attribute__((unused)) regex_matching * decoder_match) {
    function_called();
    return (void *) NULL;
}

void initDec() {
    will_return(__wrap_cJSON_CreateObject, (void *) 0x1); // final_event
    will_return(__wrap_cJSON_CreateObject, (void *) 0x1); // json_event
    will_return(__wrap_cJSON_CreateObject, (void *) 0x1); // json_system_in
    will_return(__wrap_cJSON_CreateObject, (void *) 0x0); // json_eventdata_in TODO Change this to 0x1
    will_return(__wrap_cJSON_CreateObject, (void *) 0x1); // json_extra_in
}

void cleanDec(bool deleteXML) {
    if (deleteXML) {
        expect_function_call(__wrap_OS_ClearXML);
    }
    expect_function_call(__wrap_cJSON_Delete);
    expect_function_call(__wrap_cJSON_Delete);
}

void test_winevt_json_parseFail(void ** state) {
    Eventinfo * lf = *state;
    initDec();

    // Fail in parsing the JSON
    will_return(__wrap_cJSON_ParseWithOpts, "a json error");
    will_return(__wrap_cJSON_ParseWithOpts, NULL);
    expect_string(__wrap__merror, formatted_msg, "Malformed EventChannel JSON event.");

    expect_function_call(__wrap_cJSON_Delete);
    expect_function_call(__wrap_cJSON_Delete);
    expect_function_call(__wrap_cJSON_Delete);
    expect_function_call(__wrap_cJSON_Delete);

    cleanDec(false);

    int ret = DecodeWinevt(lf);
    assert_int_equal(ret, FAIL_DECODE);
}

void test_winevt_json_notEvent(void ** state) {
    Eventinfo * lf = *state;
    initDec();

    // parse ok
    will_return(__wrap_cJSON_ParseWithOpts, (char *) 0x1);
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 0x1);

    // Event not found in JSON
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Malformed JSON received. No 'Event' field found.");

    expect_function_call(__wrap_cJSON_Delete); // Delete json_event
    expect_function_call(__wrap_cJSON_Delete); // Delete json_system_in
    expect_function_call(__wrap_cJSON_Delete); // Delete json_eventdata_in
    expect_function_call(__wrap_cJSON_Delete); // Delete json_extra_in

    cleanDec(false);

    int ret = DecodeWinevt(lf);
    assert_int_equal(ret, FAIL_DECODE);
}

void test_winevt_failXML_parse(void ** state) {
    Eventinfo * lf = *state;
    initDec();

    // parse ok
    will_return(__wrap_cJSON_ParseWithOpts, (char *) 0x1);
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 0x1);

    /********************** EVENT ***********************/
    // Get event

    cJSON event = {0};
    event.valuestring = strdup("test");
    will_return(__wrap_cJSON_GetObjectItem, &event);

    // Fail read xml
    will_return(__wrap_OS_ReadXMLString, -1);
    will_return(__wrap_OS_ReadXMLString, "unknown");
    will_return(__wrap_OS_ReadXMLString, 5);
    expect_string(__wrap__mwarn, formatted_msg, "Could not read XML string: 'test'");

    /********************** Message ***********************/
    // Fail get message
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_PrintUnformatted, NULL);

    expect_function_call(__wrap_cJSON_AddItemToObject); // json_system_in
    will_return(__wrap_cJSON_AddItemToObject, true);

    // json_eventdata_in

    // json_extra_in
    expect_function_call(__wrap_cJSON_Delete); // Delete

    /********************** Final event *********************/
    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);
    will_return(__wrap_cJSON_PrintUnformatted, (char *) strdup("test"));

    expect_function_call(__wrap_JSON_Decoder_Exec);

    cleanDec(false);

    int ret = DecodeWinevt(lf);
    assert_int_equal(ret, SUCCESS_DECODE);
    os_free(event.valuestring);
}

void test_winevt_dec_systemNode_ok(void ** state) {
    Eventinfo * lf = *state;
    initDec();

    // parse ok
    will_return(__wrap_cJSON_ParseWithOpts, (char *) 0x1);
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 0x1);

    /********************** EVENT ***********************/
    // Get event

    cJSON event = {0};
    event.valuestring = strdup("test");
    will_return(__wrap_cJSON_GetObjectItem, &event);

    // Read xml ok
    will_return(__wrap_OS_ReadXMLString, 0);

    XML_NODE root_node; // <Event> </Event>
    os_calloc(2, sizeof(xml_node *), root_node);
    os_calloc(1, sizeof(xml_node), root_node[0]);
    os_strdup("event", root_node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, root_node);

    XML_NODE system_root; // <System> </System>
    os_calloc(2, sizeof(xml_node *), system_root);
    os_calloc(1, sizeof(xml_node), system_root[0]);
    os_strdup("System", system_root[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, system_root);

    // Chill of system
    XML_NODE system_chill;
    os_calloc(9, sizeof(xml_node *), system_chill);
    os_calloc(1, sizeof(xml_node), system_chill[0]); // provider
    os_calloc(1, sizeof(xml_node), system_chill[1]); // TimeCreated
    os_calloc(1, sizeof(xml_node), system_chill[2]); // Execution
    os_calloc(1, sizeof(xml_node), system_chill[3]); // Channel
    os_calloc(1, sizeof(xml_node), system_chill[4]); // Security
    os_calloc(1, sizeof(xml_node), system_chill[5]); // Level
    os_calloc(1, sizeof(xml_node), system_chill[6]); // Keywords
    os_calloc(1, sizeof(xml_node), system_chill[7]); // Other fields

    will_return(__wrap_OS_GetElementsbyNode, system_chill);

    // Provider node
    xml_node * providerNode = system_chill[0];
    os_strdup("Provider", providerNode->element);

    os_calloc(4, sizeof(char *), providerNode->attributes);
    os_calloc(4, sizeof(char *), providerNode->values);

    os_strdup("Name", providerNode->attributes[0]);
    os_strdup("Guid", providerNode->attributes[1]);
    os_strdup("EventSourceName", providerNode->attributes[2]);

    os_strdup("value name", providerNode->values[0]);
    os_strdup("value guid", providerNode->values[1]);
    os_strdup("value event source name", providerNode->values[2]);

    expect_string(__wrap_cJSON_AddStringToObject, name, "providerName");
    expect_string(__wrap_cJSON_AddStringToObject, string, "value name");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "providerGuid");
    expect_string(__wrap_cJSON_AddStringToObject, string, "value guid");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "eventSourceName");
    expect_string(__wrap_cJSON_AddStringToObject, string, "value event source name");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    // TimeCreated node
    xml_node * timeCreatedNode = system_chill[1];
    os_strdup("TimeCreated", timeCreatedNode->element);

    os_calloc(2, sizeof(char *), timeCreatedNode->attributes);
    os_calloc(2, sizeof(char *), timeCreatedNode->values);

    os_strdup("SystemTime", timeCreatedNode->attributes[0]);
    os_strdup("time value", timeCreatedNode->values[0]);

    expect_string(__wrap_cJSON_AddStringToObject, name, "systemTime");
    expect_string(__wrap_cJSON_AddStringToObject, string, "time value");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    // Execution node
    xml_node * executionNode = system_chill[2];
    os_strdup("Execution", executionNode->element);

    os_calloc(3, sizeof(char *), executionNode->attributes);
    os_calloc(3, sizeof(char *), executionNode->values);

    os_strdup("ProcessID", executionNode->attributes[0]);
    os_strdup("ThreadID", executionNode->attributes[1]);

    os_strdup("process id value", executionNode->values[0]);
    os_strdup("thread id value", executionNode->values[1]);

    expect_string(__wrap_cJSON_AddStringToObject, name, "processID");
    expect_string(__wrap_cJSON_AddStringToObject, string, "process id value");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    expect_string(__wrap_cJSON_AddStringToObject, name, "threadID");
    expect_string(__wrap_cJSON_AddStringToObject, string, "thread id value");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    // Channel node
    xml_node * channelNode = system_chill[3];
    os_strdup("Channel", channelNode->element);
    os_strdup("Channel/name", channelNode->content);

    expect_string(__wrap_cJSON_AddStringToObject, name, "channel");
    expect_string(__wrap_cJSON_AddStringToObject, string, "Channel/name");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    os_calloc(2, sizeof(char *), channelNode->attributes);
    os_calloc(2, sizeof(char *), channelNode->values);

    os_strdup("useridAttr", channelNode->attributes[0]);
    os_strdup("UserID", channelNode->values[0]);
    // TODO Fix this should be the attribute value
    expect_string(__wrap_cJSON_AddStringToObject, name, "userID");
    expect_string(__wrap_cJSON_AddStringToObject, string, "UserID");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    // Security node
    xml_node * securityNode = system_chill[4];
    os_strdup("Security", securityNode->element);

    os_calloc(2, sizeof(char *), securityNode->attributes);
    os_calloc(2, sizeof(char *), securityNode->values);

    os_strdup("useridAttr", securityNode->attributes[0]);
    os_strdup("UserID", securityNode->values[0]);

    expect_string(__wrap_cJSON_AddStringToObject, name, "securityUserID");
    expect_string(__wrap_cJSON_AddStringToObject, string, "UserID");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    // Level
    xml_node * levelNode = system_chill[5];

    os_strdup("Level", levelNode->element);
    os_strdup("info/warn/error", levelNode->content);

    expect_string(__wrap_cJSON_AddStringToObject, name, "level");
    expect_string(__wrap_cJSON_AddStringToObject, string, "info/warn/error");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    // Keywords
    xml_node * keywordsNode = system_chill[6];

    os_strdup("Keywords", keywordsNode->element);
    os_strdup("keyword1/keyword2", keywordsNode->content);

    expect_string(__wrap_cJSON_AddStringToObject, name, "keywords");
    expect_string(__wrap_cJSON_AddStringToObject, string, "keyword1/keyword2");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    // Other fields
    xml_node * otherFieldsNode = system_chill[7];

    os_strdup("OtherFields", otherFieldsNode->element);
    os_strdup("other field value", otherFieldsNode->content);

    expect_string(__wrap_cJSON_AddStringToObject, name, "otherFields");
    expect_string(__wrap_cJSON_AddStringToObject, string, "other field value");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    /*********** Message [level && keywords] **************/
    expect_string(__wrap_cJSON_AddStringToObject, name, "severityValue");
    expect_string(__wrap_cJSON_AddStringToObject, string, "UNKNOWN");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    /********************** Message ***********************/
    // Fail get message
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_PrintUnformatted, NULL);

    expect_function_call(__wrap_cJSON_AddItemToObject); // json_system_in
    will_return(__wrap_cJSON_AddItemToObject, true);

    // json_eventdata_in

    // json_extra_in
    expect_function_call(__wrap_cJSON_Delete); // Delete

    /********************** Final event *********************/
    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);
    will_return(__wrap_cJSON_PrintUnformatted, (char *) strdup("test"));

    expect_function_call(__wrap_JSON_Decoder_Exec);

    cleanDec(false);

    int ret = DecodeWinevt(lf);
    assert_int_equal(ret, SUCCESS_DECODE);
    os_free(event.valuestring);
}

void test_winevt_dec_eventDataNode_ok(void ** state) {
    Eventinfo * lf = *state;
    initDec();

    // parse ok
    will_return(__wrap_cJSON_ParseWithOpts, (char *) 0x1);
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 0x1);

    /********************** EVENT ***********************/
    // Get event

    cJSON event = {0};
    event.valuestring = strdup("test");
    will_return(__wrap_cJSON_GetObjectItem, &event);

    // Read xml ok
    will_return(__wrap_OS_ReadXMLString, 0);

    XML_NODE root_node; // <Event> </Event>
    os_calloc(2, sizeof(xml_node *), root_node);
    os_calloc(1, sizeof(xml_node), root_node[0]);
    os_strdup("event", root_node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, root_node);

    XML_NODE eventdata_root; // <eventData> </eventData>
    os_calloc(2, sizeof(xml_node *), eventdata_root);
    os_calloc(1, sizeof(xml_node), eventdata_root[0]);
    os_strdup("EventData", eventdata_root[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, eventdata_root);

    // Chill of eventData
    XML_NODE eventdata_chill;
    os_calloc(4, sizeof(xml_node *), eventdata_chill);
    os_calloc(1, sizeof(xml_node), eventdata_chill[0]); // Data 1
    os_calloc(1, sizeof(xml_node), eventdata_chill[1]); // Data 2
    os_calloc(1, sizeof(xml_node), eventdata_chill[2]); // Data 3
    // os_calloc(1, sizeof(xml_node), eventdata_chill[3]); // Data 4

    will_return(__wrap_OS_GetElementsbyNode, eventdata_chill);

    // Data 1 node
    xml_node * data_1_node = eventdata_chill[0];
    os_strdup("Data", data_1_node->element);
    os_strdup("content", data_1_node->content);

    os_calloc(2, sizeof(char *), data_1_node->attributes);
    os_calloc(2, sizeof(char *), data_1_node->values);

    os_strdup("Name", data_1_node->attributes[0]);
    os_strdup("categoryId", data_1_node->values[0]);

    expect_string(__wrap_cJSON_AddStringToObject, name, "categoryId");
    expect_string(__wrap_cJSON_AddStringToObject, string, "content");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    // Data 2 node
    xml_node * data_2_node = eventdata_chill[1];
    os_strdup("Data", data_2_node->element);
    os_strdup("content", data_2_node->content);

    os_calloc(2, sizeof(char *), data_2_node->attributes);
    os_calloc(2, sizeof(char *), data_2_node->values);

    os_strdup("Name", data_2_node->attributes[0]);
    os_strdup("subcategoryId", data_2_node->values[0]);

    expect_string(__wrap_cJSON_AddStringToObject, name, "subcategoryId");
    expect_string(__wrap_cJSON_AddStringToObject, string, "content");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    // Data 3 node
    xml_node * data_3_node = eventdata_chill[2];
    os_strdup("Data", data_3_node->element);
    os_strdup("%%8451", data_3_node->content);

    os_calloc(2, sizeof(char *), data_3_node->attributes);
    os_calloc(2, sizeof(char *), data_3_node->values);

    os_strdup("Name", data_3_node->attributes[0]);
    os_strdup("auditPolicyChanges", data_3_node->values[0]);

    expect_string(__wrap_cJSON_AddStringToObject, name, "auditPolicyChangesId");
    expect_string(__wrap_cJSON_AddStringToObject, string, "%%8451");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    /******** Message [auditPolicyChangesId] **************/

    expect_string(__wrap_cJSON_AddStringToObject, name, "auditPolicyChanges");
    expect_string(__wrap_cJSON_AddStringToObject, string, "Failure added");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    /********************** Message ***********************/
    // Fail get message
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_PrintUnformatted, NULL);

    expect_function_call(__wrap_cJSON_AddItemToObject); // json_system_in
    will_return(__wrap_cJSON_AddItemToObject, true);

    // json_eventdata_in

    // json_extra_in
    expect_function_call(__wrap_cJSON_Delete); // Delete

    /********************** Final event *********************/
    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);
    will_return(__wrap_cJSON_PrintUnformatted, (char *) strdup("test"));

    expect_function_call(__wrap_JSON_Decoder_Exec);

    cleanDec(false);

    int ret = DecodeWinevt(lf);
    assert_int_equal(ret, SUCCESS_DECODE);
    os_free(event.valuestring);
}

void test_winevt_dec_long_log_ok(void ** state) {
    Eventinfo * lf = *state;
    initDec();

    // parse ok
    will_return(__wrap_cJSON_ParseWithOpts, (char *) 0x1);
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 0x1);

    /********************** EVENT ***********************/
    // Get event
    cJSON event = {0};
    event.valuestring = strdup("test");
    will_return(__wrap_cJSON_GetObjectItem, &event);

    // Read xml ok
    will_return(__wrap_OS_ReadXMLString, 0);

    XML_NODE root_node; // <Event> </Event>
    os_calloc(2, sizeof(xml_node *), root_node);
    os_calloc(1, sizeof(xml_node), root_node[0]);
    os_strdup("event", root_node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, root_node);

    XML_NODE eventdata_root; // <eventData> </eventData>
    os_calloc(2, sizeof(xml_node *), eventdata_root);
    os_calloc(1, sizeof(xml_node), eventdata_root[0]);
    os_strdup("EventData", eventdata_root[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, eventdata_root);

    // Chill of eventData
    XML_NODE eventdata_chill;
    os_calloc(2, sizeof(xml_node *), eventdata_chill);
    os_calloc(1, sizeof(xml_node), eventdata_chill[0]); // Data 1

    will_return(__wrap_OS_GetElementsbyNode, eventdata_chill);

    // Data 1 node
    xml_node * data_1_node = eventdata_chill[0];
    os_strdup("Data", data_1_node->element);
    os_strdup("content", data_1_node->content);

    os_calloc(2, sizeof(char *), data_1_node->attributes);
    os_calloc(2, sizeof(char *), data_1_node->values);

    os_strdup("Name", data_1_node->attributes[0]);
    os_strdup("categoryId", data_1_node->values[0]);

    expect_string(__wrap_cJSON_AddStringToObject, name, "categoryId");
    expect_string(__wrap_cJSON_AddStringToObject, string, "content");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *) 1);

    /********************** Message ***********************/
    // Fail get message
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_PrintUnformatted, NULL);

    expect_function_call(__wrap_cJSON_AddItemToObject); // json_system_in
    will_return(__wrap_cJSON_AddItemToObject, true);

    // json_extra_in
    expect_function_call(__wrap_cJSON_Delete); // Delete

    /********************** Final event *********************/

    size_t long_log_size = strlen(lf->full_log) + 1;
    // Create a long log string (5 times the size of the original)
    char * long_log = (char *) calloc(long_log_size * 5, sizeof(char));
    for (int i = 0; i < 5; i++) {
        strcat(long_log, lf->full_log);
    }

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);
    will_return(__wrap_cJSON_PrintUnformatted, (char *) long_log);

    expect_function_call(__wrap_JSON_Decoder_Exec);

    cleanDec(false);

    int ret = DecodeWinevt(lf);
    assert_int_equal(ret, SUCCESS_DECODE);
    os_free(event.valuestring);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_winevt_json_parseFail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_json_notEvent, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_failXML_parse, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_dec_systemNode_ok, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_dec_eventDataNode_ok, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_dec_long_log_ok, test_setup, test_cleanup),
        //
    };
    return cmocka_run_group_tests(tests, test_setup_global, NULL);
}
