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
#include <stdlib.h>

#include "../../headers/shared.h"
#include "../../os_xml/os_xml.h"
#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/wm_gcp.h"
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../../wrappers/wazuh/shared/schedule_scan_wrappers.h"

static const char *XML_ENABLED = "enabled";
static const char *XML_PROJECT_ID = "project_id";
static const char *XML_SUBSCRIPTION_NAME = "subscription_name";
static const char *XML_CREDENTIALS_FILE = "credentials_file";
static const char *XML_MAX_MESSAGES = "max_messages";
static const char *XML_NUM_THREADS = "num_threads";
static const char *XML_PULL_ON_START = "pull_on_start";
static const char *XML_LOGGING = "logging";

static const char *XML_RUN_ON_START = "run_on_start";
static const char *XML_BUCKET = "bucket";
static const char *XML_BUCKET_TYPE = "type";
static const char *XML_BUCKET_NAME = "name";
static const char *XML_PREFIX = "path";
static const char *XML_ONLY_LOGS_AFTER = "only_logs_after";
static const char *XML_REMOVE_FROM_BUCKET = "remove_from_bucket";

static const char *ACCESS_LOGS_BUCKET_TYPE = "access_logs";

typedef struct __group_data_s {
    OS_XML *xml;
    xml_node **nodes;
    wmodule *module;
} group_data_t;

/* Auxiliar functions */
int replace_configuration_value(XML_NODE nodes, const char *tag, const char *new_value) {
    int i;

    if(tag == NULL || nodes == NULL || *nodes == NULL)
        return -1;

    // find the required tag and change it to the new value
    for(i = 0; nodes[i]; i++) {
        if(!strcmp(nodes[i]->element, tag)) {
            os_free(nodes[i]->content);
            if(new_value != NULL){
                nodes[i]->content = strdup(new_value);

                if(nodes[i]->content == NULL)
                    return -1;
            } else {
                nodes[i]->content = NULL;
            }
            return 0;
        }
    }
    // If we got here, the given tag was not found
    return -2;
}

int replace_bucket_configuration_value(group_data_t *data, const char *tag, const char *new_value) {
    int i;
    int j;
    OS_XML *xml = data->xml;
    XML_NODE nodes = data->nodes;
    xml_node **children = NULL;

    if(xml == NULL || tag == NULL || nodes == NULL || *nodes == NULL)
        return -1;

    // find the required tag and change it to the new value
    for(i = 0; nodes[i]; i++) {
        if(!strcmp(nodes[i]->element, "bucket")) {
            if (!(children = OS_GetElementsbyNode(xml, nodes[i])))
                continue;

            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, tag)) {
                    OS_ClearNode(children);
                    OS_ClearNode(data->nodes);
                    os_free(xml->ct[i+j+2])
                    os_strdup(new_value, xml->ct[i+j+2]);
                    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
                        return -1;
                    return 0;
                }
            }
            OS_ClearNode(children);
        }
    }
    // If we got here, the given tag was not found
    return -2;
}

int replace_bucket_configuration_attribute(group_data_t *data, const char *tag, const char *new_value) {
    int i;
    int j;
    OS_XML *xml = data->xml;
    XML_NODE nodes = data->nodes;

    if(xml == NULL || tag == NULL || nodes == NULL || *nodes == NULL)
        return -1;

    // find the required tag and change it to the new value
    for(i = 0; nodes[i]; i++) {
        if(!strcmp(nodes[i]->element, "bucket")) {
            if (strcmp(*nodes[i]->attributes, tag) == 0){
                os_free(xml->ct[i+1])
                os_strdup(new_value, xml->ct[i+1]);
                OS_ClearNode(data->nodes);
                if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
                    return -1;
                return 0;
            }
        }
    }
    // If we got here, the given tag was not found
    return -2;
}

/* setup/teardown */
static int setup_group(void **state) {
    group_data_t *data;
    os_calloc(1, sizeof(group_data_t), data);

    if(data == NULL)
        return -1;

    if(os_calloc(1, sizeof(wmodule), data->module), data->module == NULL)
        return -1;

    if(os_calloc(1, sizeof(OS_XML), data->xml), data->xml == NULL)
        return -1;

    *state = data;

    return 0;
}

static int teardown_group(void **state) {
    group_data_t *data = *state;

    os_free(data->xml);
    os_free(data->module);

    os_free(data);

    return 0;
}

static int setup_test_pubsub(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<pull_on_start>no</pull_on_start>"
                        "<project_id>wazuh-gcp-pubsub-tests</project_id>"
                        "<subscription_name>testing-id</subscription_name>"
                        "<credentials_file>credentials.json</credentials_file>"
                        "<max_messages>100</max_messages>"
                        "<num_threads>2</num_threads>"
                        "<day>15</day>";


    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int setup_test_pubsub_no_project_id(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<pull_on_start>no</pull_on_start>"
                        "<subscription_name>testing-id</subscription_name>"
                        "<credentials_file>credentials.json</credentials_file>"
                        "<max_messages>100</max_messages>"
                        "<num_threads>2</num_threads>"
                        "<day>15</day>";


    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int setup_test_pubsub_no_subscription_name(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<pull_on_start>no</pull_on_start>"
                        "<project_id>wazuh-gcp-pubsub-tests</project_id>"
                        "<credentials_file>credentials.json</credentials_file>"
                        "<max_messages>100</max_messages>"
                        "<num_threads>2</num_threads>"
                        "<day>15</day>";


    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int setup_test_pubsub_no_credentials_file(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<pull_on_start>no</pull_on_start>"
                        "<project_id>wazuh-gcp-pubsub-tests</project_id>"
                        "<subscription_name>testing-id</subscription_name>"
                        "<max_messages>100</max_messages>"
                        "<num_threads>2</num_threads>"
                        "<day>15</day>";


    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int teardown_test_pubsub(void **state) {
    group_data_t *data = *state;
    wm_gcp_pubsub *gcp = data->module->data;

    os_free(data->module->tag);

    if(gcp->project_id) os_free(gcp->project_id);
    if(gcp->subscription_name) os_free(gcp->subscription_name);
    if(gcp->credentials_file) os_free(gcp->credentials_file);

    os_free(gcp);

    data->module->data = NULL;

    OS_ClearXML(data->xml);
    OS_ClearNode(data->nodes);

    return 0;
}

static int setup_test_bucket(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<run_on_start>no</run_on_start>"
                        "<bucket type='access_logs'>"
                          "<name>wazuh-gcp-bucket-tests</name>"
                          "<credentials_file>credentials.json</credentials_file>"
                          "<only_logs_after>2021-JUN-01</only_logs_after>"
                          "<path>access_logs/</path>"
                          "<remove_from_bucket>no</remove_from_bucket>"
                        "</bucket>"
                        "<bucket type='access_logs'>"
                          "<name>wazuh-gcp-bucket-tests-2</name>"
                          "<credentials_file>credentials.json</credentials_file>"
                          "<only_logs_after>2021-JUN-02</only_logs_after>"
                          "<path>access_logs/</path>"
                          "<remove_from_bucket>yes</remove_from_bucket>"
                        "</bucket>"
                        "<bucket></bucket>";

    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int setup_test_no_bucket(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<run_on_start>no</run_on_start>";

    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int setup_test_element_invalid(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<run_on_start>no</run_on_start>"
                        "<bucket type='access_logs'>"
                          "<invalid>wazuh-gcp-bucket-tests</invalid>"
                        "</bucket>";

    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int setup_test_bucket_attribute_invalid(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<run_on_start>no</run_on_start>"
                        "<bucket invalid='access_logs'>"
                          "<name>wazuh-gcp-bucket-tests</name>"
                          "<credentials_file>credentials.json</credentials_file>"
                          "<only_logs_after>2021-JUN-01</only_logs_after>"
                          "<path>access_logs/</path>"
                          "<remove_from_bucket>no</remove_from_bucket>"
                        "</bucket>";

    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int setup_test_bucket_no_bucket(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<run_on_start>no</run_on_start>"
                        "<bucket type='access_logs'>"
                          "<credentials_file>credentials.json</credentials_file>"
                          "<only_logs_after>2021-JUN-01</only_logs_after>"
                          "<path>access_logs/</path>"
                          "<remove_from_bucket>no</remove_from_bucket>"
                        "</bucket>";


    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int setup_test_bucket_no_bucket_type(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<run_on_start>no</run_on_start>"
                        "<bucket>"
                          "<name>wazuh-gcp-bucket-tests</name>"
                          "<credentials_file>credentials.json</credentials_file>"
                          "<only_logs_after>2021-JUN-01</only_logs_after>"
                          "<path>access_logs/</path>"
                          "<remove_from_bucket>no</remove_from_bucket>"
                        "</bucket>";


    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}


static int setup_test_bucket_no_only_logs_after(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<run_on_start>no</run_on_start>"
                        "<bucket type='access_logs'>"
                          "<name>wazuh-gcp-bucket-tests</name>"
                          "<credentials_file>credentials.json</credentials_file>"
                          "<path>access_logs/</path>"
                          "<remove_from_bucket>no</remove_from_bucket>"
                        "</bucket>";


    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int setup_test_bucket_no_credentials_file(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<run_on_start>no</run_on_start>"
                        "<bucket type='access_logs'>"
                          "<name>wazuh-gcp-bucket-tests</name>"
                          "<credentials_file>credentials.json</credentials_file>"
                          "<only_logs_after>2021-JUN-01</only_logs_after>"
                          "<path>access_logs/</path>"
                          "<remove_from_bucket>no</remove_from_bucket>"
                        "</bucket>"
                        "<bucket type='access_logs'>"
                          "<name>wazuh-gcp-bucket-tests</name>"
                          "<only_logs_after>2021-JUN-01</only_logs_after>"
                          "<path>access_logs/</path>"
                          "<remove_from_bucket>no</remove_from_bucket>"
                        "</bucket>";


    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int setup_test_bucket_no_path(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<run_on_start>no</run_on_start>"
                        "<bucket type='access_logs'>"
                          "<name>wazuh-gcp-bucket-tests</name>"
                          "<credentials_file>credentials.json</credentials_file>"
                          "<only_logs_after>2021-JUN-01</only_logs_after>"
                          "<remove_from_bucket>no</remove_from_bucket>"
                        "</bucket>";


    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int setup_test_bucket_no_remove(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<run_on_start>no</run_on_start>"
                        "<bucket type='access_logs'>"
                          "<name>wazuh-gcp-bucket-tests</name>"
                          "<credentials_file>credentials.json</credentials_file>"
                          "<only_logs_after>2021-JUN-01</only_logs_after>"
                          "<path>access_logs/</path>"
                        "</bucket>";


    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int teardown_test_bucket(void **state) {
    group_data_t *data = *state;
    wm_gcp_bucket_base *gcp_config = data->module->data;;
    wm_gcp_bucket *gcp_bucket = gcp_config->buckets;

    os_free(data->module->tag);

    if (gcp_bucket) {
        if (gcp_bucket->next) {
            if (gcp_bucket->next->next) {
                os_free(gcp_bucket->next->next);
            }
            if (gcp_bucket->next->bucket) os_free(gcp_bucket->next->bucket);
            if (gcp_bucket->next->type) os_free(gcp_bucket->next->type);
            if (gcp_bucket->next->credentials_file) os_free(gcp_bucket->next->credentials_file);
            if (gcp_bucket->next->prefix) os_free(gcp_bucket->next->prefix);
            if (gcp_bucket->next->only_logs_after) os_free(gcp_bucket->next->only_logs_after);
            os_free(gcp_bucket->next);
        }
        if (gcp_bucket->bucket) os_free(gcp_bucket->bucket);
        if (gcp_bucket->type) os_free(gcp_bucket->type);
        if (gcp_bucket->credentials_file) os_free(gcp_bucket->credentials_file);
        if (gcp_bucket->prefix) os_free(gcp_bucket->prefix);
        if (gcp_bucket->only_logs_after) os_free(gcp_bucket->only_logs_after);
        os_free(gcp_bucket);
    }
    os_free(gcp_config);

    data->module->data = NULL;

    OS_ClearXML(data->xml);
    OS_ClearNode(data->nodes);

    return 0;
}

/* tests */
/* wm_gcp_pubsub_read */
static void test_wm_gcp_pubsub_read_full_configuration(void **state) {
    group_data_t *data = *state;
    wm_gcp_pubsub *gcp;
    int ret;

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_PUBSUB_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, 0);

    gcp = data->module->data;

    assert_non_null(gcp);
    assert_int_equal(gcp->enabled, 1);
    assert_int_equal(gcp->pull_on_start, 0);
    assert_string_equal(gcp->project_id, "wazuh-gcp-pubsub-tests");
    assert_string_equal(gcp->subscription_name, "testing-id");
    assert_string_equal(gcp->credentials_file, "credentials.json");
    assert_int_equal(gcp->max_messages, 100);
    assert_int_equal(gcp->num_threads, 2);

    assert_ptr_equal(data->module->context, &WM_GCP_PUBSUB_CONTEXT);
    assert_string_equal(data->module->tag, GCP_PUBSUB_WM_NAME);
}

static void test_wm_gcp_pubsub_read_sched_read_invalid(void **state) {
    group_data_t *data = *state;
    wm_gcp_pubsub *gcp;
    int ret;

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_PUBSUB_WM_NAME);
    will_return(__wrap_sched_scan_read, -1);

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, -1);
}

static void test_wm_gcp_pubsub_read_enabled_tag_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_ENABLED, "invalid") != 0)
        fail();

    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'enabled'");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_pubsub_read_project_id_tag_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_PROJECT_ID, "") != 0)
        fail();

    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'project_id' at module 'gcp-pubsub'");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_pubsub_read_no_project_id_tag(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_PUBSUB_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    expect_string(__wrap__merror, formatted_msg, "No value defined for tag 'project_id' in module 'gcp-pubsub'");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_pubsub_read_subscription_name_tag_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_SUBSCRIPTION_NAME, "") != 0)
        fail();

    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'subscription_name' at module 'gcp-pubsub'");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_pubsub_read_no_subscription_name_tag(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_PUBSUB_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    expect_string(__wrap__merror, formatted_msg, "No value defined for tag 'subscription_name' in module 'gcp-pubsub'");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_pubsub_read_credentials_file_full_path(void **state) {
    group_data_t *data = *state;
    wm_gcp_pubsub *gcp;
    int ret;

    if(replace_configuration_value(data->nodes, XML_CREDENTIALS_FILE, "/some/path/credentials.json") != 0)
        fail();

    expect_string(__wrap_IsFile, file, "/some/path/credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_PUBSUB_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, 0);

    gcp = data->module->data;

    assert_non_null(gcp);
    assert_int_equal(gcp->enabled, 1);
    assert_int_equal(gcp->pull_on_start, 0);
    assert_string_equal(gcp->project_id, "wazuh-gcp-pubsub-tests");
    assert_string_equal(gcp->subscription_name, "testing-id");
    assert_string_equal(gcp->credentials_file, "/some/path/credentials.json");
    assert_int_equal(gcp->max_messages, 100);
    assert_int_equal(gcp->num_threads, 2);

    assert_ptr_equal(data->module->context, &WM_GCP_PUBSUB_CONTEXT);
    assert_string_equal(data->module->tag, GCP_PUBSUB_WM_NAME);
}

static void test_wm_gcp_pubsub_read_credentials_file_tag_empty(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_CREDENTIALS_FILE, "") != 0)
        fail();

    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'credentials_file' at module 'gcp-pubsub'");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_pubsub_read_credentials_file_tag_too_long(void **state) {
    group_data_t *data = *state;
    char buffer[OS_MAXSTR];
    int ret;

    memset(buffer, 'a', OS_MAXSTR);
    buffer[OS_MAXSTR - 1] = '\0';

    if(replace_configuration_value(data->nodes, XML_CREDENTIALS_FILE, buffer) != 0)
        fail();

    snprintf(buffer, OS_MAXSTR, "File path is too long. Max path length is %d.", PATH_MAX);
    expect_string(__wrap__merror, formatted_msg, buffer);

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_pubsub_read_credentials_file_tag_realpath_error(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_string(__wrap_realpath, path, "credentials.json");

    will_return(__wrap_realpath, (char *) NULL);   //  realpath failed

    expect_string(__wrap__merror, formatted_msg, "File '' from tag 'credentials_file' not found.");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_pubsub_read_credentials_file_tag_file_not_found(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 1);

    expect_string(__wrap__merror, formatted_msg, "File 'credentials.json' not found. Check your configuration.");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_pubsub_read_no_credentials_file_tag(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_PUBSUB_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    expect_string(__wrap__merror, formatted_msg, "No value defined for tag 'credentials_file' in module 'gcp-pubsub'");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_pubsub_read_max_messages_tag_empty(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_MAX_MESSAGES, "") != 0)
        fail();

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'max_messages'");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_pubsub_read_max_messages_tag_not_digit(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_MAX_MESSAGES, "invalid") != 0)
        fail();

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap__merror, formatted_msg, "Tag 'max_messages' from the 'gcp-pubsub' module should not have an alphabetic character.");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_pubsub_read_num_threads_tag_empty(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_NUM_THREADS, "") != 0)
        fail();

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'num_threads'");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_pubsub_read_num_threads_tag_not_digit(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_NUM_THREADS, "invalid") != 0)
        fail();

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap__merror, formatted_msg, "Tag 'num_threads' from the 'gcp-pubsub' module should not have an alphabetic character.");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_pubsub_read_pull_on_start_tag_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_PULL_ON_START, "invalid") != 0)
        fail();

    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'pull_on_start'");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_pubsub_read_invalid_tag(void **state) {
    group_data_t *data = *state;
    int ret;

    // Make an invalid XML tag element
    os_free(data->nodes[0]->element);

    if(data->nodes[0]->element = strdup("invalid"), data->nodes[0]->element == NULL)
        fail();

    expect_string(__wrap__merror, formatted_msg, "No such tag 'invalid' at module 'gcp-pubsub'.");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, -1);
}

static void test_wm_gcp_pubsub_read_invalid_element(void **state) {
    group_data_t *data = *state;
    int ret;

    // Make an invalid XML tag element
    os_free(data->nodes[0]->element);
    data->nodes[0]->element = NULL;

    expect_string(__wrap__merror, formatted_msg, "(1231): Invalid NULL element in the configuration.");

    ret = wm_gcp_pubsub_read(data->nodes, data->module);

    assert_int_equal(ret, -1);
}

static void test_wm_gcp_pubsub_read_invalid_nodes(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_string(__wrap__merror, formatted_msg, "Empty configuration at module 'gcp-pubsub'.");

    ret = wm_gcp_pubsub_read(NULL, data->module);

    assert_int_equal(ret, -1);
}

/* tests */
/* wm_gcp_pubsub_read */
static void test_wm_gcp_bucket_read_full_configuration(void **state) {
    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);

    group_data_t *data = *state;
    wm_gcp_bucket_base *gcp;

    int ret;

    expect_string_count(__wrap_realpath, path, "credentials.json", 2);
    will_return_count(__wrap_realpath, "credentials.json", 2);

    expect_string_count(__wrap_IsFile, file, "credentials.json", 2);
    will_return_count(__wrap_IsFile, 0, 2);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_BUCKET_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);



    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, 0);

    gcp = data->module->data;

    assert_non_null(gcp);
    assert_int_equal(gcp->enabled, 1);
    assert_int_equal(gcp->run_on_start, 0);
    assert_string_equal(gcp->buckets->bucket, "wazuh-gcp-bucket-tests");
    assert_string_equal(gcp->buckets->only_logs_after, "2021-JUN-01");
    assert_string_equal(gcp->buckets->credentials_file, "credentials.json");
    assert_string_equal(gcp->buckets->prefix, "access_logs/");
    assert_int_equal(gcp->buckets->remove_from_bucket, 0);

    assert_ptr_equal(data->module->context, &WM_GCP_BUCKET_CONTEXT);
    assert_string_equal(data->module->tag, GCP_BUCKET_WM_NAME);
}

static void test_wm_gcp_bucket_read_sched_read_invalid(void **state) {
    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);
    group_data_t *data = *state;
    wm_gcp_bucket_base *gcp;

    int ret;

    expect_string_count(__wrap_realpath, path, "credentials.json", 2);
    will_return_count(__wrap_realpath, "credentials.json", 2);

    expect_string_count(__wrap_IsFile, file, "credentials.json", 2);
    will_return_count(__wrap_IsFile, 0, 2);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_BUCKET_WM_NAME);
    will_return(__wrap_sched_scan_read, -1);

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, -1);
}

static void test_wm_gcp_bucket_read_enabled_tag_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_ENABLED, "invalid") != 0)
        fail();

    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'enabled'");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_no_bucket(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_BUCKET_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    expect_string(__wrap__merror, formatted_msg, "No buckets or services definitions found at module 'gcp-bucket'.");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_no_bucket_type(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);
    expect_string(__wrap__merror, formatted_msg, "No bucket type was specified. The valid one is 'access_logs'.");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}


static void test_wm_gcp_bucket_read_bucket_type_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);

    if(replace_bucket_configuration_attribute(data, XML_BUCKET_TYPE, "") != 0)
        fail();

    expect_string(__wrap__merror, formatted_msg, "Invalid bucket type ''. The valid one is 'access_logs'");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_bucket_element_invalid(void **state) {
    group_data_t *data = *state;
    int ret;
    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);

    expect_string(__wrap__merror, formatted_msg, "No such child tag 'invalid' of bucket at module 'gcp-bucket'.");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_bucket_attribute_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);
    expect_string(__wrap__merror, formatted_msg, "Attribute name 'invalid' is not valid. The valid one is 'type'.");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_bucket_tag_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);

    if(replace_bucket_configuration_value(data, XML_BUCKET_NAME, "") != 0)
        fail();

    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'name' at module 'gcp-bucket'.");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_no_bucket_tag(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap__merror, formatted_msg, "No value defined for tag 'name' in module 'gcp-bucket'.");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_remove_from_bucket_tag_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);

    if(replace_bucket_configuration_value(data, XML_REMOVE_FROM_BUCKET, "") != 0)
        fail();

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'remove_from_bucket' at module 'gcp-bucket'.");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_path_tag_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);

    if(replace_bucket_configuration_value(data, XML_PREFIX, "") != 0)
        fail();

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'path' at module 'gcp-bucket'");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_only_logs_after_tag_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);

    if(replace_bucket_configuration_value(data, XML_ONLY_LOGS_AFTER, "") != 0)
        fail();

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'only_logs_after' at module 'gcp-bucket'");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_credentials_file_full_path(void **state) {
    group_data_t *data = *state;
    wm_gcp_bucket_base *gcp;
    int ret;

    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);

    if(replace_bucket_configuration_value(data, XML_CREDENTIALS_FILE, "/some/path/credentials.json") != 0)
        fail();

    expect_string(__wrap_IsFile, file, "/some/path/credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_BUCKET_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, 0);

    gcp = data->module->data;

    assert_non_null(gcp);
    assert_int_equal(gcp->enabled, 1);
    assert_int_equal(gcp->run_on_start, 0);
    assert_string_equal(gcp->buckets->bucket, "wazuh-gcp-bucket-tests");
    assert_string_equal(gcp->buckets->only_logs_after, "2021-JUN-01");
    assert_string_equal(gcp->buckets->credentials_file, "/some/path/credentials.json");
    assert_string_equal(gcp->buckets->prefix, "access_logs/");
    assert_int_equal(gcp->buckets->remove_from_bucket, 0);

    assert_ptr_equal(data->module->context, &WM_GCP_BUCKET_CONTEXT);
    assert_string_equal(data->module->tag, GCP_BUCKET_WM_NAME);
}

static void test_wm_gcp_bucket_read_credentials_file_tag_empty(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);

    if(replace_bucket_configuration_value(data, XML_CREDENTIALS_FILE, "") != 0)
        fail();

    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'credentials_file' at module 'gcp-bucket'");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_credentials_file_tag_too_long(void **state) {
    group_data_t *data = *state;
    char buffer[OS_MAXSTR + 1] = {0};
    int ret;

    memset(buffer, 'a', OS_MAXSTR);

    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);

    if(replace_bucket_configuration_value(data, XML_CREDENTIALS_FILE, buffer) != 0)
        fail();

    snprintf(buffer, OS_MAXSTR, "File path is too long. Max path length is %d.", PATH_MAX);
    expect_string(__wrap__merror, formatted_msg, buffer);

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_credentials_file_tag_realpath_error(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);

    expect_string(__wrap_realpath, path, "credentials.json");

    will_return(__wrap_realpath, (char *) NULL);   //  realpath failed

    expect_string(__wrap__merror, formatted_msg, "File '' from tag 'credentials_file' not found.");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_credentials_file_tag_file_not_found(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 1);

    expect_string(__wrap__merror, formatted_msg, "File 'credentials.json' not found. Check your configuration.");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_no_credentials_file_tag(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);

    expect_string(__wrap_realpath, path, "credentials.json");
    will_return(__wrap_realpath, "credentials.json");

    expect_string(__wrap_IsFile, file, "credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap__merror, formatted_msg, "No value defined for tag 'credentials_file' in module 'gcp-bucket'.");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_run_on_start_tag_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_RUN_ON_START, "invalid") != 0)
        fail();


    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'run_on_start'");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_bucket_read_invalid_tag(void **state) {
    group_data_t *data = *state;
    int ret;

    // Make an invalid XML tag element
    os_free(data->nodes[0]->element);

    if(data->nodes[0]->element = strdup("invalid"), data->nodes[0]->element == NULL)
        fail();

    expect_string(__wrap__merror, formatted_msg, "No such tag 'invalid' at module 'gcp-bucket'.");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, -1);
}

static void test_wm_gcp_bucket_read_invalid_element(void **state) {
    group_data_t *data = *state;
    int ret;

    // Make an invalid XML tag element
    os_free(data->nodes[0]->element);
    data->nodes[0]->element = NULL;

    expect_string(__wrap__merror, formatted_msg, "(1231): Invalid NULL element in the configuration.");

    ret = wm_gcp_bucket_read(data->xml, data->nodes, data->module);

    assert_int_equal(ret, -1);
}

static void test_wm_gcp_bucket_read_invalid_nodes(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_string(__wrap__merror, formatted_msg, "Empty configuration at module 'gcp-bucket'.");

    ret = wm_gcp_bucket_read(data->xml, NULL, data->module);

    assert_int_equal(ret, -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_full_configuration, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_sched_read_invalid, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_enabled_tag_invalid, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_project_id_tag_invalid, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_no_project_id_tag, setup_test_pubsub_no_project_id, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_subscription_name_tag_invalid, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_no_subscription_name_tag, setup_test_pubsub_no_subscription_name, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_credentials_file_full_path, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_credentials_file_tag_empty, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_credentials_file_tag_too_long, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_credentials_file_tag_realpath_error, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_credentials_file_tag_file_not_found, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_no_credentials_file_tag, setup_test_pubsub_no_credentials_file, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_max_messages_tag_empty, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_max_messages_tag_not_digit, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_num_threads_tag_empty, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_num_threads_tag_not_digit, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_pull_on_start_tag_invalid, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_invalid_tag, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_invalid_element, setup_test_pubsub, teardown_test_pubsub),
        cmocka_unit_test_setup_teardown(test_wm_gcp_pubsub_read_invalid_nodes, setup_test_pubsub, teardown_test_pubsub),

        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_full_configuration, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_sched_read_invalid, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_enabled_tag_invalid, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_no_bucket, setup_test_no_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_bucket_element_invalid, setup_test_element_invalid, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_bucket_type_invalid, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_bucket_attribute_invalid, setup_test_bucket_attribute_invalid, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_no_bucket_type, setup_test_bucket_no_bucket_type, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_bucket_tag_invalid, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_no_bucket_tag, setup_test_bucket_no_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_remove_from_bucket_tag_invalid, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_path_tag_invalid, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_only_logs_after_tag_invalid, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_credentials_file_full_path, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_credentials_file_tag_empty, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_credentials_file_tag_too_long, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_credentials_file_tag_realpath_error, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_credentials_file_tag_file_not_found, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_no_credentials_file_tag, setup_test_bucket_no_credentials_file, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_run_on_start_tag_invalid, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_invalid_tag, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_invalid_element, setup_test_bucket, teardown_test_bucket),
        cmocka_unit_test_setup_teardown(test_wm_gcp_bucket_read_invalid_nodes, setup_test_bucket, teardown_test_bucket),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
