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
static const char *XML_PULL_ON_START = "pull_on_start";
static const char *XML_LOGGING = "logging";

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
            free(nodes[i]->content);
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

/* setup/teardown */
static int setup_group(void **state) {
    group_data_t *data = calloc(1, sizeof(group_data_t));

    if(data == NULL)
        return -1;

    if(data->module = calloc(1, sizeof(wmodule)), data->module == NULL)
        return -1;

    if(data->xml = calloc(1, sizeof(OS_XML)), data->xml == NULL)
        return -1;

    *state = data;

    return 0;
}

static int teardown_group(void **state) {
    group_data_t *data = *state;

    free(data->xml);
    free(data->module);

    free(data);

    return 0;
}

static int setup_test(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<pull_on_start>no</pull_on_start>"
                        "<project_id>wazuh-gcp-pubsub-tests</project_id>"
                        "<subscription_name>testing-id</subscription_name>"
                        "<credentials_file>credentials.json</credentials_file>"
                        "<logging>disabled</logging>"
                        "<max_messages>100</max_messages>"
                        "<day>15</day>";


    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int setup_test_no_project_id(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<pull_on_start>no</pull_on_start>"
                        "<subscription_name>testing-id</subscription_name>"
                        "<credentials_file>credentials.json</credentials_file>"
                        "<logging>disabled</logging>"
                        "<max_messages>100</max_messages>"
                        "<day>15</day>";


    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int setup_test_no_subscription_name(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<pull_on_start>no</pull_on_start>"
                        "<project_id>wazuh-gcp-pubsub-tests</project_id>"
                        "<credentials_file>credentials.json</credentials_file>"
                        "<logging>disabled</logging>"
                        "<max_messages>100</max_messages>"
                        "<day>15</day>";


    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int setup_test_no_credentials_file(void **state) {
    group_data_t *data = *state;
    char *base_config = "<enabled>yes</enabled>"
                        "<pull_on_start>no</pull_on_start>"
                        "<project_id>wazuh-gcp-pubsub-tests</project_id>"
                        "<subscription_name>testing-id</subscription_name>"
                        "<logging>disabled</logging>"
                        "<max_messages>100</max_messages>"
                        "<day>15</day>";


    if(OS_ReadXMLString(base_config, data->xml) != 0){
        return -1;
    }

    if(data->nodes = OS_GetElementsbyNode(data->xml, NULL), data->nodes == NULL)
        return -1;

    return 0;
}

static int teardown_test(void **state) {
    group_data_t *data = *state;
    wm_gcp *gcp = data->module->data;

    free(data->module->tag);

    if(gcp->project_id) free(gcp->project_id);
    if(gcp->subscription_name) free(gcp->subscription_name);
    if(gcp->credentials_file) free(gcp->credentials_file);

    free(gcp);

    data->module->data = NULL;

    OS_ClearXML(data->xml);
    OS_ClearNode(data->nodes);

    return 0;
}

/* tests */
/* wm_gcp_read */
static void test_wm_gcp_read_full_configuration(void **state) {
    group_data_t *data = *state;
    wm_gcp *gcp;
    int ret;

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);   //  realpath did not fail

    expect_string(__wrap_IsFile, file, "/var/ossec/credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, 0);

    gcp = data->module->data;

    assert_non_null(gcp);
    assert_int_equal(gcp->enabled, 1);
    assert_int_equal(gcp->pull_on_start, 0);
    assert_string_equal(gcp->project_id, "wazuh-gcp-pubsub-tests");
    assert_string_equal(gcp->subscription_name, "testing-id");
    assert_string_equal(gcp->credentials_file, "/var/ossec/credentials.json");
    assert_int_equal(gcp->logging, 0);
    assert_int_equal(gcp->max_messages, 100);

    assert_ptr_equal(data->module->context, &WM_GCP_CONTEXT);
    assert_string_equal(data->module->tag, GCP_WM_NAME);
}

static void test_wm_gcp_read_enabled_tag_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_ENABLED, "invalid") != 0)
        fail();

    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'enabled'");

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_read_project_id_tag_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_PROJECT_ID, "") != 0)
        fail();

    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'project_id' at module 'gcp-pubsub'");

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_read_no_project_id_tag(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);   //  realpath did not fail

    expect_string(__wrap_IsFile, file, "/var/ossec/credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    expect_string(__wrap__merror, formatted_msg, "No value defined for tag 'project_id' in module 'gcp-pubsub'");

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_read_subscription_name_tag_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_SUBSCRIPTION_NAME, "") != 0)
        fail();

    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'subscription_name' at module 'gcp-pubsub'");

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_read_no_subscription_name_tag(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);   //  realpath did not fail

    expect_string(__wrap_IsFile, file, "/var/ossec/credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    expect_string(__wrap__merror, formatted_msg, "No value defined for tag 'subscription_name' in module 'gcp-pubsub'");

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_read_credentials_file_full_path(void **state) {
    group_data_t *data = *state;
    wm_gcp *gcp;
    int ret;

    if(replace_configuration_value(data->nodes, XML_CREDENTIALS_FILE, "/some/path/credentials.json") != 0)
        fail();

    expect_string(__wrap_IsFile, file, "/some/path/credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, 0);

    gcp = data->module->data;

    assert_non_null(gcp);
    assert_int_equal(gcp->enabled, 1);
    assert_int_equal(gcp->pull_on_start, 0);
    assert_string_equal(gcp->project_id, "wazuh-gcp-pubsub-tests");
    assert_string_equal(gcp->subscription_name, "testing-id");
    assert_string_equal(gcp->credentials_file, "/some/path/credentials.json");
    assert_int_equal(gcp->logging, 0);
    assert_int_equal(gcp->max_messages, 100);

    assert_ptr_equal(data->module->context, &WM_GCP_CONTEXT);
    assert_string_equal(data->module->tag, GCP_WM_NAME);
}

static void test_wm_gcp_read_credentials_file_tag_empty(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_CREDENTIALS_FILE, "") != 0)
        fail();

    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'credentials_file' at module 'gcp-pubsub'");

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_read_credentials_file_tag_too_long(void **state) {
    group_data_t *data = *state;
    char buffer[OS_MAXSTR];
    int ret;

    memset(buffer, 'a', OS_MAXSTR);
    buffer[OS_MAXSTR] = '\0';

    if(replace_configuration_value(data->nodes, XML_CREDENTIALS_FILE, buffer) != 0)
        fail();

    snprintf(buffer, OS_MAXSTR, "File path is too long. Max path length is %d.", PATH_MAX);
    expect_string(__wrap__merror, formatted_msg, buffer);

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_read_credentials_file_tag_realpath_error(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) NULL);   //  realpath failed

    expect_string(__wrap__mwarn, formatted_msg, "File '/var/ossec/credentials.json' from tag 'credentials_file' not found.");

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_read_credentials_file_tag_file_not_found(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);   //  realpath did not fail

    expect_string(__wrap_IsFile, file, "/var/ossec/credentials.json");
    will_return(__wrap_IsFile, 1);

    expect_string(__wrap__mwarn, formatted_msg, "File '/var/ossec/credentials.json' not found. Check your configuration.");

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_read_no_credentials_file_tag(void **state) {
    group_data_t *data = *state;
    int ret;

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    expect_string(__wrap__merror, formatted_msg, "No value defined for tag 'credentials_file' in module 'gcp-pubsub'");

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_read_max_messages_tag_empty(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_MAX_MESSAGES, "") != 0)
        fail();

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);   //  realpath did not fail

    expect_string(__wrap_IsFile, file, "/var/ossec/credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'max_messages'");

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_read_max_messages_tag_not_digit(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_MAX_MESSAGES, "invalid") != 0)
        fail();

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);   //  realpath did not fail

    expect_string(__wrap_IsFile, file, "/var/ossec/credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap__merror, formatted_msg, "Tag 'max_messages' from the 'gcp-pubsub' module should not have an alphabetic character.");

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}
static void test_wm_gcp_read_pull_on_start_tag_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_PULL_ON_START, "invalid") != 0)
        fail();

    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'pull_on_start'");

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_read_logging_tag_debug(void **state) {
    group_data_t *data = *state;
    wm_gcp *gcp;
    int ret;

    if(replace_configuration_value(data->nodes, XML_LOGGING, "debug") != 0)
        fail();

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);   //  realpath did not fail

    expect_string(__wrap_IsFile, file, "/var/ossec/credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, 0);

    gcp = data->module->data;

    assert_non_null(gcp);
    assert_int_equal(gcp->enabled, 1);
    assert_int_equal(gcp->pull_on_start, 0);
    assert_string_equal(gcp->project_id, "wazuh-gcp-pubsub-tests");
    assert_string_equal(gcp->subscription_name, "testing-id");
    assert_string_equal(gcp->credentials_file, "/var/ossec/credentials.json");
    assert_int_equal(gcp->logging, 1);
    assert_int_equal(gcp->max_messages, 100);

    assert_ptr_equal(data->module->context, &WM_GCP_CONTEXT);
    assert_string_equal(data->module->tag, GCP_WM_NAME);
}

static void test_wm_gcp_read_logging_tag_info(void **state) {
    group_data_t *data = *state;
    wm_gcp *gcp;
    int ret;

    if(replace_configuration_value(data->nodes, XML_LOGGING, "info") != 0)
        fail();

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);   //  realpath did not fail

    expect_string(__wrap_IsFile, file, "/var/ossec/credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, 0);

    gcp = data->module->data;

    assert_non_null(gcp);
    assert_int_equal(gcp->enabled, 1);
    assert_int_equal(gcp->pull_on_start, 0);
    assert_string_equal(gcp->project_id, "wazuh-gcp-pubsub-tests");
    assert_string_equal(gcp->subscription_name, "testing-id");
    assert_string_equal(gcp->credentials_file, "/var/ossec/credentials.json");
    assert_int_equal(gcp->logging, 2);
    assert_int_equal(gcp->max_messages, 100);

    assert_ptr_equal(data->module->context, &WM_GCP_CONTEXT);
    assert_string_equal(data->module->tag, GCP_WM_NAME);
}

static void test_wm_gcp_read_logging_tag_warning(void **state) {
    group_data_t *data = *state;
    wm_gcp *gcp;
    int ret;

    if(replace_configuration_value(data->nodes, XML_LOGGING, "warning") != 0)
        fail();

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);   //  realpath did not fail

    expect_string(__wrap_IsFile, file, "/var/ossec/credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, 0);

    gcp = data->module->data;

    assert_non_null(gcp);
    assert_int_equal(gcp->enabled, 1);
    assert_int_equal(gcp->pull_on_start, 0);
    assert_string_equal(gcp->project_id, "wazuh-gcp-pubsub-tests");
    assert_string_equal(gcp->subscription_name, "testing-id");
    assert_string_equal(gcp->credentials_file, "/var/ossec/credentials.json");
    assert_int_equal(gcp->logging, 3);
    assert_int_equal(gcp->max_messages, 100);

    assert_ptr_equal(data->module->context, &WM_GCP_CONTEXT);
    assert_string_equal(data->module->tag, GCP_WM_NAME);
}

static void test_wm_gcp_read_logging_tag_error(void **state) {
    group_data_t *data = *state;
    wm_gcp *gcp;
    int ret;

    if(replace_configuration_value(data->nodes, XML_LOGGING, "error") != 0)
        fail();

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);   //  realpath did not fail

    expect_string(__wrap_IsFile, file, "/var/ossec/credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, 0);

    gcp = data->module->data;

    assert_non_null(gcp);
    assert_int_equal(gcp->enabled, 1);
    assert_int_equal(gcp->pull_on_start, 0);
    assert_string_equal(gcp->project_id, "wazuh-gcp-pubsub-tests");
    assert_string_equal(gcp->subscription_name, "testing-id");
    assert_string_equal(gcp->credentials_file, "/var/ossec/credentials.json");
    assert_int_equal(gcp->logging, 4);
    assert_int_equal(gcp->max_messages, 100);

    assert_ptr_equal(data->module->context, &WM_GCP_CONTEXT);
    assert_string_equal(data->module->tag, GCP_WM_NAME);
}

static void test_wm_gcp_read_logging_tag_critical(void **state) {
    group_data_t *data = *state;
    wm_gcp *gcp;
    int ret;

    if(replace_configuration_value(data->nodes, XML_LOGGING, "critical") != 0)
        fail();

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);   //  realpath did not fail

    expect_string(__wrap_IsFile, file, "/var/ossec/credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_value(__wrap_sched_scan_read, nodes, data->nodes);
    expect_string(__wrap_sched_scan_read, MODULE_NAME, GCP_WM_NAME);
    will_return(__wrap_sched_scan_read, 0);

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, 0);

    gcp = data->module->data;

    assert_non_null(gcp);
    assert_int_equal(gcp->enabled, 1);
    assert_int_equal(gcp->pull_on_start, 0);
    assert_string_equal(gcp->project_id, "wazuh-gcp-pubsub-tests");
    assert_string_equal(gcp->subscription_name, "testing-id");
    assert_string_equal(gcp->credentials_file, "/var/ossec/credentials.json");
    assert_int_equal(gcp->logging, 5);
    assert_int_equal(gcp->max_messages, 100);

    assert_ptr_equal(data->module->context, &WM_GCP_CONTEXT);
    assert_string_equal(data->module->tag, GCP_WM_NAME);
}

static void test_wm_gcp_read_logging_tag_invalid(void **state) {
    group_data_t *data = *state;
    int ret;

    if(replace_configuration_value(data->nodes, XML_LOGGING, "invalid") != 0)
        fail();

    expect_string(__wrap_realpath, path, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, "/var/ossec/credentials.json");
    will_return(__wrap_realpath, (char *) 1);   //  realpath did not fail

    expect_string(__wrap_IsFile, file, "/var/ossec/credentials.json");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'logging'");

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wm_gcp_read_invalid_tag(void **state) {
    group_data_t *data = *state;
    int ret;

    // Make an invalid XML tag element
    free(data->nodes[0]->element);

    if(data->nodes[0]->element = strdup("invalid"), data->nodes[0]->element == NULL)
        fail();

    expect_string(__wrap__merror, formatted_msg, "No such tag 'invalid' at module 'gcp-pubsub'.");

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, -1);
}

static void test_wm_gcp_read_invalid_element(void **state) {
    group_data_t *data = *state;
    int ret;

    // Make an invalid XML tag element
    free(data->nodes[0]->element);
    data->nodes[0]->element = NULL;

    expect_string(__wrap__merror, formatted_msg, "(1231): Invalid NULL element in the configuration.");

    ret = wm_gcp_read(data->nodes, data->module);

    assert_int_equal(ret, -1);
}



int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_full_configuration, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_enabled_tag_invalid, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_project_id_tag_invalid, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_no_project_id_tag, setup_test_no_project_id, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_subscription_name_tag_invalid, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_no_subscription_name_tag, setup_test_no_subscription_name, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_credentials_file_full_path, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_credentials_file_tag_empty, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_credentials_file_tag_too_long, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_credentials_file_tag_realpath_error, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_credentials_file_tag_file_not_found, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_no_credentials_file_tag, setup_test_no_credentials_file, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_max_messages_tag_empty, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_max_messages_tag_not_digit, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_pull_on_start_tag_invalid, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_logging_tag_debug, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_logging_tag_info, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_logging_tag_warning, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_logging_tag_error, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_logging_tag_critical, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_logging_tag_invalid, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_invalid_tag, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wm_gcp_read_invalid_element, setup_test, teardown_test),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
