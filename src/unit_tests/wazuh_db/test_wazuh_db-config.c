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

#include "../../headers/shared.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../config/wazuh_db-config.h"
#include "../../wazuh_db/wdb.h"

/* setup/teardown */

int wazuh_db_setup() {
    wdb_init_conf();

    return OS_SUCCESS;
}

int  wazuh_db_teardown() {
    wdb_free_conf();

    return OS_SUCCESS;
}

/* Read_WazuhDB tests */

void test_Read_WazuhDB_element_NULL(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;

    nodes = calloc(2, sizeof(xml_node*));
    nodes[0] = calloc(1, sizeof(xml_node));
    nodes[0]->element = NULL;

    expect_string(__wrap__merror, formatted_msg, "(1231): Invalid NULL element in the configuration.");

    int ret = Read_WazuhDB(&xml, nodes);
    assert_int_equal(ret, OS_INVALID);

    OS_ClearNode(nodes);
}

void test_Read_WazuhDB_element_invalid(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<invalid>"
        "</invalid>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1230): Invalid element in the configuration: 'invalid'.");

    int ret = Read_WazuhDB(&xml, nodes);
    assert_int_equal(ret, OS_INVALID);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

void test_Read_WazuhDB_attribute_NULL(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<backup>"
        "</backup>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1233): Invalid attribute '' in the configuration: 'backup'.");

    int ret = Read_WazuhDB(&xml, nodes);
    assert_int_equal(ret, OS_INVALID);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

void test_Read_WazuhDB_attribute_invalid(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<backup invalid='value'>"
        "</backup>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1233): Invalid attribute 'invalid' in the configuration: 'backup'.");

    int ret = Read_WazuhDB(&xml, nodes);
    assert_int_equal(ret, OS_INVALID);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

void test_Read_WazuhDB_attribute_value_invalid(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<backup database='value'>"
        "</backup>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'database': value.");

    int ret = Read_WazuhDB(&xml, nodes);
    assert_int_equal(ret, OS_INVALID);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

void test_Read_WazuhDB_content_NULL(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<backup database='global'>"
        "</backup>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1231): Invalid NULL element in the configuration.");

    int ret = Read_WazuhDB(&xml, nodes);
    assert_int_equal(ret, OS_INVALID);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

void test_Read_WazuhDB_valid_config(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<backup database='global'>"
            "<enabled>yes</enabled>"
            "<interval>120w</interval>"
            "<max_files>1</max_files>"
        "</backup>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    int ret = Read_WazuhDB(&xml, nodes);

    assert_int_equal(ret, OS_SUCCESS);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->enabled, 1);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->interval, 72576000);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->max_files, 1);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

/* Read_WazuhDB_Backup tests */

void test_Read_WazuhDB_Backup_element_NULL(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<backup database='global'>"
        "</backup>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1231): Invalid NULL element in the configuration.");

    int ret = Read_WazuhDB_Backup(&xml, nodes[0], WDB_GLOBAL_BACKUP);
    assert_int_equal(ret, OS_INVALID);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

void test_Read_WazuhDB_Backup_element_invalid(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<backup database='global'>"
            "<invalid></invalid>"
        "</backup>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1230): Invalid element in the configuration: 'invalid'.");

    int ret = Read_WazuhDB_Backup(&xml, nodes[0], WDB_GLOBAL_BACKUP);
    assert_int_equal(ret, OS_INVALID);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

void test_Read_WazuhDB_Backup_content_NULL(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<backup database='global'>"
            "<invalid>"
        "</backup>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1234): Invalid NULL content for element: invalid.");

    int ret = Read_WazuhDB_Backup(&xml, nodes[0], WDB_GLOBAL_BACKUP);
    assert_int_equal(ret, OS_INVALID);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

void test_Read_WazuhDB_Backup_enabled_empty_value(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<backup database='global'>"
            "<enabled></enabled>"
        "</backup>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'enabled': .");

    int ret = Read_WazuhDB_Backup(&xml, nodes[0], WDB_GLOBAL_BACKUP);
    assert_int_equal(ret, OS_INVALID);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

void test_Read_WazuhDB_Backup_enabled_invalid_value(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<backup database='global'>"
            "<enabled>123</enabled>"
        "</backup>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'enabled': 123.");

    int ret = Read_WazuhDB_Backup(&xml, nodes[0], WDB_GLOBAL_BACKUP);
    assert_int_equal(ret, OS_INVALID);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

void test_Read_WazuhDB_Backup_interval_invalid_value(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<backup database='global'>"
            "<enabled>yes</enabled>"
            "<interval>invalid</interval>"
        "</backup>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'interval': invalid.");

    int ret = Read_WazuhDB_Backup(&xml, nodes[0], WDB_GLOBAL_BACKUP);
    assert_int_equal(ret, OS_INVALID);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

void test_Read_WazuhDB_Backup_maxfiles_invalid_string(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<backup database='global'>"
            "<enabled>yes</enabled>"
            "<interval>1d</interval>"
            "<max_files>invalid</max_files>"
        "</backup>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'max_files': invalid.");

    int ret = Read_WazuhDB_Backup(&xml, nodes[0], WDB_GLOBAL_BACKUP);
    assert_int_equal(ret, OS_INVALID);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

void test_Read_WazuhDB_Backup_maxfiles_invalid_value(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<backup database='global'>"
            "<enabled>yes</enabled>"
            "<interval>1d</interval>"
            "<max_files>0</max_files>"
        "</backup>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'max_files': 0.");

    int ret = Read_WazuhDB_Backup(&xml, nodes[0], WDB_GLOBAL_BACKUP);
    assert_int_equal(ret, OS_INVALID);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

void test_Read_WazuhDB_Backup_valid_config(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<backup database='global'>"
            "<enabled>yes</enabled>"
            "<interval>1d</interval>"
            "<max_files>3</max_files>"
        "</backup>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    int ret = Read_WazuhDB_Backup(&xml, nodes[0], WDB_GLOBAL_BACKUP);
    assert_int_equal(ret, OS_SUCCESS);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->enabled, 1);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->interval, 86400);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->max_files, 3);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

void test_Read_WazuhDB_Backup_valid_config2(void **state)
{
    XML_NODE nodes = NULL;
    OS_XML xml;
    char *test_config =
        "<backup database='global'>"
            "<enabled>no</enabled>"
            "<interval>12h</interval>"
            "<max_files>10</max_files>"
        "</backup>";

    OS_ReadXMLString(test_config, &xml);
    nodes = OS_GetElementsbyNode(&xml, NULL);

    int ret = Read_WazuhDB_Backup(&xml, nodes[0], WDB_GLOBAL_BACKUP);
    assert_int_equal(ret, OS_SUCCESS);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->enabled, 0);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->interval, 43200);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->max_files, 10);

    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests Read_WazuhDB
        cmocka_unit_test(test_Read_WazuhDB_element_NULL),
        cmocka_unit_test(test_Read_WazuhDB_element_invalid),
        cmocka_unit_test(test_Read_WazuhDB_attribute_NULL),
        cmocka_unit_test(test_Read_WazuhDB_attribute_invalid),
        cmocka_unit_test(test_Read_WazuhDB_attribute_value_invalid),
        cmocka_unit_test(test_Read_WazuhDB_valid_config),
        // Tests Read_WazuhDB_Backup
        cmocka_unit_test(test_Read_WazuhDB_Backup_element_NULL),
        cmocka_unit_test(test_Read_WazuhDB_Backup_element_invalid),
        cmocka_unit_test(test_Read_WazuhDB_Backup_content_NULL),
        cmocka_unit_test(test_Read_WazuhDB_Backup_enabled_empty_value),
        cmocka_unit_test(test_Read_WazuhDB_Backup_enabled_invalid_value),
        cmocka_unit_test(test_Read_WazuhDB_Backup_interval_invalid_value),
        cmocka_unit_test(test_Read_WazuhDB_Backup_maxfiles_invalid_string),
        cmocka_unit_test(test_Read_WazuhDB_Backup_maxfiles_invalid_value),
        cmocka_unit_test(test_Read_WazuhDB_Backup_valid_config),
        cmocka_unit_test(test_Read_WazuhDB_Backup_valid_config2),
    };

    return cmocka_run_group_tests(tests, wazuh_db_setup, wazuh_db_teardown);
}
