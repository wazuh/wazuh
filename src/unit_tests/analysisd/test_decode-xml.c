/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../../headers/shared.h"
#include "../os_regex/os_regex.h"
#include "../os_xml/os_xml.h"
#include "../../analysisd/analysisd.h"
#include "../../analysisd/eventinfo.h"
#include "../../analysisd/decoders/decoder.h"
#include "../../analysisd/decoders/plugin_decoders.h"
#include "../../analysisd/config.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

void FreeDecoderInfo(OSDecoderInfo *pi);
char *_loadmemory(char *at, char *str, OSList* log_msg);
int addDecoder2list(const char *name, OSStore **decoder_store);
bool w_get_attr_regex_type(xml_node * node, w_exp_type_t * type);
int w_get_attr_offset(xml_node * node);

/* setup/teardown */

/* wraps */
void __wrap__os_analysisd_add_logmsg(OSList * list, int level, int line, const char * func,
                                    const char * file, char * msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(level);
    check_expected_ptr(list);
    check_expected(formatted_msg);
}

OSStore * __wrap_OSStore_Create() {
    return mock_type(OSStore *);
}

int __wrap_OSStore_Put_ex(OSStore *list, const char *key, void *data) {
    return mock_type(int);
}


/* tests */

/* FreeDecoderInfo */
void test_FreeDecoderInfo_NULL(void **state)
{
    OSDecoderInfo *info = NULL;

    FreeDecoderInfo(info);

}

void test_FreeDecoderInfo_OK(void **state)
{
    OSDecoderInfo *info;
    os_calloc(1, sizeof(OSDecoderInfo), info);

    os_calloc(1, sizeof(char), info->parent);
    os_calloc(1, sizeof(char), info->name);
    os_calloc(1, sizeof(char), info->ftscomment);
    os_calloc(1, sizeof(char), info->fts_fields);
    os_calloc(1, sizeof(char*), info->fields);
    os_calloc(1, sizeof(char), info->fields[0]);

    w_calloc_expression_t(&info->regex, EXP_TYPE_OSREGEX);
    w_calloc_expression_t(&info->prematch, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&info->program_name, EXP_TYPE_OSREGEX);

    os_calloc(1, sizeof(void*), info->order);

    Config.decoder_order_size = 1;

    FreeDecoderInfo(info);

}

// _loadmemory
void test__loadmemory_null_append_ok(void ** state)
{
    char * at = NULL;
    char * str;

    const size_t len = 1000;
    char * expect_retval;
    char * retval;

    os_calloc(len, sizeof(char), str);
    memset(str, (int) '-', len - 1);
    str[len-1] = '\0';

    os_calloc(len, sizeof(char), expect_retval);
    memset(expect_retval, (int) '-', len - 1);
    expect_retval[len-1] = '\0';

    retval = _loadmemory(at,str, NULL);

    assert_string_equal(retval, expect_retval);

    os_free(str);
    os_free(retval);
    os_free(expect_retval);

}

void test__loadmemory_null_append_oversize(void ** state)
{
    char * at = NULL;
    char * str;
    OSList list_msg = {0};

    const size_t len = 1025;
    char * retval;

    os_calloc(len, sizeof(char), str);
    memset(str, (int) '-', len - 1);
    str[len-1] = '\0';

    char expect_msg[OS_SIZE_4096];

    snprintf(expect_msg, OS_SIZE_4096, "(1104): Maximum string size reached for: %s.", str);
    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, expect_msg);

    retval = _loadmemory(at,str, &list_msg);

    assert_null(retval);

    os_free(str);

}

void test__loadmemory_append_oversize(void ** state)
{
    char * at = NULL;
    char * str = NULL;
    OSList list_msg = {0};

    const size_t len = 513;
    char * retval;

    os_calloc(len, sizeof(char), str);
    memset(str, (int) '-', len - 1);
    str[len-1] = '\0';

    os_calloc(len, sizeof(char), at);
    memset(at, (int) '+', len - 1);
    str[len-1] = '\0';

    char expect_msg[OS_SIZE_4096];

    snprintf(expect_msg, OS_SIZE_4096, "(1104): Maximum string size reached for: %s.", str);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, expect_msg);

    retval = _loadmemory(at,str, &list_msg);

    assert_null(retval);

    os_free(str);
    os_free(at);

}
void test__loadmemory_append_ok(void ** state)
{
    char * at = NULL;
    char * str = NULL;
    OSList list_msg = {0};

    const size_t len = 512;
    char * retval;
    char * expect_retval;

    os_calloc(len, sizeof(char), str);
    memset(str, (int) '-', len - 1);
    str[len-1] = '\0';

    os_calloc(len, sizeof(char), at);
    memset(at, (int) '+', len - 1);
    at[len-1] = '\0';

    os_calloc(len * 2, sizeof(char), expect_retval);
    strncat(expect_retval, at, len * 2);
    strncat(expect_retval, str, len * 2);

    retval = _loadmemory(at,str, &list_msg);

    assert_non_null(retval);
    assert_string_equal(retval, expect_retval);

    os_free(str);
    os_free(retval);
    os_free(expect_retval);

}

// addDecoder2list
void test_addDecoder2list_empty_list_deco_error(void ** state)
{
    const char * name = "test name";
    OSStore * decoder_store = NULL;
    int expect_retval = 0;
    int retval;

    will_return(__wrap_OSStore_Create, NULL);
    expect_string(__wrap__merror, formatted_msg, "(1290): Unable to create a new list (calloc).");

    retval = addDecoder2list(name, &decoder_store);

    assert_int_equal(retval, expect_retval);

}

void test_addDecoder2list_empty_list_deco_ok(void ** state)
{
    const char * name = "test name";
    OSStore * decoder_store = NULL;
    int expect_retval = 1;
    int retval;

    will_return(__wrap_OSStore_Create, (OSStore *) 1);
    will_return(__wrap_OSStore_Put_ex, 1);

    retval = addDecoder2list(name, &decoder_store);

    assert_int_equal(retval, expect_retval);
}

void test_addDecoder2list_fail_push(void ** state)
{
    const char * name = "test name";
    OSStore * decoder_store = NULL;
    int expect_retval = 0;
    int retval;
    os_calloc(1, sizeof(OSStore), decoder_store);

    will_return(__wrap_OSStore_Put_ex, 0);
    expect_string(__wrap__merror, formatted_msg, "(1291): Error adding nodes to list.");

    retval = addDecoder2list(name, &decoder_store);

    assert_int_equal(retval, expect_retval);
    os_free(decoder_store);
}

void test_addDecoder2list_push_ok(void ** state)
{
    const char * name = "test name";
    OSStore * decoder_store = NULL;
    int expect_retval = 1;
    int retval;
    os_calloc(1, sizeof(OSStore), decoder_store);

    will_return(__wrap_OSStore_Put_ex, 1);

    retval = addDecoder2list(name, &decoder_store);

    assert_int_equal(retval, expect_retval);
    os_free(decoder_store);
}

void w_get_attr_regex_type_not_found(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "attr_name_2", NULL};
    char * values[] = {"attr_val_1", "attr_val_2", NULL};
    node.attributes = attributes;
    node.values = values;

    w_exp_type_t type = -2;

    bool retval;

    retval = w_get_attr_regex_type(&node, &type);

    assert_false(retval);
    assert_int_equal(type, -2);
}

void w_get_attr_regex_type_osregex(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "type", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "osregex", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    w_exp_type_t type = -2;

    bool retval;

    retval = w_get_attr_regex_type(&node, &type);

    assert_true(retval);
    assert_int_equal(type, EXP_TYPE_OSREGEX);
}

void w_get_attr_regex_type_osmatch(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "type", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "osmatch", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    w_exp_type_t type = -2;

    bool retval;

    retval = w_get_attr_regex_type(&node, &type);

    assert_true(retval);
    assert_int_equal(type, EXP_TYPE_OSMATCH);
}

void w_get_attr_regex_type_pcre2(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "type", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "PCRE2", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    w_exp_type_t type = -2;

    bool retval;

    retval = w_get_attr_regex_type(&node, &type);

    assert_true(retval);
    assert_int_equal(type, EXP_TYPE_PCRE2);
}

void w_get_attr_regex_type_invalid(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "type", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "invalid type", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    w_exp_type_t type = -2;

    bool retval;

    retval = w_get_attr_regex_type(&node, &type);

    assert_true(retval);
    assert_int_equal(type, EXP_TYPE_INVALID);
}

// w_get_attr_offset

void w_get_attr_offset_not_found(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "attr_name_2", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "attr_val_2", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    int retval;

    retval = w_get_attr_offset(&node);

    assert_int_equal(retval, 0);
}

void w_get_attr_offset_after_parent(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "offset", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "after_parent", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    int retval;

    retval = w_get_attr_offset(&node);

    assert_int_equal(retval, AFTER_PARENT);
}

void w_get_attr_offset_after_prematch(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "offset", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "after_prematch", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    int retval;

    retval = w_get_attr_offset(&node);

    assert_int_equal(retval, AFTER_PREMATCH);
}
void w_get_attr_offset_after_after_regex(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "offset", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "after_regex", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    int retval;

    retval = w_get_attr_offset(&node);

    assert_int_equal(retval, AFTER_PREVREGEX);
}

void w_get_attr_offset_error(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "offset", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "bad_value", "attr_val_3", NULL};
    node.attributes = attributes;
    node.values = values;

    int retval;

    retval = w_get_attr_offset(&node);

    assert_int_equal(retval, AFTER_ERROR);
}

int main(void) {
    const struct CMUnitTest tests[] = {

        // Tests FreeDecoderInfo
        cmocka_unit_test(test_FreeDecoderInfo_NULL),
        cmocka_unit_test(test_FreeDecoderInfo_OK),

        // Tests _loadmemory
        cmocka_unit_test(test__loadmemory_null_append_ok),
        cmocka_unit_test(test__loadmemory_null_append_oversize),
        cmocka_unit_test(test__loadmemory_append_oversize),
        cmocka_unit_test(test__loadmemory_append_ok),

        // Tests addDecoder2list
        cmocka_unit_test(test_addDecoder2list_empty_list_deco_error),
        cmocka_unit_test(test_addDecoder2list_empty_list_deco_ok),
        cmocka_unit_test(test_addDecoder2list_fail_push),
        cmocka_unit_test(test_addDecoder2list_push_ok),

        // Test w_get_attr_regex_type
        cmocka_unit_test(w_get_attr_regex_type_not_found),
        cmocka_unit_test(w_get_attr_regex_type_osregex),
        cmocka_unit_test(w_get_attr_regex_type_osmatch),
        cmocka_unit_test(w_get_attr_regex_type_pcre2),
        cmocka_unit_test(w_get_attr_regex_type_invalid),

        // w_get_attr_offset
        cmocka_unit_test(w_get_attr_offset_not_found),
        cmocka_unit_test(w_get_attr_offset_after_parent),
        cmocka_unit_test(w_get_attr_offset_after_prematch),
        cmocka_unit_test(w_get_attr_offset_after_after_regex),
        cmocka_unit_test(w_get_attr_offset_error),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
