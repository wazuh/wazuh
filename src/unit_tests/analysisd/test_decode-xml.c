/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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
#include "os_regex/os_regex.h"
#include "os_xml/os_xml.h"
#include "../../analysisd/analysisd.h"
#include "../../analysisd/eventinfo.h"
#include "../../analysisd/decoders/decoder.h"
#include "../../analysisd/decoders/plugin_decoders.h"
#include "../../analysisd/config.h"


void FreeDecoderInfo(OSDecoderInfo *pi);
char *_loadmemory(char *at, char *str, OSList* log_msg);
int addDecoder2list(const char *name, OSStore **decoder_store);

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

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

OSStore * __wrap_OSStore_Create() {
    return mock_type(OSStore *);
}

int __wrap_OSStore_Put(OSStore *list, const char *key, void *data) {
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

    os_calloc(1, sizeof(OSRegex), info->regex);
    os_calloc(1, sizeof(OSRegex), info->prematch);
    os_calloc(1, sizeof(OSRegex), info->program_name);

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
    will_return(__wrap_OSStore_Put, 1);

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

    will_return(__wrap_OSStore_Put, 0);
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

    will_return(__wrap_OSStore_Put, 1);

    retval = addDecoder2list(name, &decoder_store);

    assert_int_equal(retval, expect_retval);
    os_free(decoder_store);
}

int main(void)
{
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
        cmocka_unit_test(test_addDecoder2list_push_ok)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
