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
#include "../../analysisd/logmsg.h"

void _os_analysisd_add_logmsg(OSList * list, int level, int line, const char * func,
                                const char * file, char * msg, ...) __attribute__((nonnull));
char * os_analysisd_string_log_msg(os_analysisd_log_msg_t * log_msg);
void os_analysisd_free_log_msg(os_analysisd_log_msg_t * log_msg);

/* setup/teardown */



/* wraps */

int __wrap_isDebug() {
    return mock();
}

void __wrap__mvinfo(const char * file, int line, const char * func, const char *msg, va_list args) {
    function_called();
    return;
}

void __wrap__mvwarn(const char * file, int line, const char * func, const char *msg, va_list args) {
    function_called();
    return;
}

void __wrap__mverror(const char * file, int line, const char * func, const char *msg, va_list args) {
    function_called();
    return;
}

void * __wrap_OSList_AddData(OSList *list, void *data) {
    os_free(((os_analysisd_log_msg_t*)data)->msg);
    os_free(((os_analysisd_log_msg_t*)data)->file);
    os_free(((os_analysisd_log_msg_t*)data)->func);
    os_free(data);
    return mock_type(void *);
}

int __wrap_vsnprintf(char *__restrict __s, size_t __maxlen,
		            const char *__restrict __format, ...) {

    check_expected(__format);

    return mock();
}

/* tests */

/* os_analysisd_free_log_msg */

void test_os_analysisd_free_log_msg_NULL(void **state)
{

    os_analysisd_log_msg_t * message = NULL;

    os_analysisd_free_log_msg(message);

}

void test_os_analysisd_free_log_msg_OK(void **state)
{

    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);

    message->level = LOGLEVEL_ERROR;
    message->line = 500;
    message->msg = strdup("Test Message");
    message->file = strdup("Test_file.c");
    message->func = strdup("TestFunction");


    os_analysisd_free_log_msg(message);

}

/* os_analysisd_string_log_msg */
void test_os_analysisd_string_log_msg_NULL(void **state)
{
    char * retval = NULL;

    os_analysisd_log_msg_t * message = NULL;

    retval = os_analysisd_string_log_msg(message);
    assert_null(retval);

}

void test_os_analysisd_string_log_msg_isDebug_false(void **state)
{
    char * retval = NULL;

    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);

    message->level = LOGLEVEL_ERROR;
    message->line = 500;
    message->msg = strdup("Test Message");
    message->file = strdup("Test_file.c");
    message->func = strdup("TestFunction");

    will_return(__wrap_isDebug, 0);

    retval = os_analysisd_string_log_msg(message);
    assert_string_equal("Test Message", retval);

    os_free(message->file);
    os_free(message->func);
    os_free(message->msg);
    os_free(message);
    os_free(retval);

}

void test_os_analysisd_string_log_msg_isDebug_true(void **state)
{
    char * retval = NULL;

    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);

    message->level = LOGLEVEL_ERROR;
    message->line = 500;
    message->msg = strdup("Test Message");
    message->file = strdup("Test_file.c");
    message->func = strdup("TestFunction");

    will_return(__wrap_isDebug, 1);

    retval = os_analysisd_string_log_msg(message);
    assert_string_equal("Test_file.c:500 at TestFunction(): Test Message", retval);

    os_free(message->file);
    os_free(message->func);
    os_free(message->msg);
    os_free(message);
    os_free(retval);

}

/* _os_analysisd_add_logmsg */

void test__os_analysisd_add_logmsg_OK(void **state)
{
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);
    OSListNode * list_msg_node;

    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);

    message->level = LOGLEVEL_ERROR;
    message->line = 500;
    message->msg = strdup("Test Message");
    message->file = strdup("Test_file.c");
    message->func = strdup("TestFunction");

    expect_string(__wrap_vsnprintf, __format, "Test Message");
    will_return(__wrap_vsnprintf, 0);

    will_return(__wrap_OSList_AddData,"test");

    _os_analysisd_add_logmsg(list_msg, message->level, message->line, message->func, message->file, message->msg);

    os_free(message->file);
    os_free(message->func);
    os_free(message->msg);
    os_free(list_msg);
    os_free(message);
}

void test__os_analysisd_add_logmsg_info(void ** state) {

    expect_function_call(__wrap__mvinfo);
    _os_analysisd_add_logmsg(NULL, LOGLEVEL_INFO, 500, "TestFunction", "Test_file.c", "Test Message");
}

void test__os_analysisd_add_logmsg_warn(void ** state) {

    expect_function_call(__wrap__mvwarn);
    _os_analysisd_add_logmsg(NULL, LOGLEVEL_WARNING, 500, "TestFunction", "Test_file.c", "Test Message");
}

void test__os_analysisd_add_logmsg_error(void ** state) {

    expect_function_call(__wrap__mverror);
    _os_analysisd_add_logmsg(NULL, LOGLEVEL_ERROR, 500, "TestFunction", "Test_file.c", "Test Message");
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        //Test os_analysisd_free_log_msg
        cmocka_unit_test(test_os_analysisd_free_log_msg_NULL),
        cmocka_unit_test(test_os_analysisd_free_log_msg_OK),
        //Test os_analysisd_string_log_msg
        cmocka_unit_test(test_os_analysisd_string_log_msg_NULL),
        cmocka_unit_test(test_os_analysisd_string_log_msg_isDebug_false),
        cmocka_unit_test(test_os_analysisd_string_log_msg_isDebug_true),
        //Test _os_analysisd_add_logmsg
        cmocka_unit_test(test__os_analysisd_add_logmsg_OK),
        cmocka_unit_test(test__os_analysisd_add_logmsg_info),
        cmocka_unit_test(test__os_analysisd_add_logmsg_error),
        cmocka_unit_test(test__os_analysisd_add_logmsg_warn),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
