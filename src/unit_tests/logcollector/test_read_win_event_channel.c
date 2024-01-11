/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "shared.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

#include <stdint.h>
#include <sec_api/stdlib_s.h>
#include <winerror.h>
#include <winevt.h>

typedef struct test_struct {
    EVT_HANDLE evt;
    LPCWSTR provider_name;
    const char *message;
} test_struct_t;

char *get_message(EVT_HANDLE evt, LPCWSTR provider_name, DWORD flags);

/* Setup & Teardown */

static int test_setup(void ** state) {
    test_struct_t *init_data = NULL;

    os_calloc(1, sizeof(test_struct_t), init_data);
    init_data->evt = NULL;
    init_data->provider_name = L"provider_name";
    init_data->message = "Test_Message";
    *state = init_data;

    test_mode = 1;
    return 0;
}

static int test_teardown(void ** state) {
    test_struct_t *data = (test_struct_t*)*state;

    os_free(data);

    test_mode = 0;
    return 0;
}

/* Wraps */

/* Tests */

void test_get_message_get_publisher_fail(void ** state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(wrap_EvtOpenPublisherMetadata, Session, NULL);
    expect_string(wrap_EvtOpenPublisherMetadata, PublisherId, data->provider_name);
    expect_value(wrap_EvtOpenPublisherMetadata, LogFilePath, NULL);
    expect_value(wrap_EvtOpenPublisherMetadata, Locale, 0);
    expect_value(wrap_EvtOpenPublisherMetadata, Flags, 0);
    will_return(wrap_EvtOpenPublisherMetadata, NULL);

    will_return(wrap_GetLastError, ERROR_FILE_NOT_FOUND);
    will_return(wrap_FormatMessage, "File not found.");
    expect_string(__wrap__mdebug1, formatted_msg, "Could not EvtOpenPublisherMetadata() with flags (1) which returned (2): File not found.");

    assert_null(get_message(data->evt, data->provider_name, EvtFormatMessageEvent));
}

void test_get_message_get_size_fail(void ** state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(wrap_EvtOpenPublisherMetadata, Session, NULL);
    expect_string(wrap_EvtOpenPublisherMetadata, PublisherId, data->provider_name);
    expect_value(wrap_EvtOpenPublisherMetadata, LogFilePath, NULL);
    expect_value(wrap_EvtOpenPublisherMetadata, Locale, 0);
    expect_value(wrap_EvtOpenPublisherMetadata, Flags, 0);
    will_return(wrap_EvtOpenPublisherMetadata, 1);

    will_return(wrap_EvtFormatMessage, strlen(data->message));
    will_return(wrap_EvtFormatMessage, TRUE);
    will_return(wrap_GetLastError, ERROR_INSUFFICIENT_BUFFER);
    expect_string(__wrap__merror, formatted_msg, "Could not EvtFormatMessage() to determine buffer size with flags (1) which returned (122)");

    will_return(wrap_EvtClose, TRUE);

    assert_null(get_message(data->evt, data->provider_name, EvtFormatMessageEvent));

}

void test_get_message_format_fail(void ** state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(wrap_EvtOpenPublisherMetadata, Session, NULL);
    expect_string(wrap_EvtOpenPublisherMetadata, PublisherId, data->provider_name);
    expect_value(wrap_EvtOpenPublisherMetadata, LogFilePath, NULL);
    expect_value(wrap_EvtOpenPublisherMetadata, Locale, 0);
    expect_value(wrap_EvtOpenPublisherMetadata, Flags, 0);
    will_return(wrap_EvtOpenPublisherMetadata, 1);

    will_return(wrap_EvtFormatMessage, strlen(data->message));
    will_return(wrap_EvtFormatMessage, FALSE);
    will_return(wrap_GetLastError, ERROR_INSUFFICIENT_BUFFER);

    will_return(wrap_EvtFormatMessage, data->message);
    will_return(wrap_EvtFormatMessage, FALSE);
    will_return(wrap_GetLastError, ERROR_INSUFFICIENT_BUFFER);
    expect_string(__wrap__merror, formatted_msg, "Could not EvtFormatMessage() with flags (1) which returned (122)");

    will_return(wrap_EvtClose, TRUE);

    assert_null(get_message(data->evt, data->provider_name, EvtFormatMessageEvent));
}

void test_get_message_convert_string_fail(void ** state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(wrap_EvtOpenPublisherMetadata, Session, NULL);
    expect_string(wrap_EvtOpenPublisherMetadata, PublisherId, data->provider_name);
    expect_value(wrap_EvtOpenPublisherMetadata, LogFilePath, NULL);
    expect_value(wrap_EvtOpenPublisherMetadata, Locale, 0);
    expect_value(wrap_EvtOpenPublisherMetadata, Flags, 0);
    will_return(wrap_EvtOpenPublisherMetadata, 1);

    will_return(wrap_EvtFormatMessage, strlen(data->message));
    will_return(wrap_EvtFormatMessage, FALSE);
    will_return(wrap_GetLastError, ERROR_INSUFFICIENT_BUFFER);

    will_return(wrap_EvtFormatMessage, data->message);
    will_return(wrap_EvtFormatMessage, TRUE);

    expect_string(__wrap_convert_windows_string, string, "Test_Message");
    will_return(__wrap_convert_windows_string, NULL);

    will_return(wrap_EvtClose, TRUE);

    assert_null(get_message(data->evt, data->provider_name, EvtFormatMessageEvent));
}

void test_get_message_success(void ** state) {
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(wrap_EvtOpenPublisherMetadata, Session, NULL);
    expect_string(wrap_EvtOpenPublisherMetadata, PublisherId, data->provider_name);
    expect_value(wrap_EvtOpenPublisherMetadata, LogFilePath, NULL);
    expect_value(wrap_EvtOpenPublisherMetadata, Locale, 0);
    expect_value(wrap_EvtOpenPublisherMetadata, Flags, 0);
    will_return(wrap_EvtOpenPublisherMetadata, 1);

    will_return(wrap_EvtFormatMessage, strlen(data->message));
    will_return(wrap_EvtFormatMessage, FALSE);
    will_return(wrap_GetLastError, ERROR_INSUFFICIENT_BUFFER);

    will_return(wrap_EvtFormatMessage, data->message);
    will_return(wrap_EvtFormatMessage, TRUE);

    expect_string(__wrap_convert_windows_string, string, "Test_Message");
    will_return(__wrap_convert_windows_string, "Test_Message");

    will_return(wrap_EvtClose, TRUE);

    assert_non_null(get_message(data->evt, data->provider_name, EvtFormatMessageEvent));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_get_message_get_publisher_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_message_get_size_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_message_format_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_message_convert_string_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_message_success, test_setup, test_teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
