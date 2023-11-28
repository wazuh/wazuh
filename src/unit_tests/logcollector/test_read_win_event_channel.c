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


char *get_message(EVT_HANDLE evt, LPCWSTR provider_name, DWORD flags);

/* Setup & Teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

/* Wraps */

/* Tests */

void test_get_message_get_publisher_fail(void ** state) {
    EVT_HANDLE evt = NULL;
    LPCWSTR provider_name = L"provider_name";

    expect_value(wrap_EvtOpenPublisherMetadata, Session, NULL);
    expect_string(wrap_EvtOpenPublisherMetadata, PublisherId, provider_name);
    expect_value(wrap_EvtOpenPublisherMetadata, LogFilePath, NULL);
    expect_value(wrap_EvtOpenPublisherMetadata, Locale, 0);
    expect_value(wrap_EvtOpenPublisherMetadata, Flags, 0);
    will_return(wrap_EvtOpenPublisherMetadata, NULL);

    will_return(wrap_GetLastError, ERROR_FILE_NOT_FOUND);
    will_return(wrap_FormatMessage, "File not found.");
    expect_string(__wrap__mdebug1, formatted_msg, "Could not EvtOpenPublisherMetadata() with flags (1) which returned (2): File not found.");

    assert_null(get_message(evt, provider_name, EvtFormatMessageEvent));
}

void test_get_message_get_size_fail(void ** state) {
    EVT_HANDLE evt = NULL;
    LPCWSTR provider_name = L"provider_name";
    char message[] = "Test_Message";

    expect_value(wrap_EvtOpenPublisherMetadata, Session, NULL);
    expect_string(wrap_EvtOpenPublisherMetadata, PublisherId, provider_name);
    expect_value(wrap_EvtOpenPublisherMetadata, LogFilePath, NULL);
    expect_value(wrap_EvtOpenPublisherMetadata, Locale, 0);
    expect_value(wrap_EvtOpenPublisherMetadata, Flags, 0);
    will_return(wrap_EvtOpenPublisherMetadata, 1);

    will_return(wrap_EvtFormatMessage, strlen(message));
    will_return(wrap_EvtFormatMessage, TRUE);
    will_return(wrap_GetLastError, ERROR_INSUFFICIENT_BUFFER);
    expect_string(__wrap__merror, formatted_msg, "Could not EvtFormatMessage() to determine buffer size with flags (1) which returned (122)");

    will_return(wrap_EvtClose, TRUE);

    assert_null(get_message(evt, provider_name, EvtFormatMessageEvent));

}

void test_get_message_format_fail(void ** state) {
    EVT_HANDLE evt = NULL;
    LPCWSTR provider_name = L"provider_name";
    char message[] = "Test_Message";

    expect_value(wrap_EvtOpenPublisherMetadata, Session, NULL);
    expect_string(wrap_EvtOpenPublisherMetadata, PublisherId, provider_name);
    expect_value(wrap_EvtOpenPublisherMetadata, LogFilePath, NULL);
    expect_value(wrap_EvtOpenPublisherMetadata, Locale, 0);
    expect_value(wrap_EvtOpenPublisherMetadata, Flags, 0);
    will_return(wrap_EvtOpenPublisherMetadata, 1);

    will_return(wrap_EvtFormatMessage, strlen(message));
    will_return(wrap_EvtFormatMessage, FALSE);
    will_return(wrap_GetLastError, ERROR_INSUFFICIENT_BUFFER);

    will_return(wrap_EvtFormatMessage, message);
    will_return(wrap_EvtFormatMessage, FALSE);
    will_return(wrap_GetLastError, ERROR_INSUFFICIENT_BUFFER);
    expect_string(__wrap__merror, formatted_msg, "Could not EvtFormatMessage() with flags (1) which returned (122)");

    will_return(wrap_EvtClose, TRUE);

    assert_null(get_message(evt, provider_name, EvtFormatMessageEvent));
}

void test_get_message_convert_string_fail(void ** state) {
    EVT_HANDLE evt = NULL;
    LPCWSTR provider_name = L"provider_name";
    char message[] = "Test_Message";

    expect_value(wrap_EvtOpenPublisherMetadata, Session, NULL);
    expect_string(wrap_EvtOpenPublisherMetadata, PublisherId, provider_name);
    expect_value(wrap_EvtOpenPublisherMetadata, LogFilePath, NULL);
    expect_value(wrap_EvtOpenPublisherMetadata, Locale, 0);
    expect_value(wrap_EvtOpenPublisherMetadata, Flags, 0);
    will_return(wrap_EvtOpenPublisherMetadata, 1);

    will_return(wrap_EvtFormatMessage, strlen(message));
    will_return(wrap_EvtFormatMessage, FALSE);
    will_return(wrap_GetLastError, ERROR_INSUFFICIENT_BUFFER);

    will_return(wrap_EvtFormatMessage, message);
    will_return(wrap_EvtFormatMessage, TRUE);

    expect_string(__wrap_convert_windows_string, string, "Test_Message");
    will_return(__wrap_convert_windows_string, NULL);

    will_return(wrap_EvtClose, TRUE);

    assert_null(get_message(evt, provider_name, EvtFormatMessageEvent));
}

void test_get_message_success(void ** state) {
    EVT_HANDLE evt = NULL;
    LPCWSTR provider_name = L"provider_name";
    char message[] = "Test_Message";

    expect_value(wrap_EvtOpenPublisherMetadata, Session, NULL);
    expect_string(wrap_EvtOpenPublisherMetadata, PublisherId, provider_name);
    expect_value(wrap_EvtOpenPublisherMetadata, LogFilePath, NULL);
    expect_value(wrap_EvtOpenPublisherMetadata, Locale, 0);
    expect_value(wrap_EvtOpenPublisherMetadata, Flags, 0);
    will_return(wrap_EvtOpenPublisherMetadata, 1);

    will_return(wrap_EvtFormatMessage, strlen(message));
    will_return(wrap_EvtFormatMessage, FALSE);
    will_return(wrap_GetLastError, ERROR_INSUFFICIENT_BUFFER);

    will_return(wrap_EvtFormatMessage, message);
    will_return(wrap_EvtFormatMessage, TRUE);

    expect_string(__wrap_convert_windows_string, string, "Test_Message");
    will_return(__wrap_convert_windows_string, "Test_Message");

    will_return(wrap_EvtClose, TRUE);

    assert_non_null(get_message(evt, provider_name, EvtFormatMessageEvent));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_message_get_publisher_fail),
        cmocka_unit_test(test_get_message_get_size_fail),
        cmocka_unit_test(test_get_message_format_fail),
        cmocka_unit_test(test_get_message_convert_string_fail),
        cmocka_unit_test(test_get_message_success)
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
