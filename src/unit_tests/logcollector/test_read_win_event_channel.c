/*
 * Copyright (C) Wazuh Inc.
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
#include "../wrappers/wazuh/shared/utf8_winapi_wrapper_wrappers.h"

#define MEMBER_SID "<Data Name='MemberSid'>S-1-5-18</Data>"
#define MISSING_NAME "<Data Name='MemberName'>-</Data>"
#define EVENT(fields) "<Event><EventData>" fields "</EventData></Event>"

typedef struct _os_channel {
    char *evt_log;
    char *bookmark_name;
    char bookmark_enabled;
    char bookmark_filename[OS_MAXSTR];
    char *query;
    int reconnect_time;
    EVT_HANDLE subscription;
} os_channel;

void send_channel_event(EVT_HANDLE evt, os_channel *channel);
void enrich_member_name(char **xml);

/* Setup & Teardown */

static int test_setup(void ** state) {
    os_channel *channel = NULL;

    os_calloc(1, sizeof(os_channel), channel);
    channel->evt_log = strdup("Application");
    channel->bookmark_name = NULL;
    channel->bookmark_enabled = 0;
    *state = channel;

    test_mode = 1;
    return 0;
}

static int test_teardown(void ** state) {
    os_channel *channel = (os_channel *)*state;

    os_free(channel->evt_log);
    os_free(channel->bookmark_name);
    os_free(channel);

    test_mode = 0;
    return 0;
}

/* Tests */

static void check_enrichment(const char *input, const char *expected) {
    char *xml = strdup(input);
    enrich_member_name(&xml);
    assert_string_equal(xml, expected);
    os_free(xml);
}

static void test_ineligible_events(void **state) {
    (void)state;
    const char *events[] = {
        EVENT(MEMBER_SID), EVENT(MISSING_NAME),
        EVENT("<Data Name='MemberName'>/existing</Data>" MEMBER_SID),
        EVENT(MISSING_NAME "<Data Name='MemberSid'/>"),
        EVENT(MISSING_NAME "<Data Name='MemberSid'>-</Data>"),
        EVENT(MISSING_NAME "<Data Name='MemberSid'>S-invalid</Data>"),
        EVENT(MISSING_NAME MISSING_NAME MEMBER_SID), EVENT(MEMBER_SID MISSING_NAME MEMBER_SID),
        EVENT("<Data Other=\" Name='MemberName' \">-</Data>" MEMBER_SID),
        EVENT("<Data Name='MemberName'>-" MEMBER_SID),
        "<Event><EventData>" MISSING_NAME "</EventData><UserData>" MEMBER_SID "</UserData></Event>",
        "<Event><UserData>" EVENT(MISSING_NAME MEMBER_SID) "</UserData></Event>",
    };
    for (size_t i = 0; i < sizeof(events) / sizeof(*events); ++i) {
        check_enrichment(events[i], events[i]);
    }
}

static void test_account_lookup_failure(void **state) {
    (void)state;
    const char *event = EVENT(MISSING_NAME MEMBER_SID);
    expect_utf8_LookupAccountSid_call(NULL, NULL, FALSE);
    check_enrichment(event, event);
    expect_utf8_LookupAccountSid_call(NULL, strdup("DOMAIN"), TRUE);
    check_enrichment(event, event);
    expect_utf8_LookupAccountSid_call(strdup("alice"), NULL, TRUE);
    check_enrichment(event, event);
    expect_utf8_LookupAccountSid_call(strdup(""), strdup("DOMAIN"), TRUE);
    check_enrichment(event, event);
    expect_utf8_LookupAccountSid_call(strdup("bad\x01"), strdup(""), TRUE);
    check_enrichment(event, event);
}

static void test_empty_and_self_closing_names(void **state) {
    (void)state;
    expect_utf8_LookupAccountSid_call(strdup("alice"), strdup(""), TRUE);
    check_enrichment(EVENT("<Data Name='MemberName'></Data>" MEMBER_SID),
                     EVENT("<Data Name='MemberName'>alice</Data>" MEMBER_SID));

    const char *prefix = "<Event><System><EventID>4732</EventID></System><EventData Name='GroupChange'>"
                         MEMBER_SID "<Data Name='Optional'/> <Data Other='a>b' Name = \"MemberName\" ";
    char input[512], expected[512];
    snprintf(input, sizeof(input), "%s/></EventData></Event>", prefix);
    snprintf(expected, sizeof(expected), "%s>D&amp;\\A&lt;&gt;</Data></EventData></Event>", prefix);
    expect_utf8_LookupAccountSid_call(strdup("A<>"), strdup("D&"), TRUE);
    check_enrichment(input, expected);
}

static void test_queue_boundary(void **state) {
    (void)state;
    const char *input = EVENT(MISSING_NAME MEMBER_SID);
    const char *enriched = EVENT("<Data Name='MemberName'>a&amp;b</Data>" MEMBER_SID);
    const size_t limit = OS_MAXSTR - sizeof("f:EventChannel:");
    /* Whitespace before the root's closing tag pads an otherwise identical event. */
    for (size_t extra = 0; extra <= 1; ++extra) {
        size_t padding = limit - strlen(enriched) + extra;
        char *xml = malloc(limit + 2);
        char *expected = malloc(limit + 2);
        const char *wanted = extra ? input : enriched;
        snprintf(xml, limit + 2, "%.*s%*s</Event>", (int)(strlen(input) - 8), input, (int)padding, "");
        snprintf(expected, limit + 2, "%.*s%*s</Event>", (int)(strlen(wanted) - 8), wanted, (int)padding, "");
        expect_utf8_LookupAccountSid_call(strdup("a&b"), strdup(""), TRUE);
        check_enrichment(xml, expected);
        free(expected);
        free(xml);
    }
}

void test_send_channel_event_render_buffer_size_fail(void ** state) {
    os_channel *channel = (os_channel *)*state;
    EVT_HANDLE evt = (EVT_HANDLE)1;

    expect_value(wrap_EvtRender, Context, NULL);
    expect_value(wrap_EvtRender, Fragment, evt);
    expect_value(wrap_EvtRender, Flags, EvtRenderEventXml);
    expect_value(wrap_EvtRender, BufferSize, 0);
    will_return(wrap_EvtRender, NULL);
    will_return(wrap_EvtRender, 100);
    will_return(wrap_EvtRender, 0);
    will_return(wrap_EvtRender, FALSE);

    /* GetLastError called twice: once in condition check, once in merror */
    will_return(wrap_GetLastError, ERROR_INVALID_PARAMETER);
    will_return(wrap_GetLastError, ERROR_INVALID_PARAMETER);

    expect_string(__wrap__merror, formatted_msg,
        "Could not EvtRender() to determine buffer size for (Application) which returned (87)");

    send_channel_event(evt, channel);
}

static void check_forwarded_event(os_channel *channel, const char *expected) {
    EVT_HANDLE evt = (EVT_HANDLE)1;
    WCHAR xml_wide[] = L"<Event><EventData><Data Name='MemberName'>-</Data>"
                       L"<Data Name='MemberSid'>S-1-5-18</Data></EventData></Event>";

    /* First EvtRender call to get buffer size */
    expect_value(wrap_EvtRender, Context, NULL);
    expect_value(wrap_EvtRender, Fragment, evt);
    expect_value(wrap_EvtRender, Flags, EvtRenderEventXml);
    expect_value(wrap_EvtRender, BufferSize, 0);
    will_return(wrap_EvtRender, NULL);
    will_return(wrap_EvtRender, (wcslen(xml_wide) + 1) * sizeof(WCHAR));
    will_return(wrap_EvtRender, 0);
    will_return(wrap_EvtRender, FALSE);
    will_return(wrap_GetLastError, ERROR_INSUFFICIENT_BUFFER);

    /* Second EvtRender call to get actual data */
    expect_value(wrap_EvtRender, Context, NULL);
    expect_value(wrap_EvtRender, Fragment, evt);
    expect_value(wrap_EvtRender, Flags, EvtRenderEventXml);
    expect_value(wrap_EvtRender, BufferSize, (wcslen(xml_wide) + 1) * sizeof(WCHAR));
    will_return(wrap_EvtRender, xml_wide);
    will_return(wrap_EvtRender, (wcslen(xml_wide) + 1) * sizeof(WCHAR));
    will_return(wrap_EvtRender, 0);
    will_return(wrap_EvtRender, TRUE);

    expect_string(__wrap_SendMSG, message, expected);
    expect_string(__wrap_SendMSG, locmsg, "EventChannel");
    expect_value(__wrap_SendMSG, loc, WIN_EVT_MQ);
    will_return(__wrap_SendMSG, 0);

    send_channel_event(evt, channel);
}

static void test_send_channel_event_success(void **state) {
    check_forwarded_event(*state, EVENT(MISSING_NAME MEMBER_SID));
}

static void test_send_security_event(void **state) {
    os_channel *channel = *state;
    os_free(channel->evt_log);
    channel->evt_log = strdup("security");
    expect_utf8_LookupAccountSid_call(strdup("alice"), strdup("DOMAIN"), TRUE);
    check_forwarded_event(channel, EVENT("<Data Name='MemberName'>DOMAIN\\alice</Data>" MEMBER_SID));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ineligible_events),
        cmocka_unit_test(test_account_lookup_failure),
        cmocka_unit_test(test_empty_and_self_closing_names),
        cmocka_unit_test(test_queue_boundary),
        cmocka_unit_test_setup_teardown(test_send_security_event, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_send_channel_event_render_buffer_size_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_send_channel_event_success, test_setup, test_teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
