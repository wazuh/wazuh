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

#include "../wrappers/windows/winbase_wrappers.h"
#include "../wrappers/wazuh/shared/utf8_winapi_wrapper_wrappers.h"

typedef struct _os_channel {
    char *evt_log;
    char *bookmark_name;
    unsigned int flags;
    EVT_HANDLE bookmark;
    int bookmark_enabled;
    EVT_HANDLE subscription;
} os_channel;

void send_channel_event(EVT_HANDLE evt, os_channel *channel);
void enrich_member_name(char **xml_event);

#define TEST_SID "S-1-5-21-3362136261-2111957958-1377730528-1006"
#define TEST_SID_W L"S-1-5-21-3362136261-2111957958-1377730528-1006"
#define TEST_PSID ((PSID)1)

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

static void expect_member_lookup(const char *account, const char *domain) {
    expect_ConvertStringSidToSidA_call(TEST_SID, TEST_PSID, TRUE);
    expect_utf8_LookupAccountSid_call(strdup(account), strdup(domain), TRUE);
}

void test_enrich_member_name_null_inputs(void ** state) {
    (void)state;
    char *xml = NULL;

    enrich_member_name(NULL);
    enrich_member_name(&xml);
}

void test_enrich_member_name_missing_tags(void ** state) {
    (void)state;
    char *missing_name = strdup("<Event><Data Name='MemberSid'>" TEST_SID "</Data></Event>");
    char *missing_sid = strdup("<Event><Data Name='MemberName'>-</Data></Event>");
    char *original_missing_name = missing_name;
    char *original_missing_sid = missing_sid;

    enrich_member_name(&missing_name);
    enrich_member_name(&missing_sid);

    assert_ptr_equal(missing_name, original_missing_name);
    assert_ptr_equal(missing_sid, original_missing_sid);
    os_free(missing_name);
    os_free(missing_sid);
}

void test_enrich_member_name_populated_unchanged(void ** state) {
    (void)state;
    char *xml = strdup("<Event><Data Name='MemberName'>CN=Auditor</Data><Data Name='MemberSid'>" TEST_SID
                       "</Data></Event>");
    char *original = xml;

    enrich_member_name(&xml);

    assert_ptr_equal(xml, original);
    assert_string_equal(xml,
                        "<Event><Data Name='MemberName'>CN=Auditor</Data><Data Name='MemberSid'>" TEST_SID
                        "</Data></Event>");
    os_free(xml);
}

void test_enrich_member_name_empty_single_quote(void ** state) {
    (void)state;
    char *xml = strdup("<Event><Data Name='MemberName'></Data><Data Name='MemberSid'>" TEST_SID "</Data></Event>");

    expect_member_lookup("alice", "DOMAIN");

    enrich_member_name(&xml);

    assert_string_equal(xml,
                        "<Event><Data Name='MemberName'>DOMAIN\\alice</Data><Data Name='MemberSid'>" TEST_SID
                        "</Data></Event>");
    os_free(xml);
}

void test_enrich_member_name_dash_double_quote(void ** state) {
    (void)state;
    char *xml = strdup("<Event><Data Name=\"MemberName\">-</Data><Data Name=\"MemberSid\">" TEST_SID "</Data></Event>");

    expect_member_lookup("alice", "DOMAIN");

    enrich_member_name(&xml);

    assert_string_equal(xml,
                        "<Event><Data Name=\"MemberName\">DOMAIN\\alice</Data><Data Name=\"MemberSid\">" TEST_SID
                        "</Data></Event>");
    os_free(xml);
}

void test_enrich_member_name_conversion_failure(void ** state) {
    (void)state;
    char *xml = strdup("<Event><Data Name='MemberName'>-</Data><Data Name='MemberSid'>" TEST_SID "</Data></Event>");
    char *original = xml;

    expect_ConvertStringSidToSidA_call(TEST_SID, NULL, FALSE);

    enrich_member_name(&xml);

    assert_ptr_equal(xml, original);
    os_free(xml);
}

void test_enrich_member_name_lookup_failure(void ** state) {
    (void)state;
    char *xml = strdup("<Event><Data Name='MemberName'>-</Data><Data Name='MemberSid'>" TEST_SID "</Data></Event>");
    char *original = xml;

    expect_ConvertStringSidToSidA_call(TEST_SID, TEST_PSID, TRUE);
    expect_utf8_LookupAccountSid_call(NULL, NULL, FALSE);

    enrich_member_name(&xml);

    assert_ptr_equal(xml, original);
    os_free(xml);
}

void test_enrich_member_name_invalid_sid_values(void ** state) {
    (void)state;
    char *empty_sid = strdup("<Event><Data Name='MemberName'>-</Data><Data Name='MemberSid'></Data></Event>");
    char *dash_sid = strdup("<Event><Data Name='MemberName'>-</Data><Data Name='MemberSid'>-</Data></Event>");
    char *original_empty_sid = empty_sid;
    char *original_dash_sid = dash_sid;

    enrich_member_name(&empty_sid);
    enrich_member_name(&dash_sid);

    assert_ptr_equal(empty_sid, original_empty_sid);
    assert_ptr_equal(dash_sid, original_dash_sid);
    os_free(empty_sid);
    os_free(dash_sid);
}

void test_enrich_member_name_account_without_domain(void ** state) {
    (void)state;
    char *xml = strdup("<Event><Data Name='MemberName'>-</Data><Data Name='MemberSid'>" TEST_SID "</Data></Event>");

    expect_member_lookup("LOCAL SERVICE", "");

    enrich_member_name(&xml);

    assert_string_equal(xml,
                        "<Event><Data Name='MemberName'>LOCAL SERVICE</Data><Data Name='MemberSid'>" TEST_SID
                        "</Data></Event>");
    os_free(xml);
}

void test_enrich_member_name_xml_escaping(void ** state) {
    (void)state;
    char *xml = strdup("<Event><Data Name='MemberName'>-</Data><Data Name='MemberSid'>" TEST_SID "</Data></Event>");

    expect_member_lookup("a&<b>", "D&<>");

    enrich_member_name(&xml);

    assert_string_equal(xml,
                        "<Event><Data Name='MemberName'>D&amp;&lt;&gt;\\a&amp;&lt;b&gt;</Data>"
                        "<Data Name='MemberSid'>" TEST_SID "</Data></Event>");
    os_free(xml);
}

void test_enrich_member_name_empty_account_unchanged(void ** state) {
    (void)state;
    char *xml = strdup("<Event><Data Name='MemberName'>-</Data><Data Name='MemberSid'>" TEST_SID "</Data></Event>");
    char *original = xml;

    expect_ConvertStringSidToSidA_call(TEST_SID, TEST_PSID, TRUE);
    expect_utf8_LookupAccountSid_call(strdup(""), strdup("DOMAIN"), TRUE);

    enrich_member_name(&xml);

    assert_ptr_equal(xml, original);
    os_free(xml);
}

void test_enrich_member_name_null_account_unchanged(void ** state) {
    (void)state;
    char *xml = strdup("<Event><Data Name='MemberName'>-</Data><Data Name='MemberSid'>" TEST_SID "</Data></Event>");
    char *original = xml;

    expect_ConvertStringSidToSidA_call(TEST_SID, TEST_PSID, TRUE);
    expect_utf8_LookupAccountSid_call(NULL, strdup("DOMAIN"), TRUE);

    enrich_member_name(&xml);

    assert_ptr_equal(xml, original);
    os_free(xml);
}

void test_enrich_member_name_null_domain_unchanged(void ** state) {
    (void)state;
    char *xml = strdup("<Event><Data Name='MemberName'>-</Data><Data Name='MemberSid'>" TEST_SID "</Data></Event>");
    char *original = xml;

    expect_ConvertStringSidToSidA_call(TEST_SID, TEST_PSID, TRUE);
    expect_utf8_LookupAccountSid_call(strdup("alice"), NULL, TRUE);

    enrich_member_name(&xml);

    assert_ptr_equal(xml, original);
    os_free(xml);
}

void test_enrich_member_name_parse_failure(void ** state) {
    (void)state;
    char *xml = strdup("<Event><Data Name='MemberName'>-<Data Name='MemberSid'>" TEST_SID "</Data></Event>");
    char *original = xml;

    enrich_member_name(&xml);

    assert_ptr_equal(xml, original);
    os_free(xml);
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

void test_send_channel_event_success(void ** state) {
    os_channel *channel = (os_channel *)*state;
    EVT_HANDLE evt = (EVT_HANDLE)1;
    WCHAR xml_wide[] = L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Test'/></System></Event>";

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

    /* convert_windows_string mock */
    expect_any(__wrap_convert_windows_string, string);
    will_return(__wrap_convert_windows_string, strdup("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Test'/></System></Event>"));

    /* SendMSG mock - this is what we want to verify */
    expect_string(__wrap_SendMSG, message, "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Test'/></System></Event>");
    expect_string(__wrap_SendMSG, locmsg, "EventChannel");
    expect_value(__wrap_SendMSG, loc, WIN_EVT_MQ);
    will_return(__wrap_SendMSG, 0);

    send_channel_event(evt, channel);
}

void test_send_channel_event_enriches_member_name(void ** state) {
    os_channel *channel = (os_channel *)*state;
    EVT_HANDLE evt = (EVT_HANDLE)1;
    WCHAR xml_wide[] = L"<Event><EventData><Data Name='MemberName'>-</Data><Data Name='MemberSid'>" TEST_SID_W
                       L"</Data></EventData></Event>";
    const char *xml_utf8 =
        "<Event><EventData><Data Name='MemberName'>-</Data><Data Name='MemberSid'>" TEST_SID
        "</Data></EventData></Event>";
    const char *expected =
        "<Event><EventData><Data Name='MemberName'>DOMAIN\\alice</Data><Data Name='MemberSid'>" TEST_SID
        "</Data></EventData></Event>";

    expect_value(wrap_EvtRender, Context, NULL);
    expect_value(wrap_EvtRender, Fragment, evt);
    expect_value(wrap_EvtRender, Flags, EvtRenderEventXml);
    expect_value(wrap_EvtRender, BufferSize, 0);
    will_return(wrap_EvtRender, NULL);
    will_return(wrap_EvtRender, (wcslen(xml_wide) + 1) * sizeof(WCHAR));
    will_return(wrap_EvtRender, 0);
    will_return(wrap_EvtRender, FALSE);
    will_return(wrap_GetLastError, ERROR_INSUFFICIENT_BUFFER);

    expect_value(wrap_EvtRender, Context, NULL);
    expect_value(wrap_EvtRender, Fragment, evt);
    expect_value(wrap_EvtRender, Flags, EvtRenderEventXml);
    expect_value(wrap_EvtRender, BufferSize, (wcslen(xml_wide) + 1) * sizeof(WCHAR));
    will_return(wrap_EvtRender, xml_wide);
    will_return(wrap_EvtRender, (wcslen(xml_wide) + 1) * sizeof(WCHAR));
    will_return(wrap_EvtRender, 0);
    will_return(wrap_EvtRender, TRUE);

    expect_any(__wrap_convert_windows_string, string);
    will_return(__wrap_convert_windows_string, strdup(xml_utf8));
    expect_member_lookup("alice", "DOMAIN");

    expect_string(__wrap_SendMSG, message, expected);
    expect_string(__wrap_SendMSG, locmsg, "EventChannel");
    expect_value(__wrap_SendMSG, loc, WIN_EVT_MQ);
    will_return(__wrap_SendMSG, 0);

    send_channel_event(evt, channel);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_enrich_member_name_null_inputs),
        cmocka_unit_test(test_enrich_member_name_missing_tags),
        cmocka_unit_test(test_enrich_member_name_populated_unchanged),
        cmocka_unit_test(test_enrich_member_name_empty_single_quote),
        cmocka_unit_test(test_enrich_member_name_dash_double_quote),
        cmocka_unit_test(test_enrich_member_name_conversion_failure),
        cmocka_unit_test(test_enrich_member_name_lookup_failure),
        cmocka_unit_test(test_enrich_member_name_invalid_sid_values),
        cmocka_unit_test(test_enrich_member_name_account_without_domain),
        cmocka_unit_test(test_enrich_member_name_xml_escaping),
        cmocka_unit_test(test_enrich_member_name_empty_account_unchanged),
        cmocka_unit_test(test_enrich_member_name_null_account_unchanged),
        cmocka_unit_test(test_enrich_member_name_null_domain_unchanged),
        cmocka_unit_test(test_enrich_member_name_parse_failure),
        cmocka_unit_test_setup_teardown(test_send_channel_event_render_buffer_size_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_send_channel_event_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_send_channel_event_enriches_member_name, test_setup, test_teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
