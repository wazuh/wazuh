/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

#include "../../config/global-config.h"
#include "../../analysisd/eventinfo.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#define TEST_AGENT_ID   "005"
#define TEST_TIME       10005

#define FAIL_DECODE    1
#define SUCCESS_DECODE 0

extern int DecodeWinevt(Eventinfo * lf);
extern void w_free_event_info(Eventinfo * lf);
extern _Config Config;

int test_setup_global(void ** state) {
    expect_string(__wrap__mdebug1, formatted_msg, "WinevtInit completed.");
    Config.decoder_order_size = 128;
    WinevtInit();
    return 0;
}

int test_setup(void ** state) {
    Eventinfo * lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    os_strdup(TEST_AGENT_ID, lf->agent_id);
    lf->time.tv_sec = (time_t) TEST_TIME;

    *state = lf;

    // lf->log and lf->full_log are null

    return 0;
}

int test_cleanup(void ** state) {
    Eventinfo * lf = *state;

    w_free_event_info(lf);
    return 0;
}

void test_winevt_dec_time_created_no_attributes(void ** state) {
    const char * TEST_LOG_STRING = "{\"Event\":\"<Event><System><TimeCreated></TimeCreated></System></Event>\"}";

    Eventinfo * lf = *state;
    lf->log = lf->full_log = strdup(TEST_LOG_STRING);

    expect_string(__wrap__mdebug2, formatted_msg, "Decoding JSON: '{\"win\":{\"system\":{}}}'");

    int ret = DecodeWinevt(lf);
    assert_int_equal(ret, SUCCESS_DECODE);
}

void test_winevt_dec_execution_no_attributes(void ** state) {
    const char * TEST_LOG_STRING = "{\"Event\":\"<Event><System><Execution></Execution></System></Event>\"}";

    Eventinfo * lf = *state;
    lf->log = lf->full_log = strdup(TEST_LOG_STRING);

    expect_string(__wrap__mdebug2, formatted_msg, "Decoding JSON: '{\"win\":{\"system\":{}}}'");

    int ret = DecodeWinevt(lf);
    assert_int_equal(ret, SUCCESS_DECODE);
}

void test_winevt_dec_execution_one_attribute(void ** state) {
    const char * TEST_LOG_STRING = "{\"Event\":\"<Event><System><Execution ProcessID='1'></Execution></System></Event>\"}";

    Eventinfo * lf = *state;
    lf->log = lf->full_log = strdup(TEST_LOG_STRING);

    expect_string(__wrap__mdebug2, formatted_msg, "Decoding JSON: '{\"win\":{\"system\":{\"processID\":\"1'");

    int ret = DecodeWinevt(lf);
    assert_int_equal(ret, SUCCESS_DECODE);
}

void test_winevt_dec_provider_no_attributes(void ** state) {
    const char * TEST_LOG_STRING = "{\"Event\":\"<Event><System><Provider></Provider></System></Event>\"}";

    Eventinfo * lf = *state;
    lf->log = lf->full_log = strdup(TEST_LOG_STRING);

    expect_string(__wrap__mdebug2, formatted_msg, "Decoding JSON: '{\"win\":{\"system\":{}}}'");

    int ret = DecodeWinevt(lf);
    assert_int_equal(ret, SUCCESS_DECODE);
}

void test_winevt_dec_provider(void ** state) {
    const char * TEST_LOG_STRING = "{\"Event\":\"<Event><System><Provider First='1' Second='2' Third='3'></Provider><Provider Fourth='4'></Provider></System></Event>\"}";

    Eventinfo * lf = *state;
    lf->log = lf->full_log = strdup(TEST_LOG_STRING);

    expect_string(__wrap__mdebug2, formatted_msg, "Decoding JSON: '{\"win\":{\"system\":{}}}'");

    int ret = DecodeWinevt(lf);
    assert_int_equal(ret, SUCCESS_DECODE);
}

/* Test that large accumulated data from multiple unnamed <Data> elements is safely truncated.
 * When total content exceeds OS_MAXSTR, snprintf should cap writes at the buffer size.
 */
void test_winevt_dec_join_data_large_accumulation(void ** state) {
    Eventinfo * lf = *state;

    /* Build a JSON event with 5 unnamed <Data> elements, each containing 16000 bytes.
     * Total accumulation would be ~80000 bytes, exceeding OS_MAXSTR (65536).
     */
    const size_t ELEMENT_SIZE = 16000;
    const int NUM_ELEMENTS = 5;

    /* Calculate buffer size needed for the JSON payload */
    size_t json_size = 128 + (NUM_ELEMENTS * (ELEMENT_SIZE + 32));
    char * json_payload = (char *) calloc(json_size, sizeof(char));
    assert_non_null(json_payload);

    strcpy(json_payload, "{\"Event\":\"<Event><EventData>");

    char * element_content = (char *) calloc(ELEMENT_SIZE + 1, sizeof(char));
    assert_non_null(element_content);
    memset(element_content, 'A', ELEMENT_SIZE);
    element_content[ELEMENT_SIZE] = '\0';

    for (int i = 0; i < NUM_ELEMENTS; i++) {
        strcat(json_payload, "<Data>");
        strcat(json_payload, element_content);
        strcat(json_payload, "</Data>");
    }

    strcat(json_payload, "</EventData></Event>\"}");

    free(element_content);

    lf->log = lf->full_log = json_payload;

    /* We use expect_any since the exact output depends on truncation. */
    expect_any(__wrap__mdebug2, formatted_msg);

    int ret = DecodeWinevt(lf);
    assert_int_equal(ret, SUCCESS_DECODE);
}

/* Returns the value of a dynamic field, or NULL if the decoder did not produce it. */
static const char * get_field(const Eventinfo * lf, const char * key) {
    for (int i = 0; i < lf->nfields; i++) {
        if (strcmp(lf->fields[i].key, key) == 0) {
            return lf->fields[i].value;
        }
    }
    return NULL;
}

/* Windows Defender event 1116 as rendered by EvtRender: single-quoted XML attributes and names with spaces. */
void test_winevt_dec_eventdata_name_with_spaces(void ** state) {
    const char * TEST_LOG_STRING =
        "{\"Event\":\"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><Provider Name='Microsoft-Windows-Windows Defender' Guid='{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}' />"
        "<EventID>1116</EventID><Version>0</Version><Level>3</Level><Task>0</Task><Opcode>0</Opcode>"
        "<Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-06-08T06:31:57.5414550Z' />"
        "<EventRecordID>5264</EventRecordID><Correlation ActivityID='{eaeb204a-b4d3-43b2-be47-42bc20d67dff}' />"
        "<Execution ProcessID='5292' ThreadID='19172' />"
        "<Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>Rocket</Computer>"
        "<Security UserID='S-1-5-18' /></System>"
        "<EventData><Data Name='Product Name'>Microsoft Defender Antivirus</Data>"
        "<Data Name='Product Version'>4.18.26040.7</Data>"
        "<Data Name='Detection ID'>{BEE71375-8269-475C-82CD-8A33096E28CB}</Data>"
        "<Data Name='Detection Time'>2026-06-08T06:31:57.227Z</Data>"
        "<Data Name='Unused'></Data>"
        "<Data Name='Threat ID'>17463</Data>"
        "<Data Name='Threat Name'>Tool:Win32/EICAR_Test_File</Data>"
        "<Data Name='Severity ID'>5</Data>"
        "<Data Name='Severity Name'>Severe</Data>"
        "<Data Name='Category ID'>34</Data>"
        "<Data Name='Category Name'>Tool</Data>"
        "<Data Name='FWLink'>https://go.microsoft.com/fwlink/?linkid=37020</Data>"
        "<Data Name='Status Code'>1</Data>"
        "<Data Name='State'>1</Data>"
        "<Data Name='Source ID'>4</Data>"
        "<Data Name='Source Name'>Downloads and attachments</Data>"
        "<Data Name='Process Name'>Unknown</Data>"
        "<Data Name='Detection User'>Rocket\\\\Vikman</Data>"
        "<Data Name='Path'>file:_D:\\\\Vikman\\\\Downloads\\\\eicar_com.zip</Data>"
        "<Data Name='Action Name'>Not Applicable</Data>"
        "<Data Name='Error Code'>0x00000000</Data>"
        "<Data Name='Error Description'>The operation completed successfully. </Data>"
        "<Data Name='Security intelligence Version'>AV: 1.451.323.0, AS: 1.451.323.0</Data>"
        "<Data Name='Engine Version'>AM: 1.1.26040.8, NIS: 1.1.26040.8</Data>"
        "</EventData></Event>\"}";

    Eventinfo * lf = *state;
    lf->log = lf->full_log = strdup(TEST_LOG_STRING);

    expect_any(__wrap__mdebug2, formatted_msg);

    int ret = DecodeWinevt(lf);
    assert_int_equal(ret, SUCCESS_DECODE);

    assert_string_equal(get_field(lf, "win.eventdata.severityName"), "Severe");
    assert_string_equal(get_field(lf, "win.eventdata.threatName"), "Tool:Win32/EICAR_Test_File");
    assert_string_equal(get_field(lf, "win.eventdata.processName"), "Unknown");
    assert_string_equal(get_field(lf, "win.eventdata.errorCode"), "0x00000000");
    assert_string_equal(get_field(lf, "win.eventdata.errorDescription"), "The operation completed successfully.");
    assert_string_equal(get_field(lf, "win.eventdata.productName"), "Microsoft Defender Antivirus");
    assert_string_equal(get_field(lf, "win.eventdata.securityIntelligenceVersion"),
                        "AV: 1.451.323.0, AS: 1.451.323.0");
    assert_string_equal(get_field(lf, "win.eventdata.state"), "1");
    assert_non_null(get_field(lf, "win.eventdata.detectionUser"));
    assert_null(get_field(lf, "win.eventdata.severity Name"));

    for (int i = 0; i < lf->nfields; i++) {
        assert_null(strchr(lf->fields[i].key, ' '));
    }
}

/* Runs of spaces, and leading or trailing ones, collapse into a single capital letter. */
void test_winevt_dec_eventdata_name_spaces_edges(void ** state) {
    const char * TEST_LOG_STRING =
        "{\"Event\":\"<Event><EventData>"
        "<Data Name='Current security intelligence Version'>1.2</Data>"
        "<Data Name=' Lead  and double '>x</Data>"
        "</EventData></Event>\"}";

    Eventinfo * lf = *state;
    lf->log = lf->full_log = strdup(TEST_LOG_STRING);

    expect_any(__wrap__mdebug2, formatted_msg);

    int ret = DecodeWinevt(lf);
    assert_int_equal(ret, SUCCESS_DECODE);

    assert_string_equal(get_field(lf, "win.eventdata.currentSecurityIntelligenceVersion"), "1.2");
    assert_string_equal(get_field(lf, "win.eventdata.leadAndDouble"), "x");
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_winevt_dec_time_created_no_attributes, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_dec_execution_no_attributes, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_dec_execution_one_attribute, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_dec_provider_no_attributes, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_dec_provider, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_dec_join_data_large_accumulation, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_dec_eventdata_name_with_spaces, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_dec_eventdata_name_spaces_edges, test_setup, test_cleanup),
    };
    return cmocka_run_group_tests(tests, test_setup_global, NULL);
}
