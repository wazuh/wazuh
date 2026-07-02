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
    Config.decoder_order_size = 32;
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

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_winevt_dec_time_created_no_attributes, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_dec_execution_no_attributes, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_dec_execution_one_attribute, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_dec_provider_no_attributes, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_dec_provider, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_winevt_dec_join_data_large_accumulation, test_setup, test_cleanup),
    };
    return cmocka_run_group_tests(tests, test_setup_global, NULL);
}
