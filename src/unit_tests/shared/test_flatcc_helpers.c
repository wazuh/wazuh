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
#include <stdlib.h>

#include "../../generated_headers/common_agentInfo_builder.h"
#include "../../generated_headers/common_agentInfo_json_parser.h"
#include "../../generated_headers/common_agentInfo_json_printer.h"
#include "../../generated_headers/common_agentInfo_verifier.h"
#include "../../headers/flatcc_helpers.h"

void test_w_flatcc_parse_json_parse_fail (void **state) {
    const char* msg_to_send = "{\"agent_id\":\"001\",\"invalid_key\":\"random_value\"}";
    const size_t msg_to_send_len = strlen(msg_to_send);

    flatcc_json_parser_table_f *parser = AgentInfo_parse_json_table;
    size_t buffer_size, flatbuffer_size;

    expect_string(__wrap__mdebug2, formatted_msg, "Failed to parse message with flatbuffer schema: unknown symbol");

    void* flatbuffer = w_flatcc_parse_json(msg_to_send_len, msg_to_send, &flatbuffer_size, 0, parser);

    assert_null(flatbuffer);
}

void test_w_flatcc_parse_json_success (void **state) {
    const char* msg_to_send = "{\"agent_id\":\"001\",\"node_name\":\"test_node_name\"}";
    const size_t msg_to_send_len = strlen(msg_to_send);

    flatcc_json_parser_table_f *parser = AgentInfo_parse_json_table;
    size_t buffer_size, flatbuffer_size;

    void* flatbuffer = w_flatcc_parse_json(msg_to_send_len, msg_to_send, &flatbuffer_size, 0, parser);
    char* output = w_flatcc_print_json(flatbuffer, flatbuffer_size, &buffer_size, 0, AgentInfo_print_json_table);

    assert_string_equal(msg_to_send, output);
    free(output);
    w_flatcc_free_buffer(flatbuffer);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_w_flatcc_parse_json_parse_fail),
        cmocka_unit_test(test_w_flatcc_parse_json_success)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
