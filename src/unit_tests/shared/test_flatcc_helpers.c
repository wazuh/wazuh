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

#include "../../generated_headers/syscollector_deltas_builder.h"
#include "../../generated_headers/syscollector_deltas_json_parser.h"
#include "../../generated_headers/syscollector_deltas_json_printer.h"
#include "../../generated_headers/syscollector_deltas_verifier.h"
#include "../../generated_headers/syscollector_synchronization_builder.h"
#include "../../generated_headers/syscollector_synchronization_json_parser.h"
#include "../../generated_headers/syscollector_synchronization_json_printer.h"
#include "../../generated_headers/syscollector_synchronization_verifier.h"
#include "../../headers/defs.h"
#include "../../headers/flatcc_helpers.h"


void test_w_flatcc_parse_json_parse_dbsync_sucess (void **state) {
    const char* msg_to_send = "{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_processes\",\"data\":{\"argvs\":null,\"checksum\":\"ecc9b586fcba7bd1d4c6cbaf33623767a307093b\",\"cmd\":null,\"egroup\":\"root\",\"euser\":\"root\",\"fgroup\":\"root\",\"name\":\"kworker/u16:2-e\",\"nice\":0,\"nlwp\":1,\"pgrp\":0,\"pid\":\"18446\",\"ppid\":2,\"priority\":20,\"processor\":3,\"resident\":0,\"rgroup\":\"root\",\"ruser\":\"root\",\"scan_time\":\"2023/11/25 19:34:43\",\"session\":0,\"sgroup\":\"root\",\"share\":0,\"size\":0,\"start_time\":1700940323,\"state\":\"I\",\"stime\":1,\"suser\":\"root\",\"tgid\":18446,\"tty\":0,\"utime\":2,\"vm_size\":0},\"operation\":\"MODIFIED\"}";
    const size_t msg_to_send_len = strlen(msg_to_send);

    flatcc_json_parser_table_f *parser = SyscollectorDeltas_Delta_parse_json_table;
    size_t buffer_size, flatbuffer_size;

    void* flatbuffer = w_flatcc_parse_json(msg_to_send_len, msg_to_send, &flatbuffer_size, 0, parser);
    char* output = w_flatcc_print_json(flatbuffer, flatbuffer_size, &buffer_size, 0, SyscollectorSynchronization_SyncMsg_print_json_table);

    assert_string_equal(msg_to_send, output);
    free(output);
    w_flatcc_free_buffer(flatbuffer);
}

void test_w_flatcc_parse_json_parse_integrity_clear_success (void **state) {
    const char* msg_to_send = "{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"integrity_clear\",\"data\":{\"attributes_type\":\"syscollector_hotfixes\",\"id\":1700880716}}";
    const size_t msg_to_send_len = strlen(msg_to_send);

    flatcc_json_parser_table_f *parser = SyscollectorSynchronization_SyncMsg_parse_json_table;
    size_t buffer_size, flatbuffer_size;

    void* flatbuffer = w_flatcc_parse_json(msg_to_send_len, msg_to_send, &flatbuffer_size, 0, parser);
    char* output = w_flatcc_print_json(flatbuffer, flatbuffer_size, &buffer_size, 0, SyscollectorSynchronization_SyncMsg_print_json_table);

    assert_string_equal(msg_to_send, output);
    free(output);
    w_flatcc_free_buffer(flatbuffer);
}

void test_w_flatcc_parse_json_parse_rsync_processes_success (void **state) {
    const char* msg_to_send = "{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"state\",\"data\":{\"attributes_type\":\"syscollector_processes\",\"attributes\":{\"argvs\":\"/usr/bin/unattended-upgrade\",\"checksum\":\"07710c430f7c9c0fefd9c76ad65cac2b87dcf915\",\"cmd\":\"/usr/bin/python3\",\"egroup\":\"root\",\"euser\":\"root\",\"fgroup\":\"root\",\"name\":\"unattended-upgr\",\"nice\":0,\"nlwp\":1,\"pgrp\":5597,\"pid\":\"6459\",\"ppid\":6122,\"priority\":20,\"processor\":1,\"resident\":57764,\"rgroup\":\"root\",\"ruser\":\"root\",\"scan_time\":\"2023/11/25 02:51:58\",\"session\":5597,\"sgroup\":\"root\",\"share\":441,\"size\":83694,\"start_time\":1700880714,\"state\":\"S\",\"stime\":0,\"suser\":\"root\",\"tgid\":6459,\"tty\":0,\"utime\":0,\"vm_size\":334776},\"index\":\"6459\",\"timestamp\":\"\"}}";
    const size_t msg_to_send_len = strlen(msg_to_send);

    flatcc_json_parser_table_f *parser = SyscollectorSynchronization_SyncMsg_parse_json_table;
    size_t buffer_size, flatbuffer_size;

    void* flatbuffer = w_flatcc_parse_json(msg_to_send_len, msg_to_send, &flatbuffer_size, 0, parser);
    char* output = w_flatcc_print_json(flatbuffer, flatbuffer_size, &buffer_size, 0, SyscollectorSynchronization_SyncMsg_print_json_table);

    assert_string_equal(msg_to_send, output);
    free(output);
    w_flatcc_free_buffer(flatbuffer);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_w_flatcc_parse_json_parse_dbsync_sucess),
        cmocka_unit_test(test_w_flatcc_parse_json_parse_integrity_clear_success),
        cmocka_unit_test(test_w_flatcc_parse_json_parse_rsync_processes_success)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
