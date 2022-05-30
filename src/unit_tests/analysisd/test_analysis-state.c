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

#include "analysisd/analysisd.h"
#include "analysisd/state.h"

#include "../wrappers/posix/time_wrappers.h"

extern analysisd_state_t analysisd_state;
extern queue_status_t queue_status;

/* setup/teardown */

static int test_setup(void ** state) {
    analysisd_state.events_received = 4589;
    analysisd_state.events_received_breakdown.events_decoded_breakdown.syscheck = 785;
    analysisd_state.events_received_breakdown.events_decoded_breakdown.syscollector = 458;
    analysisd_state.events_received_breakdown.events_decoded_breakdown.rootcheck = 58;
    analysisd_state.events_received_breakdown.events_decoded_breakdown.sca = 96;
    analysisd_state.events_received_breakdown.events_decoded_breakdown.hostinfo = 39;
    analysisd_state.events_received_breakdown.events_decoded_breakdown.winevt = 549;
    analysisd_state.events_received_breakdown.events_decoded_breakdown.dbsync = 1058;
    analysisd_state.events_received_breakdown.events_decoded_breakdown.upgrade = 10;
    analysisd_state.events_received_breakdown.events_decoded_breakdown.events = 1548;
    analysisd_state.events_received_breakdown.events_dropped_breakdown.syscheck = 95;
    analysisd_state.events_received_breakdown.events_dropped_breakdown.syscollector = 43;
    analysisd_state.events_received_breakdown.events_dropped_breakdown.rootcheck = 22;
    analysisd_state.events_received_breakdown.events_dropped_breakdown.sca = 12;
    analysisd_state.events_received_breakdown.events_dropped_breakdown.hostinfo = 15;
    analysisd_state.events_received_breakdown.events_dropped_breakdown.winevt = 29;
    analysisd_state.events_received_breakdown.events_dropped_breakdown.dbsync = 145;
    analysisd_state.events_received_breakdown.events_dropped_breakdown.upgrade = 0;
    analysisd_state.events_received_breakdown.events_dropped_breakdown.events = 75;
    analysisd_state.events_received_breakdown.events_unknown_breakdown.syscheck = 5;
    analysisd_state.events_received_breakdown.events_unknown_breakdown.syscollector = 3;
    analysisd_state.events_received_breakdown.events_unknown_breakdown.rootcheck = 1;
    analysisd_state.events_received_breakdown.events_unknown_breakdown.sca = 0;
    analysisd_state.events_received_breakdown.events_unknown_breakdown.hostinfo = 0;
    analysisd_state.events_received_breakdown.events_unknown_breakdown.winevt = 4;
    analysisd_state.events_received_breakdown.events_unknown_breakdown.dbsync = 15;
    analysisd_state.events_received_breakdown.events_unknown_breakdown.upgrade = 0;
    analysisd_state.events_received_breakdown.events_unknown_breakdown.events = 11;
    analysisd_state.events_processed = 4256;
    analysisd_state.alerts_written = 2154;
    analysisd_state.firewall_written = 148;
    analysisd_state.fts_written = 19;
    analysisd_state.stats_written = 564;
    analysisd_state.archives_written = 4200;

    decode_queue_syscheck_input = queue_init(4096);
    decode_queue_syscollector_input = queue_init(4096);
    decode_queue_rootcheck_input = queue_init(4096);
    decode_queue_sca_input = queue_init(4096);
    decode_queue_hostinfo_input = queue_init(4096);
    decode_queue_winevt_input = queue_init(4096);
    dispatch_dbsync_input = queue_init(4096);
    upgrade_module_input = queue_init(4096);
    decode_queue_event_input = queue_init(4096);
    decode_queue_event_output = queue_init(4096);
    writer_queue_log = queue_init(4096);
    writer_queue_log_firewall = queue_init(4096);
    writer_queue_log_fts = queue_init(4096);
    writer_queue_log_statistical = queue_init(4096);
    writer_queue = queue_init(4096);

    decode_queue_syscheck_input->size = queue_status.syscheck_queue_size = 4096;
    decode_queue_syscollector_input->size = queue_status.syscollector_queue_size = 4096;
    decode_queue_rootcheck_input->size = queue_status.rootcheck_queue_size = 4096;
    decode_queue_sca_input->size = queue_status.sca_queue_size = 4096;
    decode_queue_hostinfo_input->size = queue_status.hostinfo_queue_size = 4096;
    decode_queue_winevt_input->size = queue_status.winevt_queue_size = 4096;
    dispatch_dbsync_input->size = queue_status.dbsync_queue_size = 4096;
    upgrade_module_input->size = queue_status.upgrade_queue_size = 4096;
    decode_queue_event_input->size = queue_status.events_queue_size = 4096;
    decode_queue_event_output->size = queue_status.processed_queue_size = 4096;
    writer_queue_log->size = queue_status.alerts_queue_size = 4096;
    writer_queue_log_firewall->size = queue_status.firewall_queue_size = 4096;
    writer_queue_log_fts->size = queue_status.fts_queue_size = 4096;
    writer_queue_log_statistical->size = queue_status.stats_queue_size = 4096;
    writer_queue->size = queue_status.archives_queue_size = 4096;

    decode_queue_syscheck_input->elements = 128;
    decode_queue_syscollector_input->elements = 46;
    decode_queue_rootcheck_input->elements = 87;
    decode_queue_sca_input->elements = 15;
    decode_queue_hostinfo_input->elements = 1;
    decode_queue_winevt_input->elements = 23;
    dispatch_dbsync_input->elements = 456;
    upgrade_module_input->elements = 0;
    decode_queue_event_input->elements = 259;
    decode_queue_event_output->elements = 154;
    writer_queue_log->elements = 5;
    writer_queue_log_firewall->elements = 1;
    writer_queue_log_fts->elements = 0;
    writer_queue_log_statistical->elements = 2;
    writer_queue->elements = 24;

    return 0;
}

static int test_teardown(void ** state) {
    cJSON* json = *state;
    cJSON_Delete(json);
    return 0;
}

/* Tests */

void test_asys_create_state_json(void ** state) {

    will_return(__wrap_time, 123456789);

    cJSON* state_json = asys_create_state_json();

    *state = (void *)state_json;

    assert_non_null(state_json);

    assert_non_null(cJSON_GetObjectItem(state_json, "statistics"));
    cJSON* statistics = cJSON_GetObjectItem(state_json, "statistics");

    assert_non_null(cJSON_GetObjectItem(statistics, "events_received"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "events_received")->valueint, 4589);

    assert_non_null(cJSON_GetObjectItem(statistics, "events_received_breakdown"));
    cJSON* recv = cJSON_GetObjectItem(statistics, "events_received_breakdown");

    assert_non_null(cJSON_GetObjectItem(recv, "events_decoded"));
    assert_int_equal(cJSON_GetObjectItem(recv, "events_decoded")->valueint, 4601);

    assert_non_null(cJSON_GetObjectItem(recv, "events_decoded_breakdown"));
    cJSON* decoded = cJSON_GetObjectItem(recv, "events_decoded_breakdown");

    assert_non_null(cJSON_GetObjectItem(decoded, "syscheck_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "syscheck_decoded")->valueint, 785);
    assert_non_null(cJSON_GetObjectItem(decoded, "syscollector_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "syscollector_decoded")->valueint, 458);
    assert_non_null(cJSON_GetObjectItem(decoded, "rootcheck_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "rootcheck_decoded")->valueint, 58);
    assert_non_null(cJSON_GetObjectItem(decoded, "sca_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "sca_decoded")->valueint, 96);
    assert_non_null(cJSON_GetObjectItem(decoded, "hostinfo_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "hostinfo_decoded")->valueint, 39);
    assert_non_null(cJSON_GetObjectItem(decoded, "winevt_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "winevt_decoded")->valueint, 549);
    assert_non_null(cJSON_GetObjectItem(decoded, "dbsync_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "dbsync_decoded")->valueint, 1058);
    assert_non_null(cJSON_GetObjectItem(decoded, "upgrade_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "upgrade_decoded")->valueint, 10);
    assert_non_null(cJSON_GetObjectItem(decoded, "events_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "events_decoded")->valueint, 1548);

    assert_non_null(cJSON_GetObjectItem(recv, "events_dropped"));
    assert_int_equal(cJSON_GetObjectItem(recv, "events_dropped")->valueint, 436);

    assert_non_null(cJSON_GetObjectItem(recv, "events_dropped_breakdown"));
    cJSON* dropped = cJSON_GetObjectItem(recv, "events_dropped_breakdown");

    assert_non_null(cJSON_GetObjectItem(dropped, "syscheck_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "syscheck_dropped")->valueint, 95);
    assert_non_null(cJSON_GetObjectItem(dropped, "syscollector_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "syscollector_dropped")->valueint, 43);
    assert_non_null(cJSON_GetObjectItem(dropped, "rootcheck_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "rootcheck_dropped")->valueint, 22);
    assert_non_null(cJSON_GetObjectItem(dropped, "sca_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "sca_dropped")->valueint, 12);
    assert_non_null(cJSON_GetObjectItem(dropped, "hostinfo_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "hostinfo_dropped")->valueint, 15);
    assert_non_null(cJSON_GetObjectItem(dropped, "winevt_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "winevt_dropped")->valueint, 29);
    assert_non_null(cJSON_GetObjectItem(dropped, "dbsync_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "dbsync_dropped")->valueint, 145);
    assert_non_null(cJSON_GetObjectItem(dropped, "upgrade_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "upgrade_dropped")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped, "events_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "events_dropped")->valueint, 75);

    assert_non_null(cJSON_GetObjectItem(recv, "events_unknown"));
    assert_int_equal(cJSON_GetObjectItem(recv, "events_unknown")->valueint, 39);

    assert_non_null(cJSON_GetObjectItem(recv, "events_unknown_breakdown"));
    cJSON* unknown = cJSON_GetObjectItem(recv, "events_unknown_breakdown");

    assert_non_null(cJSON_GetObjectItem(unknown, "syscheck_unknown"));
    assert_int_equal(cJSON_GetObjectItem(unknown, "syscheck_unknown")->valueint, 5);
    assert_non_null(cJSON_GetObjectItem(unknown, "syscollector_unknown"));
    assert_int_equal(cJSON_GetObjectItem(unknown, "syscollector_unknown")->valueint, 3);
    assert_non_null(cJSON_GetObjectItem(unknown, "rootcheck_unknown"));
    assert_int_equal(cJSON_GetObjectItem(unknown, "rootcheck_unknown")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(unknown, "sca_unknown"));
    assert_int_equal(cJSON_GetObjectItem(unknown, "sca_unknown")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(unknown, "hostinfo_unknown"));
    assert_int_equal(cJSON_GetObjectItem(unknown, "hostinfo_unknown")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(unknown, "winevt_unknown"));
    assert_int_equal(cJSON_GetObjectItem(unknown, "winevt_unknown")->valueint, 4);
    assert_non_null(cJSON_GetObjectItem(unknown, "dbsync_unknown"));
    assert_int_equal(cJSON_GetObjectItem(unknown, "dbsync_unknown")->valueint, 15);
    assert_non_null(cJSON_GetObjectItem(unknown, "upgrade_unknown"));
    assert_int_equal(cJSON_GetObjectItem(unknown, "upgrade_unknown")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(unknown, "events_unknown"));
    assert_int_equal(cJSON_GetObjectItem(unknown, "events_unknown")->valueint, 11);

    assert_non_null(cJSON_GetObjectItem(statistics, "events_processed"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "events_processed")->valueint, 4256);

    assert_non_null(cJSON_GetObjectItem(statistics, "alerts_written"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "alerts_written")->valueint, 2154);

    assert_non_null(cJSON_GetObjectItem(statistics, "firewall_written"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "firewall_written")->valueint, 148);

    assert_non_null(cJSON_GetObjectItem(statistics, "fts_written"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "fts_written")->valueint, 19);

    assert_non_null(cJSON_GetObjectItem(statistics, "stats_written"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "stats_written")->valueint, 564);

    assert_non_null(cJSON_GetObjectItem(statistics, "archives_written"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "archives_written")->valueint, 4200);

    assert_non_null(cJSON_GetObjectItem(statistics, "queue_status"));
    cJSON* queue = cJSON_GetObjectItem(statistics, "queue_status");

    assert_non_null(cJSON_GetObjectItem(queue, "syscheck_queue_usage"));
    assert_float_equal(cJSON_GetObjectItem(queue, "syscheck_queue_usage")->valuedouble, 0.031, 0.001);
    assert_non_null(cJSON_GetObjectItem(queue, "syscheck_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "syscheck_queue_size")->valueint, 4096);
    assert_non_null(cJSON_GetObjectItem(queue, "syscollector_queue_usage"));
    assert_float_equal(cJSON_GetObjectItem(queue, "syscollector_queue_usage")->valuedouble, 0.011, 0.001);
    assert_non_null(cJSON_GetObjectItem(queue, "syscollector_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "syscollector_queue_size")->valueint, 4096);
    assert_non_null(cJSON_GetObjectItem(queue, "rootcheck_queue_usage"));
    assert_float_equal(cJSON_GetObjectItem(queue, "rootcheck_queue_usage")->valuedouble, 0.021, 0.001);
    assert_non_null(cJSON_GetObjectItem(queue, "rootcheck_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "rootcheck_queue_size")->valueint, 4096);
    assert_non_null(cJSON_GetObjectItem(queue, "sca_queue_usage"));
    assert_float_equal(cJSON_GetObjectItem(queue, "sca_queue_usage")->valuedouble, 0.003, 0.001);
    assert_non_null(cJSON_GetObjectItem(queue, "sca_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "sca_queue_size")->valueint, 4096);
    assert_non_null(cJSON_GetObjectItem(queue, "hostinfo_queue_usage"));
    assert_float_equal(cJSON_GetObjectItem(queue, "hostinfo_queue_usage")->valuedouble, 0, 0.001);
    assert_non_null(cJSON_GetObjectItem(queue, "hostinfo_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "hostinfo_queue_size")->valueint, 4096);
    assert_non_null(cJSON_GetObjectItem(queue, "winevt_queue_usage"));
    assert_float_equal(cJSON_GetObjectItem(queue, "winevt_queue_usage")->valuedouble, 0.005, 0.001);
    assert_non_null(cJSON_GetObjectItem(queue, "winevt_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "winevt_queue_size")->valueint, 4096);
    assert_non_null(cJSON_GetObjectItem(queue, "dbsync_queue_usage"));
    assert_float_equal(cJSON_GetObjectItem(queue, "dbsync_queue_usage")->valuedouble, 0.111, 0.001);
    assert_non_null(cJSON_GetObjectItem(queue, "dbsync_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "dbsync_queue_size")->valueint, 4096);
    assert_non_null(cJSON_GetObjectItem(queue, "upgrade_queue_usage"));
    assert_float_equal(cJSON_GetObjectItem(queue, "upgrade_queue_usage")->valuedouble, 0, 0.001);
    assert_non_null(cJSON_GetObjectItem(queue, "upgrade_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "upgrade_queue_size")->valueint, 4096);
    assert_non_null(cJSON_GetObjectItem(queue, "events_queue_usage"));
    assert_float_equal(cJSON_GetObjectItem(queue, "events_queue_usage")->valuedouble, 0.063, 0.001);
    assert_non_null(cJSON_GetObjectItem(queue, "events_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "events_queue_size")->valueint, 4096);
    assert_non_null(cJSON_GetObjectItem(queue, "processed_queue_usage"));
    assert_float_equal(cJSON_GetObjectItem(queue, "processed_queue_usage")->valuedouble, 0.037, 0.001);
    assert_non_null(cJSON_GetObjectItem(queue, "processed_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "processed_queue_size")->valueint, 4096);
    assert_non_null(cJSON_GetObjectItem(queue, "alerts_queue_usage"));
    assert_float_equal(cJSON_GetObjectItem(queue, "alerts_queue_usage")->valuedouble, 0.001, 0.001);
    assert_non_null(cJSON_GetObjectItem(queue, "alerts_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "alerts_queue_size")->valueint, 4096);
    assert_non_null(cJSON_GetObjectItem(queue, "firewall_queue_usage"));
    assert_float_equal(cJSON_GetObjectItem(queue, "firewall_queue_usage")->valuedouble, 0, 0.001);
    assert_non_null(cJSON_GetObjectItem(queue, "firewall_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "firewall_queue_size")->valueint, 4096);
    assert_non_null(cJSON_GetObjectItem(queue, "fts_queue_usage"));
    assert_float_equal(cJSON_GetObjectItem(queue, "fts_queue_usage")->valuedouble, 0, 0.001);
    assert_non_null(cJSON_GetObjectItem(queue, "fts_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "fts_queue_size")->valueint, 4096);
    assert_non_null(cJSON_GetObjectItem(queue, "stats_queue_usage"));
    assert_float_equal(cJSON_GetObjectItem(queue, "stats_queue_usage")->valuedouble, 0, 0.001);
    assert_non_null(cJSON_GetObjectItem(queue, "stats_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "stats_queue_size")->valueint, 4096);
    assert_non_null(cJSON_GetObjectItem(queue, "archives_queue_usage"));
    assert_float_equal(cJSON_GetObjectItem(queue, "archives_queue_usage")->valuedouble, 0.005, 0.001);
    assert_non_null(cJSON_GetObjectItem(queue, "archives_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "archives_queue_size")->valueint, 4096);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test asys_create_state_json
        cmocka_unit_test_setup_teardown(test_asys_create_state_json, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
