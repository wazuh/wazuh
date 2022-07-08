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

#include "../wrappers/common.h"
#include "../wrappers/posix/time_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/shared/cluster_utils_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_global_helpers_wrappers.h"

typedef struct test_struct {
    analysisd_agent_state_t *agent_state;
    OSHashNode *hash_node;
    cJSON * state_json;
} test_struct_t;

extern analysisd_state_t analysisd_state;
extern queue_status_t queue_status;
extern OSHash *analysisd_agents_state;

analysisd_agent_state_t * get_node(const char *agent_id);
void w_analysisd_clean_agents_state();
/* setup/teardown */

static int test_setup(void ** state) {
    test_struct_t *test_data = NULL;
    os_calloc(1, sizeof(test_struct_t),test_data);
    os_calloc(1, sizeof(analysisd_agent_state_t), test_data->agent_state);
    os_calloc(1, sizeof(OSHashNode), test_data->hash_node);

    analysisd_state.received_bytes = 123654789;
    analysisd_state.events_received = 4589;
    analysisd_state.events_decoded_breakdown.agent = 1;
    analysisd_state.events_decoded_breakdown.agentless = 15;
    analysisd_state.events_decoded_breakdown.dbsync = 350;
    analysisd_state.events_decoded_breakdown.monitor = 2;
    analysisd_state.events_decoded_breakdown.remote = 8;
    analysisd_state.events_decoded_breakdown.syslog = 48;
    analysisd_state.events_decoded_breakdown.integrations.virustotal = 13;
    analysisd_state.events_decoded_breakdown.modules.aws = 19;
    analysisd_state.events_decoded_breakdown.modules.azure = 46;
    analysisd_state.events_decoded_breakdown.modules.ciscat = 11;
    analysisd_state.events_decoded_breakdown.modules.command = 25;
    analysisd_state.events_decoded_breakdown.modules.docker = 36;
    analysisd_state.events_decoded_breakdown.modules.gcp = 6;
    analysisd_state.events_decoded_breakdown.modules.github = 98;
    analysisd_state.events_decoded_breakdown.modules.office365 = 114;
    analysisd_state.events_decoded_breakdown.modules.oscap = 2;
    analysisd_state.events_decoded_breakdown.modules.osquery = 55;
    analysisd_state.events_decoded_breakdown.modules.rootcheck = 149;
    analysisd_state.events_decoded_breakdown.modules.sca = 1352;
    analysisd_state.events_decoded_breakdown.modules.syscheck = 1258;
    analysisd_state.events_decoded_breakdown.modules.syscollector = 589;
    analysisd_state.events_decoded_breakdown.modules.upgrade = 1;
    analysisd_state.events_decoded_breakdown.modules.vulnerability = 18;
    analysisd_state.events_decoded_breakdown.modules.logcollector.eventchannel = 695;
    analysisd_state.events_decoded_breakdown.modules.logcollector.eventlog = 125;
    analysisd_state.events_decoded_breakdown.modules.logcollector.macos = 36;
    analysisd_state.events_decoded_breakdown.modules.logcollector.others = 2011;
    analysisd_state.events_dropped_breakdown.agent = 0;
    analysisd_state.events_dropped_breakdown.agentless = 2;
    analysisd_state.events_dropped_breakdown.dbsync = 39;
    analysisd_state.events_dropped_breakdown.monitor = 0;
    analysisd_state.events_dropped_breakdown.remote = 0;
    analysisd_state.events_dropped_breakdown.syslog = 4;
    analysisd_state.events_dropped_breakdown.integrations.virustotal = 1;
    analysisd_state.events_dropped_breakdown.modules.aws = 0;
    analysisd_state.events_dropped_breakdown.modules.azure = 0;
    analysisd_state.events_dropped_breakdown.modules.ciscat = 0;
    analysisd_state.events_dropped_breakdown.modules.command = 3;
    analysisd_state.events_dropped_breakdown.modules.docker = 0;
    analysisd_state.events_dropped_breakdown.modules.gcp = 1;
    analysisd_state.events_dropped_breakdown.modules.github = 8;
    analysisd_state.events_dropped_breakdown.modules.office365 = 12;
    analysisd_state.events_dropped_breakdown.modules.oscap = 0;
    analysisd_state.events_dropped_breakdown.modules.osquery = 0;
    analysisd_state.events_dropped_breakdown.modules.rootcheck = 33;
    analysisd_state.events_dropped_breakdown.modules.sca = 25;
    analysisd_state.events_dropped_breakdown.modules.syscheck = 98;
    analysisd_state.events_dropped_breakdown.modules.syscollector = 14;
    analysisd_state.events_dropped_breakdown.modules.upgrade = 0;
    analysisd_state.events_dropped_breakdown.modules.vulnerability = 1;
    analysisd_state.events_dropped_breakdown.modules.logcollector.eventchannel = 25;
    analysisd_state.events_dropped_breakdown.modules.logcollector.eventlog = 2;
    analysisd_state.events_dropped_breakdown.modules.logcollector.macos = 1;
    analysisd_state.events_dropped_breakdown.modules.logcollector.others = 36;
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

    test_mode = 0;
    will_return(__wrap_time, 123456789);
    analysisd_agents_state = __wrap_OSHash_Create();

    test_data->agent_state->events_processed = 1286;
    test_data->agent_state->alerts_written = 269;
    test_data->agent_state->archives_written = 1286;
    test_data->agent_state->firewall_written = 15;
    test_data->agent_state->events_decoded_breakdown.agent = 1;
    test_data->agent_state->events_decoded_breakdown.dbsync = 154;
    test_data->agent_state->events_decoded_breakdown.monitor = 2;
    test_data->agent_state->events_decoded_breakdown.remote = 2;
    test_data->agent_state->events_decoded_breakdown.modules.aws = 39;
    test_data->agent_state->events_decoded_breakdown.modules.azure = 14;
    test_data->agent_state->events_decoded_breakdown.modules.ciscat = 22;
    test_data->agent_state->events_decoded_breakdown.modules.command = 5;
    test_data->agent_state->events_decoded_breakdown.modules.docker = 39;
    test_data->agent_state->events_decoded_breakdown.modules.gcp = 12;
    test_data->agent_state->events_decoded_breakdown.modules.github = 44;
    test_data->agent_state->events_decoded_breakdown.modules.office365 = 6;
    test_data->agent_state->events_decoded_breakdown.modules.oscap = 0;
    test_data->agent_state->events_decoded_breakdown.modules.osquery = 12;
    test_data->agent_state->events_decoded_breakdown.modules.rootcheck = 25;
    test_data->agent_state->events_decoded_breakdown.modules.sca = 68;
    test_data->agent_state->events_decoded_breakdown.modules.syscheck = 514;
    test_data->agent_state->events_decoded_breakdown.modules.syscollector = 320;
    test_data->agent_state->events_decoded_breakdown.modules.upgrade = 10;
    test_data->agent_state->events_decoded_breakdown.modules.vulnerability = 14;
    test_data->agent_state->events_decoded_breakdown.modules.logcollector.eventchannel = 37;
    test_data->agent_state->events_decoded_breakdown.modules.logcollector.eventlog = 15;
    test_data->agent_state->events_decoded_breakdown.modules.logcollector.macos = 36;
    test_data->agent_state->events_decoded_breakdown.modules.logcollector.others = 55;
    test_data->agent_state->events_decoded_breakdown.integrations.virustotal = 1;

    OSHash_Add_ex(analysisd_agents_state, "001", test_data->agent_state);
    test_mode = 1;

    test_data->hash_node->key = "001";
    test_data->hash_node->data = test_data->agent_state;

    *state = test_data;

    return 0;
}

static int test_teardown(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;

    cJSON_Delete(test_data->state_json);

    if (analysisd_agents_state) {
        OSHash_Free(analysisd_agents_state);
        analysisd_agents_state = NULL;
    }

    os_free(decode_queue_syscheck_input->data);
    os_free(decode_queue_syscollector_input->data);
    os_free(decode_queue_rootcheck_input->data);
    os_free(decode_queue_sca_input->data);
    os_free(decode_queue_hostinfo_input->data);
    os_free(decode_queue_winevt_input->data);
    os_free(dispatch_dbsync_input->data);
    os_free(upgrade_module_input->data);
    os_free(decode_queue_event_input->data);
    os_free(decode_queue_event_output->data);
    os_free(writer_queue_log->data);
    os_free(writer_queue_log_firewall->data);
    os_free(writer_queue_log_fts->data);
    os_free(writer_queue_log_statistical->data);
    os_free(writer_queue->data);
    os_free(decode_queue_syscheck_input);
    os_free(decode_queue_syscollector_input);
    os_free(decode_queue_rootcheck_input);
    os_free(decode_queue_sca_input);
    os_free(decode_queue_hostinfo_input);
    os_free(decode_queue_winevt_input);
    os_free(dispatch_dbsync_input);
    os_free(upgrade_module_input);
    os_free(decode_queue_event_input);
    os_free(decode_queue_event_output);
    os_free(writer_queue_log);
    os_free(writer_queue_log_firewall);
    os_free(writer_queue_log_fts);
    os_free(writer_queue_log_statistical);
    os_free(writer_queue);

    os_free(test_data->hash_node);
    os_free(test_data);

    return 0;
}

static int test_setup_empty_hash_table(void ** state) {
    test_struct_t *test_data = NULL;
    os_calloc(1, sizeof(test_struct_t),test_data);
    os_calloc(1, sizeof(analysisd_agent_state_t), test_data->agent_state);

    test_mode = 0;
    will_return(__wrap_time, 123456789);
    analysisd_agents_state = __wrap_OSHash_Create();
    test_mode = 1;

    *state = test_data;

    return 0;
}

static int test_teardown_empty_hash_table(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;

    if (analysisd_agents_state) {
        OSHash_Free(analysisd_agents_state);
        analysisd_agents_state = NULL;
    }

    os_free(test_data->agent_state);
    os_free(test_data);

    return 0;
}

/* Tests */

void test_asys_create_state_json(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;

    will_return(__wrap_time, 123456789);

    expect_value(__wrap_OSHash_Begin, self, analysisd_agents_state);
    will_return(__wrap_OSHash_Begin, test_data->hash_node);

    expect_value(__wrap_OSHash_Next, self, analysisd_agents_state);
    will_return(__wrap_OSHash_Next, NULL);

    test_data->state_json = asys_create_state_json();

    assert_non_null(test_data->state_json);

    assert_non_null(cJSON_GetObjectItem(test_data->state_json, "statistics"));
    cJSON* statistics = cJSON_GetObjectItem(test_data->state_json, "statistics");

    assert_non_null(cJSON_GetObjectItem(statistics, "received_bytes"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "received_bytes")->valueint, 123654789);

    assert_non_null(cJSON_GetObjectItem(statistics, "events_received"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "events_received")->valueint, 4589);

    assert_non_null(cJSON_GetObjectItem(statistics, "events_received_breakdown"));
    cJSON* recv = cJSON_GetObjectItem(statistics, "events_received_breakdown");

    assert_non_null(cJSON_GetObjectItem(recv, "events_decoded_breakdown"));
    cJSON* decoded = cJSON_GetObjectItem(recv, "events_decoded_breakdown");

    assert_non_null(cJSON_GetObjectItem(decoded, "agent_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "agent_decoded")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(decoded, "agentless_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "agentless_decoded")->valueint, 15);
    assert_non_null(cJSON_GetObjectItem(decoded, "dbsync_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "dbsync_decoded")->valueint, 350);
    assert_non_null(cJSON_GetObjectItem(decoded, "monitor_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "monitor_decoded")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(decoded, "remote_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "remote_decoded")->valueint, 8);
    assert_non_null(cJSON_GetObjectItem(decoded, "syslog_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "syslog_decoded")->valueint, 48);

    assert_non_null(cJSON_GetObjectItem(decoded, "integrations_decoded"));
    cJSON* decoded_int = cJSON_GetObjectItem(decoded, "integrations_decoded");

    assert_non_null(cJSON_GetObjectItem(decoded_int, "virustotal_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_int, "virustotal_decoded")->valueint, 13);

    assert_non_null(cJSON_GetObjectItem(decoded, "modules_decoded"));
    cJSON* decoded_mod = cJSON_GetObjectItem(decoded, "modules_decoded");

    assert_non_null(cJSON_GetObjectItem(decoded_mod, "aws_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "aws_decoded")->valueint, 19);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "azure_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "azure_decoded")->valueint, 46);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "ciscat_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "ciscat_decoded")->valueint, 11);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "command_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "command_decoded")->valueint, 25);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "docker_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "docker_decoded")->valueint, 36);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "gcp_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "gcp_decoded")->valueint, 6);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "github_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "github_decoded")->valueint, 98);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "office365_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "office365_decoded")->valueint, 114);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "oscap_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "oscap_decoded")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "osquery_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "osquery_decoded")->valueint, 55);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "rootcheck_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "rootcheck_decoded")->valueint, 149);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "sca_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "sca_decoded")->valueint, 1352);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "syscheck_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "syscheck_decoded")->valueint, 1258);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "syscollector_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "syscollector_decoded")->valueint, 589);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "upgrade_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "upgrade_decoded")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "vulnerability_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "vulnerability_decoded")->valueint, 18);

    assert_non_null(cJSON_GetObjectItem(decoded_mod, "logcollector_decoded"));
    cJSON* decoded_mod_log = cJSON_GetObjectItem(decoded_mod, "logcollector_decoded");

    assert_non_null(cJSON_GetObjectItem(decoded_mod_log, "eventchannel_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod_log, "eventchannel_decoded")->valueint, 695);
    assert_non_null(cJSON_GetObjectItem(decoded_mod_log, "eventlog_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod_log, "eventlog_decoded")->valueint, 125);
    assert_non_null(cJSON_GetObjectItem(decoded_mod_log, "macos_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod_log, "macos_decoded")->valueint, 36);
    assert_non_null(cJSON_GetObjectItem(decoded_mod_log, "others_decoded"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod_log, "others_decoded")->valueint, 2011);

    assert_non_null(cJSON_GetObjectItem(recv, "events_dropped_breakdown"));
    cJSON* dropped = cJSON_GetObjectItem(recv, "events_dropped_breakdown");

    assert_non_null(cJSON_GetObjectItem(dropped, "agent_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "agent_dropped")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped, "agentless_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "agentless_dropped")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(dropped, "dbsync_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "dbsync_dropped")->valueint, 39);
    assert_non_null(cJSON_GetObjectItem(dropped, "monitor_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "monitor_dropped")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped, "remote_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "remote_dropped")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped, "syslog_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "syslog_dropped")->valueint, 4);

    assert_non_null(cJSON_GetObjectItem(dropped, "integrations_dropped"));
    cJSON* dropped_int = cJSON_GetObjectItem(dropped, "integrations_dropped");

    assert_non_null(cJSON_GetObjectItem(dropped_int, "virustotal_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_int, "virustotal_dropped")->valueint, 1);

    assert_non_null(cJSON_GetObjectItem(dropped, "modules_dropped"));
    cJSON* dropped_mod = cJSON_GetObjectItem(dropped, "modules_dropped");

    assert_non_null(cJSON_GetObjectItem(dropped_mod, "aws_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "aws_dropped")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "azure_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "azure_dropped")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "ciscat_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "ciscat_dropped")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "command_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "command_dropped")->valueint, 3);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "docker_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "docker_dropped")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "gcp_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "gcp_dropped")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "github_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "github_dropped")->valueint, 8);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "office365_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "office365_dropped")->valueint, 12);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "oscap_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "oscap_dropped")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "osquery_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "osquery_dropped")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "rootcheck_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "rootcheck_dropped")->valueint, 33);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "sca_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "sca_dropped")->valueint, 25);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "syscheck_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "syscheck_dropped")->valueint, 98);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "syscollector_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "syscollector_dropped")->valueint, 14);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "upgrade_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "upgrade_dropped")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "vulnerability_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "vulnerability_dropped")->valueint, 1);

    assert_non_null(cJSON_GetObjectItem(dropped_mod, "logcollector_dropped"));
    cJSON* dropped_mod_log = cJSON_GetObjectItem(dropped_mod, "logcollector_dropped");

    assert_non_null(cJSON_GetObjectItem(dropped_mod_log, "eventchannel_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod_log, "eventchannel_dropped")->valueint, 25);
    assert_non_null(cJSON_GetObjectItem(dropped_mod_log, "eventlog_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod_log, "eventlog_dropped")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(dropped_mod_log, "macos_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod_log, "macos_dropped")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(dropped_mod_log, "others_dropped"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod_log, "others_dropped")->valueint, 36);

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

    assert_non_null(cJSON_GetObjectItem(test_data->state_json, "agents_connected"));
    cJSON* agents_connected = cJSON_GetObjectItem(test_data->state_json, "agents_connected");

    assert_non_null(cJSON_GetArrayItem(agents_connected, 0));
    cJSON* agent_connected = cJSON_GetArrayItem(agents_connected, 0);
    assert_int_equal(cJSON_GetObjectItem(agent_connected, "agent_id")->valueint, 1);

    assert_non_null(cJSON_GetObjectItem(agent_connected, "statistics"));
    cJSON* agent_statistics = cJSON_GetObjectItem(agent_connected, "statistics");

    assert_int_equal(cJSON_GetObjectItem(agent_statistics, "events_processed")->valueint, 1286);
    assert_int_equal(cJSON_GetObjectItem(agent_statistics, "alerts_written")->valueint, 269);
    assert_int_equal(cJSON_GetObjectItem(agent_statistics, "firewall_written")->valueint, 15);
    assert_int_equal(cJSON_GetObjectItem(agent_statistics, "archives_written")->valueint, 1286);

    assert_non_null(cJSON_GetObjectItem(agent_statistics, "events_received_breakdown"));
    cJSON* events_received_breakdown = cJSON_GetObjectItem(agent_statistics, "events_received_breakdown");

    assert_non_null(cJSON_GetObjectItem(events_received_breakdown, "events_decoded_breakdown"));
    cJSON* events_decoded_breakdown = cJSON_GetObjectItem(events_received_breakdown, "events_decoded_breakdown");

    assert_int_equal(cJSON_GetObjectItem(events_decoded_breakdown, "agent_decoded")->valueint, 1);
    assert_int_equal(cJSON_GetObjectItem(events_decoded_breakdown, "dbsync_decoded")->valueint, 154);
    assert_int_equal(cJSON_GetObjectItem(events_decoded_breakdown, "monitor_decoded")->valueint, 2);
    assert_int_equal(cJSON_GetObjectItem(events_decoded_breakdown, "remote_decoded")->valueint, 2);

    assert_non_null(cJSON_GetObjectItem(events_decoded_breakdown, "integrations_decoded"));
    cJSON* integrations_decoded = cJSON_GetObjectItem(events_decoded_breakdown, "integrations_decoded");

    assert_int_equal(cJSON_GetObjectItem(integrations_decoded, "virustotal_decoded")->valueint, 1);

    assert_non_null(cJSON_GetObjectItem(events_decoded_breakdown, "modules_decoded"));
    cJSON* modules_decoded = cJSON_GetObjectItem(events_decoded_breakdown, "modules_decoded");

    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "aws_decoded")->valueint, 39);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "azure_decoded")->valueint, 14);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "ciscat_decoded")->valueint, 22);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "command_decoded")->valueint, 5);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "docker_decoded")->valueint, 39);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "gcp_decoded")->valueint, 12);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "github_decoded")->valueint, 44);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "office365_decoded")->valueint, 6);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "oscap_decoded")->valueint, 0);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "osquery_decoded")->valueint, 12);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "rootcheck_decoded")->valueint, 25);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "sca_decoded")->valueint, 68);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "syscheck_decoded")->valueint, 514);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "syscollector_decoded")->valueint, 320);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "upgrade_decoded")->valueint, 10);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "vulnerability_decoded")->valueint, 14);

    assert_non_null(cJSON_GetObjectItem(modules_decoded, "logcollector_decoded"));
    cJSON* logcollector_decoded = cJSON_GetObjectItem(modules_decoded, "logcollector_decoded");

    assert_int_equal(cJSON_GetObjectItem(logcollector_decoded, "eventchannel_decoded")->valueint, 37);
    assert_int_equal(cJSON_GetObjectItem(logcollector_decoded, "eventlog_decoded")->valueint, 15);
    assert_int_equal(cJSON_GetObjectItem(logcollector_decoded, "macos_decoded")->valueint, 36);
    assert_int_equal(cJSON_GetObjectItem(logcollector_decoded, "others_decoded")->valueint, 55);

    os_free(test_data->agent_state);
}

void test_asys_get_node_new_node(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;
    const char *agent_id = "001";

    expect_value(__wrap_OSHash_Get_ex, self, analysisd_agents_state);
    expect_string(__wrap_OSHash_Get_ex, key, agent_id);
    will_return(__wrap_OSHash_Get_ex, NULL);

    expect_value(__wrap_OSHash_Add_ex, self, analysisd_agents_state);
    expect_string(__wrap_OSHash_Add_ex, key, agent_id);
    expect_memory(__wrap_OSHash_Add_ex, data, test_data->agent_state, sizeof(test_data->agent_state));
    will_return(__wrap_OSHash_Add_ex, 2);

    analysisd_agent_state_t *agent_state_returned = get_node(agent_id);

    assert_non_null(agent_state_returned);

    os_free(agent_state_returned);
}

void test_asys_get_node_existing_node(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;
    const char *agent_id = "001";

    expect_value(__wrap_OSHash_Get_ex, self, analysisd_agents_state);
    expect_string(__wrap_OSHash_Get_ex, key, agent_id);
    will_return(__wrap_OSHash_Get_ex, test_data->agent_state);

    analysisd_agent_state_t *agent_state_returned = get_node(agent_id);

    assert_non_null(agent_state_returned);

    os_free(test_data->agent_state);
}

void test_w_analysisd_clean_agents_state_empty_table(void ** state) {
    expect_value(__wrap_OSHash_Begin, self, analysisd_agents_state);
    will_return(__wrap_OSHash_Begin, NULL);

    w_analysisd_clean_agents_state();
}

void test_w_analysisd_clean_agents_state_completed(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;

    expect_value(__wrap_OSHash_Begin, self, analysisd_agents_state);
    will_return(__wrap_OSHash_Begin, test_data->hash_node);

    char *cluster_node_name = NULL;
    cluster_node_name = strdup("node01");
    int *connected_agents = NULL;
    os_calloc(1, sizeof(int), connected_agents);
    connected_agents[0] = OS_INVALID;

    will_return(__wrap_get_node_name, cluster_node_name);

    expect_string(__wrap_wdb_get_agents_by_connection_status, status, AGENT_CS_ACTIVE);
    expect_string(__wrap_wdb_get_agents_by_connection_status, node_name, cluster_node_name);
    will_return(__wrap_wdb_get_agents_by_connection_status, connected_agents);

    expect_value(__wrap_OSHash_Next, self, analysisd_agents_state);
    will_return(__wrap_OSHash_Next, NULL);

    expect_value(__wrap_OSHash_Delete_ex, self, analysisd_agents_state);
    expect_value(__wrap_OSHash_Delete_ex, key, "001");
    will_return(__wrap_OSHash_Delete_ex, test_data->agent_state);

    w_analysisd_clean_agents_state();

    os_free(connected_agents);
}

void test_w_analysisd_clean_agents_state_completed_without_delete(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;

    expect_value(__wrap_OSHash_Begin, self, analysisd_agents_state);
    will_return(__wrap_OSHash_Begin, test_data->hash_node);

    char *cluster_node_name = NULL;
    cluster_node_name = strdup("node01");
    int *connected_agents = NULL;
    os_calloc(1, sizeof(int), connected_agents);
    connected_agents[0] = 1;

    will_return(__wrap_get_node_name, cluster_node_name);

    expect_string(__wrap_wdb_get_agents_by_connection_status, status, AGENT_CS_ACTIVE);
    expect_string(__wrap_wdb_get_agents_by_connection_status, node_name, cluster_node_name);
    will_return(__wrap_wdb_get_agents_by_connection_status, connected_agents);

    expect_value(__wrap_OSHash_Next, self, analysisd_agents_state);
    will_return(__wrap_OSHash_Next, NULL);

    w_analysisd_clean_agents_state();

    os_free(connected_agents);
    os_free(test_data->agent_state);
}

void test_w_analysisd_clean_agents_state_query_fail(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;

    expect_value(__wrap_OSHash_Begin, self, analysisd_agents_state);
    will_return(__wrap_OSHash_Begin, test_data->hash_node);

    char *cluster_node_name = NULL;
    cluster_node_name = strdup("node01");
    int *connected_agents = NULL;

    will_return(__wrap_get_node_name, cluster_node_name);

    expect_string(__wrap_wdb_get_agents_by_connection_status, status, AGENT_CS_ACTIVE);
    expect_string(__wrap_wdb_get_agents_by_connection_status, node_name, cluster_node_name);
    will_return(__wrap_wdb_get_agents_by_connection_status, connected_agents);

    expect_string(__wrap__merror, formatted_msg, "Unable to get connected agents.");

    w_analysisd_clean_agents_state();
    os_free(test_data->agent_state);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test asys_create_state_json
        cmocka_unit_test_setup_teardown(test_asys_create_state_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_asys_get_node_new_node, test_setup_empty_hash_table, test_teardown_empty_hash_table),
        cmocka_unit_test_setup_teardown(test_asys_get_node_existing_node, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_analysisd_clean_agents_state_empty_table, test_setup_empty_hash_table, test_teardown_empty_hash_table),
        cmocka_unit_test_setup_teardown(test_w_analysisd_clean_agents_state_completed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_analysisd_clean_agents_state_completed_without_delete, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_analysisd_clean_agents_state_query_fail, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
