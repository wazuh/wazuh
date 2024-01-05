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

#include "../../analysisd/analysisd.h"
#include "../../analysisd/state.h"
#include "../../analysisd/config.h"

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
void w_analysisd_clean_agents_state(int *sock);
/* setup/teardown */

static int test_setup(void ** state) {
    Config.eps.maximum = 100;
    Config.eps.timeframe = 30;

    analysisd_state.uptime = 123456789;
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
    analysisd_state.events_written_breakdown.alerts_written = 2154;
    analysisd_state.events_written_breakdown.firewall_written = 148;
    analysisd_state.events_written_breakdown.fts_written = 19;
    analysisd_state.events_written_breakdown.stats_written = 564;
    analysisd_state.events_written_breakdown.archives_written = 4200;
    analysisd_state.eps_state_breakdown.events_dropped = 552;
    analysisd_state.eps_state_breakdown.events_dropped_not_eps = 120;
    analysisd_state.eps_state_breakdown.seconds_over_limit = 1254;
    analysisd_state.eps_state_breakdown.available_credits_prev = 12;

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

static int test_setup_agent(void ** state) {
    test_struct_t *test_data = NULL;
    os_calloc(1, sizeof(test_struct_t),test_data);
    os_calloc(1, sizeof(analysisd_agent_state_t), test_data->agent_state);
    os_calloc(1, sizeof(OSHashNode), test_data->hash_node);

    test_mode = 0;
    will_return(__wrap_time, 123456789);
    analysisd_agents_state = __wrap_OSHash_Create();

    test_data->agent_state->uptime = 123456789;
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

    return 0;
}

static int test_teardown_agent(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;

    cJSON_Delete(test_data->state_json);

    if (analysisd_agents_state) {
        OSHash_Free(analysisd_agents_state);
        analysisd_agents_state = NULL;
    }

    os_free(test_data->hash_node);
    os_free(test_data);

    return 0;
}

static int test_setup_empty_hash_table(void ** state) {
    test_struct_t *test_data = NULL;
    os_calloc(1, sizeof(test_struct_t),test_data);
    os_calloc(1, sizeof(analysisd_agent_state_t), test_data->agent_state);

    test_data->agent_state->uptime = 123456789;

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
    will_return(__wrap_time, 123456789);

    will_return(__wrap_limit_reached, 31);
    will_return(__wrap_limit_reached, false);

    cJSON* state_json = asys_create_state_json();

    assert_non_null(state_json);

    assert_int_equal(cJSON_GetObjectItem(state_json, "uptime")->valueint, 123456789);

    assert_non_null(cJSON_GetObjectItem(state_json, "metrics"));
    cJSON* metrics = cJSON_GetObjectItem(state_json, "metrics");

    assert_non_null(cJSON_GetObjectItem(metrics, "bytes"));
    cJSON* bytes = cJSON_GetObjectItem(metrics, "bytes");

    assert_non_null(cJSON_GetObjectItem(bytes, "received"));
    assert_int_equal(cJSON_GetObjectItem(bytes, "received")->valueint, 123654789);

    assert_non_null(cJSON_GetObjectItem(metrics, "eps"));
    cJSON* eps = cJSON_GetObjectItem(metrics, "eps");

    assert_non_null(cJSON_GetObjectItem(eps, "available_credits"));
    assert_int_equal(cJSON_GetObjectItem(eps, "available_credits")->valueint, 31);

    assert_non_null(cJSON_GetObjectItem(eps, "available_credits_prev"));
    assert_int_equal(cJSON_GetObjectItem(eps, "available_credits_prev")->valueint, 12);

    assert_non_null(cJSON_GetObjectItem(eps, "events_dropped"));
    assert_int_equal(cJSON_GetObjectItem(eps, "events_dropped")->valueint, 552);

    assert_non_null(cJSON_GetObjectItem(eps, "events_dropped_not_eps"));
    assert_int_equal(cJSON_GetObjectItem(eps, "events_dropped_not_eps")->valueint, 120);

    assert_non_null(cJSON_GetObjectItem(eps, "seconds_over_limit"));
    assert_int_equal(cJSON_GetObjectItem(eps, "seconds_over_limit")->valueint, 1254);

    assert_non_null(cJSON_GetObjectItem(metrics, "events"));
    cJSON* events = cJSON_GetObjectItem(metrics, "events");

    assert_non_null(cJSON_GetObjectItem(events, "processed"));
    assert_int_equal(cJSON_GetObjectItem(events, "processed")->valueint, 4256);

    assert_non_null(cJSON_GetObjectItem(events, "received"));
    assert_int_equal(cJSON_GetObjectItem(events, "received")->valueint, 4589);

    assert_non_null(cJSON_GetObjectItem(events, "received_breakdown"));
    cJSON* recv = cJSON_GetObjectItem(events, "received_breakdown");

    assert_non_null(cJSON_GetObjectItem(recv, "decoded_breakdown"));
    cJSON* decoded = cJSON_GetObjectItem(recv, "decoded_breakdown");

    assert_non_null(cJSON_GetObjectItem(decoded, "agent"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "agent")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(decoded, "agentless"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "agentless")->valueint, 15);
    assert_non_null(cJSON_GetObjectItem(decoded, "dbsync"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "dbsync")->valueint, 350);
    assert_non_null(cJSON_GetObjectItem(decoded, "monitor"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "monitor")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(decoded, "remote"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "remote")->valueint, 8);
    assert_non_null(cJSON_GetObjectItem(decoded, "syslog"));
    assert_int_equal(cJSON_GetObjectItem(decoded, "syslog")->valueint, 48);

    assert_non_null(cJSON_GetObjectItem(decoded, "integrations_breakdown"));
    cJSON* decoded_int = cJSON_GetObjectItem(decoded, "integrations_breakdown");

    assert_non_null(cJSON_GetObjectItem(decoded_int, "virustotal"));
    assert_int_equal(cJSON_GetObjectItem(decoded_int, "virustotal")->valueint, 13);

    assert_non_null(cJSON_GetObjectItem(decoded, "modules_breakdown"));
    cJSON* decoded_mod = cJSON_GetObjectItem(decoded, "modules_breakdown");

    assert_non_null(cJSON_GetObjectItem(decoded_mod, "aws"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "aws")->valueint, 19);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "azure"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "azure")->valueint, 46);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "ciscat"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "ciscat")->valueint, 11);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "command"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "command")->valueint, 25);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "docker"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "docker")->valueint, 36);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "gcp"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "gcp")->valueint, 6);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "github"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "github")->valueint, 98);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "office365"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "office365")->valueint, 114);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "oscap"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "oscap")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "osquery"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "osquery")->valueint, 55);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "rootcheck"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "rootcheck")->valueint, 149);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "sca"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "sca")->valueint, 1352);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "syscheck"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "syscheck")->valueint, 1258);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "syscollector"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "syscollector")->valueint, 589);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "upgrade"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "upgrade")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(decoded_mod, "vulnerability"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod, "vulnerability")->valueint, 18);

    assert_non_null(cJSON_GetObjectItem(decoded_mod, "logcollector_breakdown"));
    cJSON* decoded_mod_log = cJSON_GetObjectItem(decoded_mod, "logcollector_breakdown");

    assert_non_null(cJSON_GetObjectItem(decoded_mod_log, "eventchannel"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod_log, "eventchannel")->valueint, 695);
    assert_non_null(cJSON_GetObjectItem(decoded_mod_log, "eventlog"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod_log, "eventlog")->valueint, 125);
    assert_non_null(cJSON_GetObjectItem(decoded_mod_log, "macos"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod_log, "macos")->valueint, 36);
    assert_non_null(cJSON_GetObjectItem(decoded_mod_log, "others"));
    assert_int_equal(cJSON_GetObjectItem(decoded_mod_log, "others")->valueint, 2011);

    assert_non_null(cJSON_GetObjectItem(recv, "dropped_breakdown"));
    cJSON* dropped = cJSON_GetObjectItem(recv, "dropped_breakdown");

    assert_non_null(cJSON_GetObjectItem(dropped, "agent"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "agent")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped, "agentless"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "agentless")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(dropped, "dbsync"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "dbsync")->valueint, 39);
    assert_non_null(cJSON_GetObjectItem(dropped, "monitor"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "monitor")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped, "remote"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "remote")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped, "syslog"));
    assert_int_equal(cJSON_GetObjectItem(dropped, "syslog")->valueint, 4);

    assert_non_null(cJSON_GetObjectItem(dropped, "integrations_breakdown"));
    cJSON* dropped_int = cJSON_GetObjectItem(dropped, "integrations_breakdown");

    assert_non_null(cJSON_GetObjectItem(dropped_int, "virustotal"));
    assert_int_equal(cJSON_GetObjectItem(dropped_int, "virustotal")->valueint, 1);

    assert_non_null(cJSON_GetObjectItem(dropped, "modules_breakdown"));
    cJSON* dropped_mod = cJSON_GetObjectItem(dropped, "modules_breakdown");

    assert_non_null(cJSON_GetObjectItem(dropped_mod, "aws"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "aws")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "azure"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "azure")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "ciscat"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "ciscat")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "command"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "command")->valueint, 3);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "docker"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "docker")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "gcp"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "gcp")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "github"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "github")->valueint, 8);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "office365"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "office365")->valueint, 12);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "oscap"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "oscap")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "osquery"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "osquery")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "rootcheck"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "rootcheck")->valueint, 33);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "sca"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "sca")->valueint, 25);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "syscheck"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "syscheck")->valueint, 98);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "syscollector"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "syscollector")->valueint, 14);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "upgrade"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "upgrade")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(dropped_mod, "vulnerability"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod, "vulnerability")->valueint, 1);

    assert_non_null(cJSON_GetObjectItem(dropped_mod, "logcollector_breakdown"));
    cJSON* dropped_mod_log = cJSON_GetObjectItem(dropped_mod, "logcollector_breakdown");

    assert_non_null(cJSON_GetObjectItem(dropped_mod_log, "eventchannel"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod_log, "eventchannel")->valueint, 25);
    assert_non_null(cJSON_GetObjectItem(dropped_mod_log, "eventlog"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod_log, "eventlog")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(dropped_mod_log, "macos"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod_log, "macos")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(dropped_mod_log, "others"));
    assert_int_equal(cJSON_GetObjectItem(dropped_mod_log, "others")->valueint, 36);

    assert_non_null(cJSON_GetObjectItem(events, "written_breakdown"));
    cJSON* written = cJSON_GetObjectItem(events, "written_breakdown");

    assert_non_null(cJSON_GetObjectItem(written, "alerts"));
    assert_int_equal(cJSON_GetObjectItem(written, "alerts")->valueint, 2154);

    assert_non_null(cJSON_GetObjectItem(written, "firewall"));
    assert_int_equal(cJSON_GetObjectItem(written, "firewall")->valueint, 148);

    assert_non_null(cJSON_GetObjectItem(written, "fts"));
    assert_int_equal(cJSON_GetObjectItem(written, "fts")->valueint, 19);

    assert_non_null(cJSON_GetObjectItem(written, "stats"));
    assert_int_equal(cJSON_GetObjectItem(written, "stats")->valueint, 564);

    assert_non_null(cJSON_GetObjectItem(written, "archives"));
    assert_int_equal(cJSON_GetObjectItem(written, "archives")->valueint, 4200);

    assert_non_null(cJSON_GetObjectItem(metrics, "queues"));
    cJSON* queue = cJSON_GetObjectItem(metrics, "queues");

    cJSON* syscheck = cJSON_GetObjectItem(queue, "syscheck");
    assert_non_null(cJSON_GetObjectItem(syscheck, "usage"));
    assert_float_equal(cJSON_GetObjectItem(syscheck, "usage")->valuedouble, 0.031, 0.001);
    assert_non_null(cJSON_GetObjectItem(syscheck, "size"));
    assert_int_equal(cJSON_GetObjectItem(syscheck, "size")->valueint, 4096);
    cJSON* syscollector = cJSON_GetObjectItem(queue, "syscollector");
    assert_non_null(cJSON_GetObjectItem(syscollector, "usage"));
    assert_float_equal(cJSON_GetObjectItem(syscollector, "usage")->valuedouble, 0.011, 0.001);
    assert_non_null(cJSON_GetObjectItem(syscollector, "size"));
    assert_int_equal(cJSON_GetObjectItem(syscollector, "size")->valueint, 4096);
    cJSON* rootcheck = cJSON_GetObjectItem(queue, "rootcheck");
    assert_non_null(cJSON_GetObjectItem(rootcheck, "usage"));
    assert_float_equal(cJSON_GetObjectItem(rootcheck, "usage")->valuedouble, 0.021, 0.001);
    assert_non_null(cJSON_GetObjectItem(rootcheck, "size"));
    assert_int_equal(cJSON_GetObjectItem(rootcheck, "size")->valueint, 4096);
    cJSON* sca = cJSON_GetObjectItem(queue, "sca");
    assert_non_null(cJSON_GetObjectItem(sca, "usage"));
    assert_float_equal(cJSON_GetObjectItem(sca, "usage")->valuedouble, 0.003, 0.001);
    assert_non_null(cJSON_GetObjectItem(sca, "size"));
    assert_int_equal(cJSON_GetObjectItem(sca, "size")->valueint, 4096);
    cJSON* hostinfo = cJSON_GetObjectItem(queue, "hostinfo");
    assert_non_null(cJSON_GetObjectItem(hostinfo, "usage"));
    assert_float_equal(cJSON_GetObjectItem(hostinfo, "usage")->valuedouble, 0, 0.001);
    assert_non_null(cJSON_GetObjectItem(hostinfo, "size"));
    assert_int_equal(cJSON_GetObjectItem(hostinfo, "size")->valueint, 4096);
    cJSON* eventchannel = cJSON_GetObjectItem(queue, "eventchannel");
    assert_non_null(cJSON_GetObjectItem(eventchannel, "usage"));
    assert_float_equal(cJSON_GetObjectItem(eventchannel, "usage")->valuedouble, 0.005, 0.001);
    assert_non_null(cJSON_GetObjectItem(eventchannel, "size"));
    assert_int_equal(cJSON_GetObjectItem(eventchannel, "size")->valueint, 4096);
    cJSON* dbsync = cJSON_GetObjectItem(queue, "dbsync");
    assert_non_null(cJSON_GetObjectItem(dbsync, "usage"));
    assert_float_equal(cJSON_GetObjectItem(dbsync, "usage")->valuedouble, 0.111, 0.001);
    assert_non_null(cJSON_GetObjectItem(dbsync, "size"));
    assert_int_equal(cJSON_GetObjectItem(dbsync, "size")->valueint, 4096);
    cJSON* upgrade = cJSON_GetObjectItem(queue, "upgrade");
    assert_non_null(cJSON_GetObjectItem(upgrade, "usage"));
    assert_float_equal(cJSON_GetObjectItem(upgrade, "usage")->valuedouble, 0, 0.001);
    assert_non_null(cJSON_GetObjectItem(upgrade, "size"));
    assert_int_equal(cJSON_GetObjectItem(upgrade, "size")->valueint, 4096);
    cJSON* others = cJSON_GetObjectItem(queue, "others");
    assert_non_null(cJSON_GetObjectItem(others, "usage"));
    assert_float_equal(cJSON_GetObjectItem(others, "usage")->valuedouble, 0.063, 0.001);
    assert_non_null(cJSON_GetObjectItem(others, "size"));
    assert_int_equal(cJSON_GetObjectItem(others, "size")->valueint, 4096);
    cJSON* processed = cJSON_GetObjectItem(queue, "processed");
    assert_non_null(cJSON_GetObjectItem(processed, "usage"));
    assert_float_equal(cJSON_GetObjectItem(processed, "usage")->valuedouble, 0.037, 0.001);
    assert_non_null(cJSON_GetObjectItem(processed, "size"));
    assert_int_equal(cJSON_GetObjectItem(processed, "size")->valueint, 4096);
    cJSON* alerts = cJSON_GetObjectItem(queue, "alerts");
    assert_non_null(cJSON_GetObjectItem(alerts, "usage"));
    assert_float_equal(cJSON_GetObjectItem(alerts, "usage")->valuedouble, 0.001, 0.001);
    assert_non_null(cJSON_GetObjectItem(alerts, "size"));
    assert_int_equal(cJSON_GetObjectItem(alerts, "size")->valueint, 4096);
    cJSON* firewall = cJSON_GetObjectItem(queue, "firewall");
    assert_non_null(cJSON_GetObjectItem(firewall, "usage"));
    assert_float_equal(cJSON_GetObjectItem(firewall, "usage")->valuedouble, 0, 0.001);
    assert_non_null(cJSON_GetObjectItem(firewall, "size"));
    assert_int_equal(cJSON_GetObjectItem(firewall, "size")->valueint, 4096);
    cJSON* fts = cJSON_GetObjectItem(queue, "fts");
    assert_non_null(cJSON_GetObjectItem(fts, "usage"));
    assert_float_equal(cJSON_GetObjectItem(fts, "usage")->valuedouble, 0, 0.001);
    assert_non_null(cJSON_GetObjectItem(fts, "size"));
    assert_int_equal(cJSON_GetObjectItem(fts, "size")->valueint, 4096);
    cJSON* stats = cJSON_GetObjectItem(queue, "stats");
    assert_non_null(cJSON_GetObjectItem(stats, "usage"));
    assert_float_equal(cJSON_GetObjectItem(stats, "usage")->valuedouble, 0, 0.001);
    assert_non_null(cJSON_GetObjectItem(stats, "size"));
    assert_int_equal(cJSON_GetObjectItem(stats, "size")->valueint, 4096);
    cJSON* archives = cJSON_GetObjectItem(queue, "archives");
    assert_non_null(cJSON_GetObjectItem(archives, "usage"));
    assert_float_equal(cJSON_GetObjectItem(archives, "usage")->valuedouble, 0.005, 0.001);
    assert_non_null(cJSON_GetObjectItem(archives, "size"));
    assert_int_equal(cJSON_GetObjectItem(archives, "size")->valueint, 4096);

    cJSON_Delete(state_json);
}

void test_asys_create_agents_state_json(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;
    int *agents_ids = NULL;
    os_calloc(2, sizeof(int), agents_ids);
    agents_ids[0] = 1;
    agents_ids[1] = OS_INVALID;
    const char *agent_id = "001";

    will_return(__wrap_time, 123456789);

    expect_value(__wrap_OSHash_Get_ex, self, analysisd_agents_state);
    expect_string(__wrap_OSHash_Get_ex, key, agent_id);
    will_return(__wrap_OSHash_Get_ex, test_data->hash_node->data);

    test_data->state_json = asys_create_agents_state_json(agents_ids);

    assert_non_null(test_data->state_json);

    assert_non_null(cJSON_GetObjectItem(test_data->state_json, "agents"));
    cJSON* agents = cJSON_GetObjectItem(test_data->state_json, "agents");

    assert_non_null(cJSON_GetArrayItem(agents, 0));
    cJSON* agent = cJSON_GetArrayItem(agents, 0);
    assert_int_equal(cJSON_GetObjectItem(agent, "id")->valueint, 1);
    assert_int_equal(cJSON_GetObjectItem(agent, "uptime")->valueint, 123456789);

    assert_non_null(cJSON_GetObjectItem(agent, "metrics"));
    cJSON* agent_metrics = cJSON_GetObjectItem(agent, "metrics");

    assert_non_null(cJSON_GetObjectItem(agent_metrics, "events"));
    cJSON* events = cJSON_GetObjectItem(agent_metrics, "events");

    assert_int_equal(cJSON_GetObjectItem(events, "processed")->valueint, 1286);

    assert_non_null(cJSON_GetObjectItem(events, "received_breakdown"));
    cJSON* events_received_breakdown = cJSON_GetObjectItem(events, "received_breakdown");

    assert_non_null(cJSON_GetObjectItem(events_received_breakdown, "decoded_breakdown"));
    cJSON* events_decoded_breakdown = cJSON_GetObjectItem(events_received_breakdown, "decoded_breakdown");

    assert_int_equal(cJSON_GetObjectItem(events_decoded_breakdown, "agent")->valueint, 1);
    assert_int_equal(cJSON_GetObjectItem(events_decoded_breakdown, "dbsync")->valueint, 154);
    assert_int_equal(cJSON_GetObjectItem(events_decoded_breakdown, "monitor")->valueint, 2);
    assert_int_equal(cJSON_GetObjectItem(events_decoded_breakdown, "remote")->valueint, 2);

    assert_non_null(cJSON_GetObjectItem(events_decoded_breakdown, "integrations_breakdown"));
    cJSON* integrations_decoded = cJSON_GetObjectItem(events_decoded_breakdown, "integrations_breakdown");

    assert_int_equal(cJSON_GetObjectItem(integrations_decoded, "virustotal")->valueint, 1);

    assert_non_null(cJSON_GetObjectItem(events_decoded_breakdown, "modules_breakdown"));
    cJSON* modules_decoded = cJSON_GetObjectItem(events_decoded_breakdown, "modules_breakdown");

    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "aws")->valueint, 39);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "azure")->valueint, 14);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "ciscat")->valueint, 22);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "command")->valueint, 5);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "docker")->valueint, 39);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "gcp")->valueint, 12);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "github")->valueint, 44);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "office365")->valueint, 6);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "oscap")->valueint, 0);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "osquery")->valueint, 12);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "rootcheck")->valueint, 25);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "sca")->valueint, 68);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "syscheck")->valueint, 514);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "syscollector")->valueint, 320);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "upgrade")->valueint, 10);
    assert_int_equal(cJSON_GetObjectItem(modules_decoded, "vulnerability")->valueint, 14);

    assert_non_null(cJSON_GetObjectItem(modules_decoded, "logcollector_breakdown"));
    cJSON* logcollector_decoded = cJSON_GetObjectItem(modules_decoded, "logcollector_breakdown");

    assert_int_equal(cJSON_GetObjectItem(logcollector_decoded, "eventchannel")->valueint, 37);
    assert_int_equal(cJSON_GetObjectItem(logcollector_decoded, "eventlog")->valueint, 15);
    assert_int_equal(cJSON_GetObjectItem(logcollector_decoded, "macos")->valueint, 36);
    assert_int_equal(cJSON_GetObjectItem(logcollector_decoded, "others")->valueint, 55);

    assert_non_null(cJSON_GetObjectItem(events, "written_breakdown"));
    cJSON* written = cJSON_GetObjectItem(events, "written_breakdown");

    assert_int_equal(cJSON_GetObjectItem(written, "alerts")->valueint, 269);
    assert_int_equal(cJSON_GetObjectItem(written, "firewall")->valueint, 15);
    assert_int_equal(cJSON_GetObjectItem(written, "archives")->valueint, 1286);

    os_free(test_data->agent_state);
    os_free(agents_ids);
}

void test_asys_get_node_new_node(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;
    const char *agent_id = "001";

    expect_value(__wrap_OSHash_Get_ex, self, analysisd_agents_state);
    expect_string(__wrap_OSHash_Get_ex, key, agent_id);
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_time, 123456789);

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

    int sock = 1;

    w_analysisd_clean_agents_state(&sock);
}

void test_w_analysisd_clean_agents_state_completed(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;

    expect_value(__wrap_OSHash_Begin, self, analysisd_agents_state);
    will_return(__wrap_OSHash_Begin, test_data->hash_node);

    int *connected_agents = NULL;
    os_calloc(1, sizeof(int), connected_agents);
    connected_agents[0] = OS_INVALID;

    expect_string(__wrap_wdb_get_agents_ids_of_current_node, status, AGENT_CS_ACTIVE);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, last_id, 0);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, limit, -1);
    will_return(__wrap_wdb_get_agents_ids_of_current_node, connected_agents);

    expect_value(__wrap_OSHash_Next, self, analysisd_agents_state);
    will_return(__wrap_OSHash_Next, NULL);

    expect_value(__wrap_OSHash_Delete_ex, self, analysisd_agents_state);
    expect_value(__wrap_OSHash_Delete_ex, key, "001");
    will_return(__wrap_OSHash_Delete_ex, test_data->agent_state);

    int sock = 1;

    w_analysisd_clean_agents_state(&sock);
}

void test_w_analysisd_clean_agents_state_completed_without_delete(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;

    expect_value(__wrap_OSHash_Begin, self, analysisd_agents_state);
    will_return(__wrap_OSHash_Begin, test_data->hash_node);

    int *connected_agents = NULL;
    os_calloc(1, sizeof(int), connected_agents);
    connected_agents[0] = 1;

    expect_string(__wrap_wdb_get_agents_ids_of_current_node, status, AGENT_CS_ACTIVE);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, last_id, 0);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, limit, -1);
    will_return(__wrap_wdb_get_agents_ids_of_current_node, connected_agents);

    expect_value(__wrap_OSHash_Next, self, analysisd_agents_state);
    will_return(__wrap_OSHash_Next, NULL);

    int sock = 1;

    w_analysisd_clean_agents_state(&sock);

    os_free(test_data->agent_state);
}

void test_w_analysisd_clean_agents_state_query_fail(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;

    expect_value(__wrap_OSHash_Begin, self, analysisd_agents_state);
    will_return(__wrap_OSHash_Begin, test_data->hash_node);

    int *connected_agents = NULL;

    expect_string(__wrap_wdb_get_agents_ids_of_current_node, status, AGENT_CS_ACTIVE);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, last_id, 0);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, limit, -1);
    will_return(__wrap_wdb_get_agents_ids_of_current_node, connected_agents);

    int sock = 1;

    w_analysisd_clean_agents_state(&sock);

    os_free(test_data->agent_state);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test asys_create_state_json
        cmocka_unit_test_setup_teardown(test_asys_create_state_json, test_setup, test_teardown),
        // Test asys_create_agents_state_json
        cmocka_unit_test_setup_teardown(test_asys_create_agents_state_json, test_setup_agent, test_teardown_agent),
        // Test get_node
        cmocka_unit_test_setup_teardown(test_asys_get_node_new_node, test_setup_empty_hash_table, test_teardown_empty_hash_table),
        cmocka_unit_test_setup_teardown(test_asys_get_node_existing_node, test_setup_agent, test_teardown_agent),
        // Test w_analysisd_clean_agents_state
        cmocka_unit_test_setup_teardown(test_w_analysisd_clean_agents_state_empty_table, test_setup_empty_hash_table, test_teardown_empty_hash_table),
        cmocka_unit_test_setup_teardown(test_w_analysisd_clean_agents_state_completed, test_setup_agent, test_teardown_agent),
        cmocka_unit_test_setup_teardown(test_w_analysisd_clean_agents_state_completed_without_delete, test_setup_agent, test_teardown_agent),
        cmocka_unit_test_setup_teardown(test_w_analysisd_clean_agents_state_query_fail, test_setup_agent, test_teardown_agent),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
