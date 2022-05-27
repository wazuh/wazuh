/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef ARGV0
#define ARGV0 "wazuh-analysisd"
#endif

#include "shared.h"
#include "analysisd.h"
#include "state.h"

analysisd_state_t analysisd_state;
queue_status_t queue_status;
static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static int w_analysisd_write_state();
static int interval;

/**
 * @brief Get the number of elements divided by the size of queues
 * Values are save in state's variables
 */
static void w_get_queues_size();

/**
 * @brief Obtains analysisd's queues sizes
 * Values are save in state's variables
 */
static void w_get_initial_queues_size();


void * w_analysisd_state_main() {
    interval = getDefine_Int("analysisd", "state_interval", 0, 86400);

    if (!interval) {
        minfo("State file is disabled.");
        return NULL;
    }

    mdebug1("State file updating thread started.");

    w_mutex_lock(&queue_mutex);
    w_get_initial_queues_size();
    w_mutex_unlock(&queue_mutex);

    while (1) {
        w_analysisd_write_state();
        sleep(interval);
    }

    return NULL;
}

int w_analysisd_write_state() {
    FILE * fp;
    char path[PATH_MAX - 8];
    char path_temp[PATH_MAX + 1];
    analysisd_state_t state_cpy;
    queue_status_t queue_cpy;

    if (!strcmp(__local_name, "unset")) {
        merror("At write_state(): __local_name is unset.");
        return -1;
    }

    mdebug2("Updating state file.");

    snprintf(path, sizeof(path), OS_PIDFILE "/%s.state", __local_name);
    snprintf(path_temp, sizeof(path_temp), "%s.temp", path);

    if (fp = fopen(path_temp, "w"), !fp) {
        merror(FOPEN_ERROR, path_temp, errno, strerror(errno));
        return -1;
    }

    w_mutex_lock(&queue_mutex);
    w_get_queues_size();
    memcpy(&queue_cpy, &queue_status, sizeof(queue_status_t));
    w_mutex_unlock(&queue_mutex);

    w_mutex_lock(&state_mutex);
    memcpy(&state_cpy, &analysisd_state, sizeof(analysisd_state_t));
    w_mutex_unlock(&state_mutex);

    fprintf(fp,
        "# State file for %s\n"
        "# THIS FILE WILL BE DEPRECATED IN FUTURE VERSIONS\n"
        "\n"
        "# Total events decoded\n"
        "total_events_decoded='%lu'\n"
        "\n"
        "# Syscheck events decoded\n"
        "syscheck_events_decoded='%lu'\n"
        "\n"
        "# Syscollector events decoded\n"
        "syscollector_events_decoded='%lu'\n"
        "\n"
        "# Rootcheck events decoded\n"
        "rootcheck_events_decoded='%lu'\n"
        "\n"
         "# Security configuration assessment events decoded\n"
        "sca_events_decoded='%lu'\n"
        "\n"
        "# Hostinfo events decoded\n"
        "hostinfo_events_decoded='%lu'\n"
        "\n"
        "# Winevt events decoded\n"
        "winevt_events_decoded='%lu'\n"
        "\n"
        "# Database synchronization messages dispatched\n"
        "dbsync_messages_dispatched='%lu'\n"
        "\n"
        "# Other events decoded\n"
        "other_events_decoded='%lu'\n"
        "\n"
        "# Events processed (Rule matching)\n"
        "events_processed='%lu'\n"
        "\n"
        "# Events received\n"
        "events_received='%lu'\n"
        "\n"
        "# Events dropped\n"
        "events_dropped='%lu'\n"
        "\n"
        "# Alerts written to disk\n"
        "alerts_written='%lu'\n"
        "\n"
        "# Firewall alerts written to disk\n"
        "firewall_written='%u'\n"
        "\n"
        "# FTS alerts written to disk\n"
        "fts_written='%u'\n"
        "\n"
        "# Syscheck queue\n"
        "syscheck_queue_usage='%.2f'\n"
        "\n"
        "# Syscheck queue size\n"
        "syscheck_queue_size='%zu'\n"
        "\n"
        "# Syscollector queue\n"
        "syscollector_queue_usage='%.2f'\n"
        "\n"
        "# Syscollector queue size\n"
        "syscollector_queue_size='%zu'\n"
        "\n"
        "# Rootcheck queue\n"
        "rootcheck_queue_usage='%.2f'\n"
        "\n"
        "# Rootcheck queue size\n"
        "rootcheck_queue_size='%zu'\n"
        "\n"
        "# Security configuration assessment queue\n"
        "sca_queue_usage='%.2f'\n"
        "\n"
        "# Security configuration assessment queue size\n"
        "sca_queue_size='%zu'\n"
        "\n"
        "# Hostinfo queue\n"
        "hostinfo_queue_usage='%.2f'\n"
        "\n"
        "# Hostinfo queue size\n"
        "hostinfo_queue_size='%zu'\n"
        "\n"
        "# Winevt queue\n"
        "winevt_queue_usage='%.2f'\n"
        "\n"
        "# Winevt queue size\n"
        "winevt_queue_size='%zu'\n"
        "\n"
        "# Database synchronization message queue\n"
        "dbsync_queue_usage='%.2f'\n"
        "\n"
        "# Database synchronization message queue size\n"
        "dbsync_queue_size='%zu'\n"
        "\n"
        "# Upgrade module message queue\n"
        "upgrade_queue_usage='%.2f'\n"
        "\n"
        "# Upgrade module message queue size\n"
        "upgrade_queue_size='%zu'\n"
        "\n"
        "# Event queue\n"
        "event_queue_usage='%.2f'\n"
        "\n"
        "# Event queue size\n"
        "event_queue_size='%zu'\n"
        "\n"
        "# Rule matching queue\n"
        "rule_matching_queue_usage='%.2f'\n"
        "\n"
        "# Rule matching queue size\n"
        "rule_matching_queue_size='%zu'\n"
        "\n"
        "# Alerts log queue\n"
        "alerts_queue_usage='%.2f'\n"
        "\n"
        "# Alerts log queue size\n"
        "alerts_queue_size='%zu'\n"
        "\n"
        "# Firewall log queue\n"
        "firewall_queue_usage='%.2f'\n"
        "\n"
        "# Firewall log queue size\n"
        "firewall_queue_size='%zu'\n"
        "\n"
        "# Statistical log queue\n"
        "statistical_queue_usage='%.2f'\n"
        "\n"
        "# Statistical log queue size\n"
        "statistical_queue_size='%zu'\n"
        "\n"
        "# Archives log queue\n"
        "archives_queue_usage='%.2f'\n"
        "\n"
        "# Archives log queue size\n"
        "archives_queue_size='%zu'\n"
        "\n",
        __local_name,
        state_cpy.events_received_breakdown.events_decoded_breakdown.syscheck + state_cpy.events_received_breakdown.events_decoded_breakdown.syscollector +
        state_cpy.events_received_breakdown.events_decoded_breakdown.rootcheck + state_cpy.events_received_breakdown.events_decoded_breakdown.sca +
        state_cpy.events_received_breakdown.events_decoded_breakdown.hostinfo + state_cpy.events_received_breakdown.events_decoded_breakdown.winevt +
        state_cpy.events_received_breakdown.events_decoded_breakdown.events,
        state_cpy.events_received_breakdown.events_decoded_breakdown.syscheck,
        state_cpy.events_received_breakdown.events_decoded_breakdown.syscollector,
        state_cpy.events_received_breakdown.events_decoded_breakdown.rootcheck,
        state_cpy.events_received_breakdown.events_decoded_breakdown.sca,
        state_cpy.events_received_breakdown.events_decoded_breakdown.hostinfo,
        state_cpy.events_received_breakdown.events_decoded_breakdown.winevt,
        state_cpy.events_received_breakdown.events_decoded_breakdown.dbsync,
        state_cpy.events_received_breakdown.events_decoded_breakdown.events,
        state_cpy.events_processed,
        state_cpy.events_received,
        state_cpy.events_received_breakdown.events_dropped_breakdown.syscheck + state_cpy.events_received_breakdown.events_dropped_breakdown.syscollector +
        state_cpy.events_received_breakdown.events_dropped_breakdown.rootcheck + state_cpy.events_received_breakdown.events_dropped_breakdown.sca +
        state_cpy.events_received_breakdown.events_dropped_breakdown.hostinfo + state_cpy.events_received_breakdown.events_dropped_breakdown.winevt +
        state_cpy.events_received_breakdown.events_dropped_breakdown.events,
        state_cpy.alerts_written,
        state_cpy.firewall_written,
        state_cpy.fts_written,
        queue_status.syscheck_queue_usage,
        queue_status.syscheck_queue_size,
        queue_status.syscollector_queue_usage,
        queue_status.syscollector_queue_size,
        queue_status.rootcheck_queue_usage,
        queue_status.rootcheck_queue_size,
        queue_status.sca_queue_usage,
        queue_status.sca_queue_size,
        queue_status.hostinfo_queue_usage,
        queue_status.hostinfo_queue_size,
        queue_status.winevt_queue_usage,
        queue_status.winevt_queue_size,
        queue_status.dbsync_queue_usage, queue_status.dbsync_queue_size,
        queue_status.upgrade_queue_usage, queue_status.upgrade_queue_size,
        queue_status.events_queue_usage, queue_status.events_queue_size,
        queue_status.processed_queue_usage,
        queue_status.processed_queue_size,
        queue_status.alerts_queue_usage,
        queue_status.alerts_queue_size,
        queue_status.firewall_queue_usage,
        queue_status.firewall_queue_size,
        queue_status.stats_queue_usage,
        queue_status.stats_queue_size,
        queue_status.archives_queue_usage,
        queue_status.archives_queue_size);

    fclose(fp);

    if (rename(path_temp, path) < 0) {
        merror("Renaming %s to %s: %s", path_temp, path, strerror(errno));
        if (unlink(path_temp) < 0) {
            merror("Deleting %s: %s", path_temp, strerror(errno));
        }
       return -1;
    }

   return 0;
}

void w_get_queues_size() {
    queue_status.syscheck_queue_usage = ((decode_queue_syscheck_input->elements / (float)decode_queue_syscheck_input->size));
    queue_status.syscollector_queue_usage = ((decode_queue_syscollector_input->elements / (float)decode_queue_syscollector_input->size));
    queue_status.rootcheck_queue_usage = ((decode_queue_rootcheck_input->elements / (float)decode_queue_rootcheck_input->size));
    queue_status.sca_queue_usage = ((decode_queue_sca_input->elements / (float)decode_queue_sca_input->size));
    queue_status.hostinfo_queue_usage = ((decode_queue_hostinfo_input->elements / (float)decode_queue_hostinfo_input->size));
    queue_status.winevt_queue_usage = ((decode_queue_winevt_input->elements / (float)decode_queue_winevt_input->size));
    queue_status.dbsync_queue_usage = ((dispatch_dbsync_input->elements / (float)dispatch_dbsync_input->size));
    queue_status.upgrade_queue_usage = ((upgrade_module_input->elements / (float)upgrade_module_input->size));
    queue_status.events_queue_usage = ((decode_queue_event_input->elements / (float)decode_queue_event_input->size));
    queue_status.processed_queue_usage = ((decode_queue_event_output->elements / (float)decode_queue_event_output->size));
    queue_status.alerts_queue_usage = ((writer_queue_log->elements / (float)writer_queue_log->size));
    queue_status.archives_queue_usage = ((writer_queue->elements / (float)writer_queue->size));
    queue_status.firewall_queue_usage = ((writer_queue_log_firewall->elements / (float)writer_queue_log_firewall->size));
    queue_status.fts_queue_usage = ((writer_queue_log_fts->elements / (float)writer_queue_log_firewall->size));
    queue_status.stats_queue_usage = ((writer_queue_log_statistical->elements / (float)writer_queue_log_statistical->size));
}

void w_get_initial_queues_size() {
    queue_status.syscheck_queue_size = decode_queue_syscheck_input->size;
    queue_status.syscollector_queue_size = decode_queue_syscollector_input->size;
    queue_status.rootcheck_queue_size = decode_queue_rootcheck_input->size;
    queue_status.sca_queue_size = decode_queue_sca_input->size;
    queue_status.hostinfo_queue_size = decode_queue_hostinfo_input->size;
    queue_status.winevt_queue_size = decode_queue_winevt_input->size;
    queue_status.dbsync_queue_size = dispatch_dbsync_input->size;
    queue_status.upgrade_queue_size = upgrade_module_input->size;
    queue_status.events_queue_size = decode_queue_event_input->size;
    queue_status.processed_queue_size = decode_queue_event_output->size;
    queue_status.alerts_queue_size = writer_queue_log->size;
    queue_status.archives_queue_size = writer_queue->size;
    queue_status.firewall_queue_size = writer_queue_log_firewall->size;
    queue_status.fts_queue_size = writer_queue_log_fts->size;
    queue_status.stats_queue_size = writer_queue_log_statistical->size;
}

void w_inc_received_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_syscheck_decoded_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_decoded_breakdown.syscheck++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_syscollector_decoded_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_decoded_breakdown.syscollector++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_rootcheck_decoded_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_decoded_breakdown.rootcheck++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_sca_decoded_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_decoded_breakdown.sca++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_hostinfo_decoded_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_decoded_breakdown.hostinfo++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_winevt_decoded_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_decoded_breakdown.winevt++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_dbsync_decoded_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_decoded_breakdown.dbsync++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_upgrade_decoded_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_decoded_breakdown.upgrade++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_events_decoded() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_decoded_breakdown.events++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_syscheck_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_dropped_breakdown.syscheck++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_syscollector_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_dropped_breakdown.syscollector++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_rootcheck_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_dropped_breakdown.rootcheck++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_sca_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_dropped_breakdown.sca++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_hostinfo_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_dropped_breakdown.hostinfo++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_winevt_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_dropped_breakdown.winevt++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_dbsync_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_dropped_breakdown.dbsync++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_upgrade_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_dropped_breakdown.upgrade++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_events_dropped() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_dropped_breakdown.events++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_syscheck_unknown_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_unknown_breakdown.syscheck++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_syscollector_unknown_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_unknown_breakdown.syscollector++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_rootcheck_unknown_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_unknown_breakdown.rootcheck++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_sca_unknown_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_unknown_breakdown.sca++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_hostinfo_unknown_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_unknown_breakdown.hostinfo++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_winevt_unknown_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_unknown_breakdown.winevt++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_dbsync_unknown_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_unknown_breakdown.dbsync++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_upgrade_unknown_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_unknown_breakdown.upgrade++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_events_unknown() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received_breakdown.events_unknown_breakdown.events++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_processed_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_processed++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_alerts_written() {
    w_mutex_lock(&state_mutex);
    analysisd_state.alerts_written++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_archives_written() {
    w_mutex_lock(&state_mutex);
    analysisd_state.archives_written++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_firewall_written() {
    w_mutex_lock(&state_mutex);
    analysisd_state.firewall_written++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_fts_written() {
    w_mutex_lock(&state_mutex);
    analysisd_state.fts_written++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_stats_written() {
    w_mutex_lock(&state_mutex);
    analysisd_state.stats_written++;
    w_mutex_unlock(&state_mutex);
}

cJSON* asys_create_state_json() {
    analysisd_state_t state_cpy;
    queue_status_t queue_cpy;
    cJSON *_statistics = NULL;
    cJSON *_received = NULL;
    cJSON *_decoded = NULL;
    cJSON *_dropped = NULL;
    cJSON *_unknown = NULL;
    cJSON *_queue = NULL;

    w_mutex_lock(&queue_mutex);
    w_get_queues_size();
    memcpy(&queue_cpy, &queue_status, sizeof(queue_status_t));
    w_mutex_unlock(&queue_mutex);

    w_mutex_lock(&state_mutex);
    memcpy(&state_cpy, &analysisd_state, sizeof(analysisd_state_t));
    w_mutex_unlock(&state_mutex);

    cJSON *asys_state_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(asys_state_json, "version", VERSION);
    cJSON_AddNumberToObject(asys_state_json, "timestamp", time(NULL));
    cJSON_AddStringToObject(asys_state_json, "daemon_name", ARGV0);

    _statistics = cJSON_CreateObject();
    cJSON_AddItemToObject(asys_state_json, "statistics", _statistics);

    cJSON_AddNumberToObject(_statistics, "events_received", state_cpy.events_received);

    _received = cJSON_CreateObject();
    cJSON_AddItemToObject(_statistics, "events_received_breakdown", _received);

    cJSON_AddNumberToObject(_received, "events_decoded", state_cpy.events_received_breakdown.events_decoded_breakdown.syscheck +
                                                         state_cpy.events_received_breakdown.events_decoded_breakdown.syscollector +
                                                         state_cpy.events_received_breakdown.events_decoded_breakdown.rootcheck +
                                                         state_cpy.events_received_breakdown.events_decoded_breakdown.sca +
                                                         state_cpy.events_received_breakdown.events_decoded_breakdown.hostinfo +
                                                         state_cpy.events_received_breakdown.events_decoded_breakdown.winevt +
                                                         state_cpy.events_received_breakdown.events_decoded_breakdown.dbsync +
                                                         state_cpy.events_received_breakdown.events_decoded_breakdown.upgrade +
                                                         state_cpy.events_received_breakdown.events_decoded_breakdown.events);

    _decoded = cJSON_CreateObject();
    cJSON_AddItemToObject(_received, "events_decoded_breakdown", _decoded);

    cJSON_AddNumberToObject(_decoded, "syscheck_decoded", state_cpy.events_received_breakdown.events_decoded_breakdown.syscheck);
    cJSON_AddNumberToObject(_decoded, "syscollector_decoded", state_cpy.events_received_breakdown.events_decoded_breakdown.syscollector);
    cJSON_AddNumberToObject(_decoded, "rootcheck_decoded", state_cpy.events_received_breakdown.events_decoded_breakdown.rootcheck);
    cJSON_AddNumberToObject(_decoded, "sca_decoded", state_cpy.events_received_breakdown.events_decoded_breakdown.sca);
    cJSON_AddNumberToObject(_decoded, "hostinfo_decoded", state_cpy.events_received_breakdown.events_decoded_breakdown.hostinfo);
    cJSON_AddNumberToObject(_decoded, "winevt_decoded", state_cpy.events_received_breakdown.events_decoded_breakdown.winevt);
    cJSON_AddNumberToObject(_decoded, "dbsync_decoded", state_cpy.events_received_breakdown.events_decoded_breakdown.dbsync);
    cJSON_AddNumberToObject(_decoded, "upgrade_decoded", state_cpy.events_received_breakdown.events_decoded_breakdown.upgrade);
    cJSON_AddNumberToObject(_decoded, "events_decoded", state_cpy.events_received_breakdown.events_decoded_breakdown.events);

    cJSON_AddNumberToObject(_received, "events_dropped", state_cpy.events_received_breakdown.events_dropped_breakdown.syscheck +
                                                         state_cpy.events_received_breakdown.events_dropped_breakdown.syscollector +
                                                         state_cpy.events_received_breakdown.events_dropped_breakdown.rootcheck +
                                                         state_cpy.events_received_breakdown.events_dropped_breakdown.sca +
                                                         state_cpy.events_received_breakdown.events_dropped_breakdown.hostinfo +
                                                         state_cpy.events_received_breakdown.events_dropped_breakdown.winevt +
                                                         state_cpy.events_received_breakdown.events_dropped_breakdown.dbsync +
                                                         state_cpy.events_received_breakdown.events_dropped_breakdown.upgrade +
                                                         state_cpy.events_received_breakdown.events_dropped_breakdown.events);

    _dropped = cJSON_CreateObject();
    cJSON_AddItemToObject(_received, "events_dropped_breakdown", _dropped);

    cJSON_AddNumberToObject(_dropped, "syscheck_dropped", state_cpy.events_received_breakdown.events_dropped_breakdown.syscheck);
    cJSON_AddNumberToObject(_dropped, "syscollector_dropped", state_cpy.events_received_breakdown.events_dropped_breakdown.syscollector);
    cJSON_AddNumberToObject(_dropped, "rootcheck_dropped", state_cpy.events_received_breakdown.events_dropped_breakdown.rootcheck);
    cJSON_AddNumberToObject(_dropped, "sca_dropped", state_cpy.events_received_breakdown.events_dropped_breakdown.sca);
    cJSON_AddNumberToObject(_dropped, "hostinfo_dropped", state_cpy.events_received_breakdown.events_dropped_breakdown.hostinfo);
    cJSON_AddNumberToObject(_dropped, "winevt_dropped", state_cpy.events_received_breakdown.events_dropped_breakdown.winevt);
    cJSON_AddNumberToObject(_dropped, "dbsync_dropped", state_cpy.events_received_breakdown.events_dropped_breakdown.dbsync);
    cJSON_AddNumberToObject(_dropped, "upgrade_dropped", state_cpy.events_received_breakdown.events_dropped_breakdown.upgrade);
    cJSON_AddNumberToObject(_dropped, "events_dropped", state_cpy.events_received_breakdown.events_dropped_breakdown.events);

    cJSON_AddNumberToObject(_received, "events_unknown", state_cpy.events_received_breakdown.events_unknown_breakdown.syscheck +
                                                         state_cpy.events_received_breakdown.events_unknown_breakdown.syscollector +
                                                         state_cpy.events_received_breakdown.events_unknown_breakdown.rootcheck +
                                                         state_cpy.events_received_breakdown.events_unknown_breakdown.sca +
                                                         state_cpy.events_received_breakdown.events_unknown_breakdown.hostinfo +
                                                         state_cpy.events_received_breakdown.events_unknown_breakdown.winevt +
                                                         state_cpy.events_received_breakdown.events_unknown_breakdown.dbsync +
                                                         state_cpy.events_received_breakdown.events_unknown_breakdown.upgrade +
                                                         state_cpy.events_received_breakdown.events_unknown_breakdown.events);

    _unknown = cJSON_CreateObject();
    cJSON_AddItemToObject(_received, "events_unknown_breakdown", _unknown);

    cJSON_AddNumberToObject(_unknown, "syscheck_unknown", state_cpy.events_received_breakdown.events_unknown_breakdown.syscheck);
    cJSON_AddNumberToObject(_unknown, "syscollector_unknown", state_cpy.events_received_breakdown.events_unknown_breakdown.syscollector);
    cJSON_AddNumberToObject(_unknown, "rootcheck_unknown", state_cpy.events_received_breakdown.events_unknown_breakdown.rootcheck);
    cJSON_AddNumberToObject(_unknown, "sca_unknown", state_cpy.events_received_breakdown.events_unknown_breakdown.sca);
    cJSON_AddNumberToObject(_unknown, "hostinfo_unknown", state_cpy.events_received_breakdown.events_unknown_breakdown.hostinfo);
    cJSON_AddNumberToObject(_unknown, "winevt_unknown", state_cpy.events_received_breakdown.events_unknown_breakdown.winevt);
    cJSON_AddNumberToObject(_unknown, "dbsync_unknown", state_cpy.events_received_breakdown.events_unknown_breakdown.dbsync);
    cJSON_AddNumberToObject(_unknown, "upgrade_unknown", state_cpy.events_received_breakdown.events_unknown_breakdown.upgrade);
    cJSON_AddNumberToObject(_unknown, "events_unknown", state_cpy.events_received_breakdown.events_unknown_breakdown.events);

    cJSON_AddNumberToObject(_statistics, "events_processed", state_cpy.events_processed);
    cJSON_AddNumberToObject(_statistics, "alerts_written", state_cpy.alerts_written);
    cJSON_AddNumberToObject(_statistics, "firewall_written", state_cpy.firewall_written);
    cJSON_AddNumberToObject(_statistics, "fts_written", state_cpy.fts_written);
    cJSON_AddNumberToObject(_statistics, "stats_written", state_cpy.stats_written);
    cJSON_AddNumberToObject(_statistics, "archives_written", state_cpy.archives_written);

    _queue = cJSON_CreateObject();
    cJSON_AddItemToObject(_statistics, "queue_status", _queue);

    cJSON_AddNumberToObject(_queue, "syscheck_queue_usage", queue_cpy.syscheck_queue_usage);
    cJSON_AddNumberToObject(_queue, "syscheck_queue_size", queue_cpy.syscheck_queue_size);
    cJSON_AddNumberToObject(_queue, "syscollector_queue_usage", queue_cpy.syscollector_queue_usage);
    cJSON_AddNumberToObject(_queue, "syscollector_queue_size", queue_cpy.syscollector_queue_size);
    cJSON_AddNumberToObject(_queue, "rootcheck_queue_usage", queue_cpy.rootcheck_queue_usage);
    cJSON_AddNumberToObject(_queue, "rootcheck_queue_size", queue_cpy.rootcheck_queue_size);
    cJSON_AddNumberToObject(_queue, "sca_queue_usage", queue_cpy.sca_queue_usage);
    cJSON_AddNumberToObject(_queue, "sca_queue_size", queue_cpy.sca_queue_size);
    cJSON_AddNumberToObject(_queue, "hostinfo_queue_usage", queue_cpy.hostinfo_queue_usage);
    cJSON_AddNumberToObject(_queue, "hostinfo_queue_size", queue_cpy.hostinfo_queue_size);
    cJSON_AddNumberToObject(_queue, "winevt_queue_usage", queue_cpy.winevt_queue_usage);
    cJSON_AddNumberToObject(_queue, "winevt_queue_size", queue_cpy.winevt_queue_size);
    cJSON_AddNumberToObject(_queue, "dbsync_queue_usage", queue_cpy.dbsync_queue_usage);
    cJSON_AddNumberToObject(_queue, "dbsync_queue_size", queue_cpy.dbsync_queue_size);
    cJSON_AddNumberToObject(_queue, "upgrade_queue_usage", queue_cpy.upgrade_queue_usage);
    cJSON_AddNumberToObject(_queue, "upgrade_queue_size", queue_cpy.upgrade_queue_size);
    cJSON_AddNumberToObject(_queue, "events_queue_usage", queue_cpy.events_queue_usage);
    cJSON_AddNumberToObject(_queue, "events_queue_size", queue_cpy.events_queue_size);
    cJSON_AddNumberToObject(_queue, "processed_queue_usage", queue_cpy.processed_queue_usage);
    cJSON_AddNumberToObject(_queue, "processed_queue_size", queue_cpy.processed_queue_size);
    cJSON_AddNumberToObject(_queue, "alerts_queue_usage", queue_cpy.alerts_queue_usage);
    cJSON_AddNumberToObject(_queue, "alerts_queue_size", queue_cpy.alerts_queue_size);
    cJSON_AddNumberToObject(_queue, "firewall_queue_usage", queue_cpy.firewall_queue_usage);
    cJSON_AddNumberToObject(_queue, "firewall_queue_size", queue_cpy.firewall_queue_size);
    cJSON_AddNumberToObject(_queue, "fts_queue_usage", queue_cpy.fts_queue_usage);
    cJSON_AddNumberToObject(_queue, "fts_queue_size", queue_cpy.fts_queue_size);
    cJSON_AddNumberToObject(_queue, "stats_queue_usage", queue_cpy.stats_queue_usage);
    cJSON_AddNumberToObject(_queue, "stats_queue_size", queue_cpy.stats_queue_size);
    cJSON_AddNumberToObject(_queue, "archives_queue_usage", queue_cpy.archives_queue_usage);
    cJSON_AddNumberToObject(_queue, "archives_queue_size", queue_cpy.archives_queue_size);

    return asys_state_json;
}
