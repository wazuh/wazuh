/* Remoted state management functions
 * May 25, 2018
 *
 * Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "remoted.h"
#include "state.h"
#include <pthread.h>

remoted_state_t remoted_state;
static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;
static int rem_write_state();
static char *refresh_time;

void * rem_state_main() {
    int interval = getDefine_Int("remoted", "state_interval", 0, 86400);

    if (!interval) {
        minfo("State file is disabled.");
        return NULL;
    }

    os_calloc(48, sizeof(char), refresh_time);
    if (interval < 60) {
        snprintf(refresh_time, 48, "Updated every %i seconds.", interval);
    } else if (interval < 3600) {
        snprintf(refresh_time, 48, "Updated every %i minutes.", interval/60);
    } else {
        snprintf(refresh_time, 48, "Updated every %i hours.", interval/3600);
    }

    mdebug1("State file updating thread started.");

    while (1) {
        rem_write_state();
        sleep(interval);
    }

    return NULL;
}

int rem_write_state() {
    FILE * fp;
    char path[PATH_MAX - 8];
    char path_temp[PATH_MAX + 1];
    remoted_state_t state_cpy;

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

    w_mutex_lock(&state_mutex);
    memcpy(&state_cpy, &remoted_state, sizeof(remoted_state_t));
    w_mutex_unlock(&state_mutex);

    fprintf(fp,
        "# State file for %s\n"
        "# THIS FILE WILL BE DEPRECATED IN FUTURE VERSIONS\n"
        "# %s\n"
        "\n"
        "# Queue size\n"
        "queue_size='%zu'\n"
        "\n"
        "# Total queue size\n"
        "total_queue_size='%zu'\n"
        "\n"
        "# TCP sessions\n"
        "tcp_sessions='%u'\n"
        "\n"
        "# Events sent to Analysisd\n"
        "evt_count='%lu'\n"
        "\n"
        "# Control messages received\n"
        "ctrl_msg_count='%lu'\n"
        "\n"
        "# Discarded messages\n"
        "discarded_count='%u'\n"
        "\n"
        "# Total number of bytes sent\n"
        "sent_bytes='%lu'\n"
        "\n"
        "# Total number of bytes received\n"
        "recv_bytes='%lu'\n"
        "\n"
        "# Messages dequeued after the agent closes the connection\n"
        "dequeued_after_close='%u'\n",
        __local_name, refresh_time, rem_get_qsize(), rem_get_tsize(), state_cpy.tcp_sessions,
        state_cpy.recv_breakdown.evt_count, state_cpy.recv_breakdown.ctrl_count, state_cpy.recv_breakdown.discarded_count,
        state_cpy.sent_bytes, state_cpy.recv_bytes, state_cpy.recv_breakdown.dequeued_count);

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

void rem_inc_tcp() {
    w_mutex_lock(&state_mutex);
    remoted_state.tcp_sessions++;
    w_mutex_unlock(&state_mutex);
}

void rem_dec_tcp() {
    w_mutex_lock(&state_mutex);
    remoted_state.tcp_sessions--;
    w_mutex_unlock(&state_mutex);
}

void rem_add_recv(unsigned long bytes) {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_bytes += bytes;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_evt() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.evt_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_ctrl() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.ctrl_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_ping() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.ping_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_unknown() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.unknown_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_dequeued() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.dequeued_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_discarded() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.discarded_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_ctrl_keepalive() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.ctrl_breakdown.keepalive_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_ctrl_startup() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.ctrl_breakdown.startup_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_ctrl_shutdown() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.ctrl_breakdown.shutdown_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_ctrl_request() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.ctrl_breakdown.request_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_add_send(unsigned long bytes) {
    w_mutex_lock(&state_mutex);
    remoted_state.sent_bytes += bytes;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_send_ack() {
    w_mutex_lock(&state_mutex);
    remoted_state.sent_breakdown.ack_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_send_shared() {
    w_mutex_lock(&state_mutex);
    remoted_state.sent_breakdown.shared_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_send_ar() {
    w_mutex_lock(&state_mutex);
    remoted_state.sent_breakdown.ar_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_send_cfga() {
    w_mutex_lock(&state_mutex);
    remoted_state.sent_breakdown.cfga_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_send_request() {
    w_mutex_lock(&state_mutex);
    remoted_state.sent_breakdown.request_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_send_discarded() {
    w_mutex_lock(&state_mutex);
    remoted_state.sent_breakdown.discarded_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_keys_reload() {
    w_mutex_lock(&state_mutex);
    remoted_state.keys_reload_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_update_shared_files() {
    w_mutex_lock(&state_mutex);
    remoted_state.update_shared_files_count++;
    w_mutex_unlock(&state_mutex);
}

cJSON* rem_create_state_json() {
    remoted_state_t state_cpy;
    cJSON *_statistics = NULL;
    cJSON *_received = NULL;
    cJSON *_control = NULL;
    cJSON *_sent = NULL;
    cJSON *_queue = NULL;

    w_mutex_lock(&state_mutex);
    memcpy(&state_cpy, &remoted_state, sizeof(remoted_state_t));
    w_mutex_unlock(&state_mutex);

    cJSON *rem_state_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(rem_state_json, "version", VERSION);
    cJSON_AddNumberToObject(rem_state_json, "timestamp", time(NULL));
    cJSON_AddStringToObject(rem_state_json, "daemon_name", ARGV0);

    _statistics = cJSON_CreateObject();
    cJSON_AddItemToObject(rem_state_json, "statistics", _statistics);

    cJSON_AddNumberToObject(_statistics, "tcp_sessions", state_cpy.tcp_sessions);

    cJSON_AddNumberToObject(_statistics, "received_bytes", state_cpy.recv_bytes);

    _received = cJSON_CreateObject();
    cJSON_AddItemToObject(_statistics, "messages_received_breakdown", _received);

    cJSON_AddNumberToObject(_received, "event_messages", state_cpy.recv_breakdown.evt_count);
    cJSON_AddNumberToObject(_received, "control_messages", state_cpy.recv_breakdown.ctrl_count);

    _control = cJSON_CreateObject();
    cJSON_AddItemToObject(_received, "control_breakdown", _control);

    cJSON_AddNumberToObject(_control, "request_messages", state_cpy.recv_breakdown.ctrl_breakdown.request_count);
    cJSON_AddNumberToObject(_control, "startup_messages", state_cpy.recv_breakdown.ctrl_breakdown.startup_count);
    cJSON_AddNumberToObject(_control, "shutdown_messages", state_cpy.recv_breakdown.ctrl_breakdown.shutdown_count);
    cJSON_AddNumberToObject(_control, "keepalive_messages", state_cpy.recv_breakdown.ctrl_breakdown.keepalive_count);

    cJSON_AddNumberToObject(_received, "ping_messages", state_cpy.recv_breakdown.ping_count);
    cJSON_AddNumberToObject(_received, "unknown_messages", state_cpy.recv_breakdown.unknown_count);
    cJSON_AddNumberToObject(_received, "dequeued_after_close_messages", state_cpy.recv_breakdown.dequeued_count);
    cJSON_AddNumberToObject(_received, "discarded_messages", state_cpy.recv_breakdown.discarded_count);

    cJSON_AddNumberToObject(_statistics, "sent_bytes", state_cpy.sent_bytes);

    _sent = cJSON_CreateObject();
    cJSON_AddItemToObject(_statistics, "messages_sent_breakdown", _sent);

    cJSON_AddNumberToObject(_sent, "ack_messages", state_cpy.sent_breakdown.ack_count);
    cJSON_AddNumberToObject(_sent, "shared_file_messages", state_cpy.sent_breakdown.shared_count);
    cJSON_AddNumberToObject(_sent, "ar_messages", state_cpy.sent_breakdown.ar_count);
    cJSON_AddNumberToObject(_sent, "cfga_messages", state_cpy.sent_breakdown.cfga_count);
    cJSON_AddNumberToObject(_sent, "request_messages", state_cpy.sent_breakdown.request_count);
    cJSON_AddNumberToObject(_sent, "discarded_messages", state_cpy.sent_breakdown.discarded_count);

    _queue = cJSON_CreateObject();
    cJSON_AddItemToObject(_statistics, "queue_status", _queue);

    cJSON_AddNumberToObject(_queue, "receive_queue_usage", rem_get_qsize());
    cJSON_AddNumberToObject(_queue, "receive_queue_size", rem_get_tsize());

    cJSON_AddNumberToObject(_statistics, "keys_reload_count", state_cpy.keys_reload_count);
    cJSON_AddNumberToObject(_statistics, "update_shared_files_count", state_cpy.update_shared_files_count);

    return rem_state_json;
}
