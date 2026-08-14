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
#include <stdlib.h>

remoted_state_t remoted_state = {0};
static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;

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

void rem_inc_recv_events() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.events_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_ctrl() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.ctrl_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_events_failed() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.events_failed_count++;
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

void rem_inc_ctrl_queue_inserted() {
    w_mutex_lock(&state_mutex);
    remoted_state.ctrl_queue_breakdown.inserted_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_ctrl_queue_replaced() {
    w_mutex_lock(&state_mutex);
    remoted_state.ctrl_queue_breakdown.replaced_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_ctrl_queue_processed() {
    w_mutex_lock(&state_mutex);
    remoted_state.ctrl_queue_breakdown.processed_count++;
    w_mutex_unlock(&state_mutex);
}

cJSON* rem_create_state_json() {
    remoted_state_t state_cpy;

    w_mutex_lock(&state_mutex);
    memcpy(&state_cpy, &remoted_state, sizeof(remoted_state_t));
    w_mutex_unlock(&state_mutex);

    cJSON *rem_state_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(rem_state_json, "uptime", state_cpy.uptime);
    cJSON_AddNumberToObject(rem_state_json, "timestamp", time(NULL));
    cJSON_AddStringToObject(rem_state_json, "name", ARGV0);

    cJSON *_metrics = cJSON_CreateObject();
    cJSON_AddItemToObject(rem_state_json, "metrics", _metrics);

    // Fields within metrics are sorted alphabetically

    cJSON *_bytes = cJSON_CreateObject();
    cJSON_AddItemToObject(_metrics, "bytes", _bytes);

    cJSON_AddNumberToObject(_bytes, "received", state_cpy.recv_bytes);
    cJSON_AddNumberToObject(_bytes, "sent", state_cpy.sent_bytes);

    cJSON_AddNumberToObject(_metrics, "keys_reload_count", state_cpy.keys_reload_count);

    cJSON *_messages = cJSON_CreateObject();
    cJSON_AddItemToObject(_metrics, "messages", _messages);

    cJSON *_received_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_messages, "received_breakdown", _received_breakdown);

    cJSON_AddNumberToObject(_received_breakdown, "control", state_cpy.recv_breakdown.ctrl_count);

    cJSON *_control_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_received_breakdown, "control_breakdown", _control_breakdown);

    cJSON_AddNumberToObject(_control_breakdown, "keepalive", state_cpy.recv_breakdown.ctrl_breakdown.keepalive_count);
    cJSON_AddNumberToObject(_control_breakdown, "request", state_cpy.recv_breakdown.ctrl_breakdown.request_count);
    cJSON_AddNumberToObject(_control_breakdown, "shutdown", state_cpy.recv_breakdown.ctrl_breakdown.shutdown_count);
    cJSON_AddNumberToObject(_control_breakdown, "startup", state_cpy.recv_breakdown.ctrl_breakdown.startup_count);

    cJSON_AddNumberToObject(_received_breakdown, "events_failed", state_cpy.recv_breakdown.events_failed_count);
    cJSON_AddNumberToObject(_received_breakdown, "dequeued_after", state_cpy.recv_breakdown.dequeued_count);
    cJSON_AddNumberToObject(_received_breakdown, "discarded", state_cpy.recv_breakdown.discarded_count);
    cJSON_AddNumberToObject(_received_breakdown, "events", state_cpy.recv_breakdown.events_count);
    cJSON_AddNumberToObject(_received_breakdown, "states", state_cpy.recv_breakdown.states_count);
    cJSON_AddNumberToObject(_received_breakdown, "ping", state_cpy.recv_breakdown.ping_count);
    cJSON_AddNumberToObject(_received_breakdown, "unknown", state_cpy.recv_breakdown.unknown_count);
    cJSON_AddNumberToObject(_received_breakdown, "upgrade_ack", state_cpy.recv_breakdown.upgrade_ack_count);

    cJSON *_sent_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_messages, "sent_breakdown", _sent_breakdown);

    cJSON_AddNumberToObject(_sent_breakdown, "ack", state_cpy.sent_breakdown.ack_count);
    cJSON_AddNumberToObject(_sent_breakdown, "ar", state_cpy.sent_breakdown.ar_count);
    cJSON_AddNumberToObject(_sent_breakdown, "discarded", state_cpy.sent_breakdown.discarded_count);
    cJSON_AddNumberToObject(_sent_breakdown, "request", state_cpy.sent_breakdown.request_count);
    cJSON_AddNumberToObject(_sent_breakdown, "shared", state_cpy.sent_breakdown.shared_count);

    cJSON *_queues = cJSON_CreateObject();
    cJSON_AddItemToObject(_metrics, "queues", _queues);

    cJSON *_received_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "received", _received_q);

    // cJSON_AddNumberToObject(_received_q, "size", rem_get_tsize());
    // cJSON_AddNumberToObject(_received_q, "usage", rem_get_qsize());
    cJSON_AddNumberToObject(_received_q, "size", rem_get_input_max_bytes());
    cJSON_AddNumberToObject(_received_q, "usage", rem_get_input_bytes_used());

    cJSON_AddNumberToObject(_metrics, "tcp_sessions", state_cpy.tcp_sessions);

    cJSON_AddNumberToObject(_metrics, "control_messages_queue_usage", control_msg_queue ? indexed_queue_size(control_msg_queue) : 0);

    cJSON *_ctrl_queue_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_metrics, "control_messages_queue_breakdown", _ctrl_queue_breakdown);

    cJSON_AddNumberToObject(_ctrl_queue_breakdown, "inserted", state_cpy.ctrl_queue_breakdown.inserted_count);
    cJSON_AddNumberToObject(_ctrl_queue_breakdown, "replaced", state_cpy.ctrl_queue_breakdown.replaced_count);
    cJSON_AddNumberToObject(_ctrl_queue_breakdown, "processed", state_cpy.ctrl_queue_breakdown.processed_count);

    return rem_state_json;
}

