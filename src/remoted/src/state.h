/*
 * Copyright (C) 2015, Wazuh Inc.
 * May 04, 2022
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef STATEREMOTE_H
#define STATEREMOTE_H

#include "wazuhdb_queries_op.h"
#include <stdint.h>

/* Status structures */

typedef struct _ctrl_msgs_t
{
    uint64_t keepalive_count;
    uint32_t startup_count;
    uint32_t shutdown_count;
    uint32_t request_count;
} ctrl_msgs_t;

typedef struct _recv_msgs_t
{
    uint64_t events_count;
    uint64_t ctrl_count;
    uint64_t states_count;
    uint32_t upgrade_ack_count;
    uint32_t ping_count;
    uint32_t unknown_count;
    uint32_t dequeued_count;
    uint32_t discarded_count;
    uint32_t events_failed_count;
    ctrl_msgs_t ctrl_breakdown;
} recv_msgs_t;

typedef struct _ctrl_queue_breakdown_t
{
    uint32_t inserted_count;  // New messages inserted into queue
    uint32_t replaced_count;  // Messages replaced/updated in queue
    uint32_t processed_count; // Messages processed from queue
} ctrl_queue_breakdown_t;

typedef struct _sent_msgs_t
{
    uint64_t ack_count;
    uint64_t shared_count;
    uint32_t ar_count;
    uint32_t request_count;
    uint32_t discarded_count;
} sent_msgs_t;

typedef struct _remoted_state_t
{
    uint64_t uptime;
    uint64_t recv_bytes;
    uint64_t sent_bytes;
    uint32_t tcp_sessions;
    uint32_t keys_reload_count;
    recv_msgs_t recv_breakdown;
    sent_msgs_t sent_breakdown;
    ctrl_queue_breakdown_t ctrl_queue_breakdown;
} remoted_state_t;

/* Status functions */

/**
 * @brief Listen to remoted socket for new requests
 */
void* remcom_main(__attribute__((unused)) void* arg);

/**
 * @brief Increment TCP sessions counter
 */
void rem_inc_tcp();

/**
 * @brief Decrement TCP sessions counter
 */
void rem_dec_tcp();

/**
 * @brief Increment bytes received
 * @param bytes Number of bytes to increment
 */
void rem_add_recv(unsigned long bytes);

/**
 * @brief Increment received event messages counter
 */
void rem_inc_recv_events();

/**
 * @brief Increment received control messages counter
 */
void rem_inc_recv_ctrl();

/**
 * @brief Increment failed-event messages counter
 *
 * Counts events that were accepted from the agent but could not be
 * delivered to analysisd, either because the batch queue refused the
 * enqueue or because the analysisd dispatcher dropped the item (POST
 * failed or connection unavailable).
 */
void rem_inc_recv_events_failed();

/**
 * @brief Increment received ping messages counter
 */
void rem_inc_recv_ping();

/**
 * @brief Increment received unknown messages counter
 */
void rem_inc_recv_unknown();

/**
 * @brief Increment received dequeued after closed messages counter
 */
void rem_inc_recv_dequeued();

/**
 * @brief Increment received discarded messages counter
 */
void rem_inc_recv_discarded();

/**
 * @brief Increment received keepalive control messages counter
 */
void rem_inc_recv_ctrl_keepalive();

/**
 * @brief Increment received startup control messages counter
 */
void rem_inc_recv_ctrl_startup();

/**
 * @brief Increment received shutdown control messages counter
 */
void rem_inc_recv_ctrl_shutdown();

/**
 * @brief Increment received request control messages counter
 */
void rem_inc_recv_ctrl_request();

/**
 * @brief Increment bytes sent
 * @param bytes Number of bytes to increment
 */
void rem_add_send(unsigned long bytes);

/**
 * @brief Increment sent ack messages counter
 */
void rem_inc_send_ack();

/**
 * @brief Increment sent shared file messages counter
 */
void rem_inc_send_shared();

/**
 * @brief Increment sent AR messages counter
 */
void rem_inc_send_ar();

/**
 * @brief Increment sent request messages counter
 */
void rem_inc_send_request();

/**
 * @brief Increment sent discarded messages counter
 */
void rem_inc_send_discarded();

/**
 * @brief Increment keys reload counter
 */
void rem_inc_keys_reload();

/**
 * @brief Increment control message queue inserted counter
 */
void rem_inc_ctrl_queue_inserted();

/**
 * @brief Increment control message queue replaced counter
 */
void rem_inc_ctrl_queue_replaced();

/**
 * @brief Increment control message queue processed counter
 */
void rem_inc_ctrl_queue_processed();

/**
 * @brief Create a JSON object with all the remoted state information
 * @return JSON object
 */
cJSON* rem_create_state_json();

#endif
