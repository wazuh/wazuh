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

#define REM_MAX_NUM_AGENTS_STATS 150

#include <stdint.h>
#include "../wazuh_db/helpers/wdb_global_helpers.h"

/* Status structures */

typedef struct _ctrl_msgs_t {
    uint64_t keepalive_count;
    uint32_t startup_count;
    uint32_t shutdown_count;
    uint32_t request_count;
} ctrl_msgs_t;

typedef struct _recv_msgs_t {
    uint64_t evt_count;
    uint64_t ctrl_count;
    uint32_t ping_count;
    uint32_t unknown_count;
    uint32_t dequeued_count;
    uint32_t discarded_count;
    ctrl_msgs_t ctrl_breakdown;
} recv_msgs_t;

typedef struct _sent_msgs_t {
    uint64_t ack_count;
    uint64_t shared_count;
    uint32_t ar_count;
    uint32_t sca_count;
    uint32_t request_count;
    uint32_t discarded_count;
} sent_msgs_t;

typedef struct _remoted_state_t {
    uint64_t uptime;
    uint64_t recv_bytes;
    uint64_t sent_bytes;
    uint32_t tcp_sessions;
    uint32_t keys_reload_count;
    uint32_t ctrl_msg_queue_usage;
    recv_msgs_t recv_breakdown;
    sent_msgs_t sent_breakdown;
} remoted_state_t;

typedef struct _remoted_agent_state_t {
    uint64_t uptime;
    uint64_t recv_evt_count;
    uint64_t recv_ctrl_count;
    ctrl_msgs_t ctrl_breakdown;
    sent_msgs_t sent_breakdown;
} remoted_agent_state_t;

/* Status functions */

/**
 * @brief Listen to remoted socket for new requests
 */
void* remcom_main(__attribute__((unused)) void * arg) ;

/**
 * @brief Main function of remoted status writer
 */
void* rem_state_main();

/**
 * @brief Increment TCP sessions counter
 */
void rem_inc_tcp();

/**
 * @brief Decrement TCP sessions counter
 */
void rem_dec_tcp();

/**
 * @brief Increment control message queue usage
 */
void rem_inc_ctrl_msg_queue_usage();

/**
 * @brief Decrement control message queue usage
 */
void rem_dec_ctrl_msg_queue_usage();

/**
 * @brief Increment bytes received
 * @param bytes Number of bytes to increment
 */
void rem_add_recv(unsigned long bytes);

/**
 * @brief Increment received event messages counter
 * @param agent_id Id of the agent that corresponds to the message
 */
void rem_inc_recv_evt(const char *agent_id);

/**
 * @brief Increment received control messages counter
 * @param agent_id Id of the agent that corresponds to the message
 */
void rem_inc_recv_ctrl(const char *agent_id);

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
 * @param agent_id Id of the agent that corresponds to the message
 */
void rem_inc_recv_ctrl_keepalive(const char *agent_id);

/**
 * @brief Increment received startup control messages counter
 * @param agent_id Id of the agent that corresponds to the message
 */
void rem_inc_recv_ctrl_startup(const char *agent_id);

/**
 * @brief Increment received shutdown control messages counter
 * @param agent_id Id of the agent that corresponds to the message
 */
void rem_inc_recv_ctrl_shutdown(const char *agent_id);

/**
 * @brief Increment received request control messages counter
 * @param agent_id Id of the agent that corresponds to the message
 */
void rem_inc_recv_ctrl_request(const char *agent_id);

/**
 * @brief Increment bytes sent
 * @param bytes Number of bytes to increment
 */
void rem_add_send(unsigned long bytes);

/**
 * @brief Increment sent ack messages counter
 * @param agent_id Id of the agent that corresponds to the message
 */
void rem_inc_send_ack(const char *agent_id);

/**
 * @brief Increment sent shared file messages counter
 * @param agent_id Id of the agent that corresponds to the message
 */
void rem_inc_send_shared(const char *agent_id);

/**
 * @brief Increment sent AR messages counter
 * @param agent_id Id of the agent that corresponds to the message
 */
void rem_inc_send_ar(const char *agent_id);

/**
 * @brief Increment sent CFGA messages counter
 * @param agent_id Id of the agent that corresponds to the message
 */
void rem_inc_send_cfga(const char *agent_id);

/**
 * @brief Increment sent request messages counter
 * @param agent_id Id of the agent that corresponds to the message
 */
void rem_inc_send_request(const char *agent_id);

/**
 * @brief Increment sent discarded messages counter
 * @param agent_id Id of the agent that corresponds to the message
 */
void rem_inc_send_discarded(const char *agent_id);

/**
 * @brief Increment keys reload counter
 */
void rem_inc_keys_reload();

/**
 * @brief Create a JSON object with all the remoted state information
 * @return JSON object
 */
cJSON* rem_create_state_json();

/**
 * @brief Create a JSON object with all the remoted agents state information
 * @param agents_ids Ids of the requested agents
 * @return JSON object
 */
cJSON* rem_create_agents_state_json(int* agents_ids);

#endif
