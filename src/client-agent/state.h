/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef AGENTD_STATE_H
#define AGENTD_STATE_H

/* Time output */
#define W_AGENTD_STATE_TIME_FORMAT "%Y-%m-%d %H:%M:%S" ///< Time format for the JSON and the file output
#define W_AGENTD_STATE_TIME_LENGHT (19 + 1)            ///< Maximum time size

/* State file and JSON responses field's names */
#define W_AGENTD_JSON_ERROR       "error"          ///< An error code
#define W_AGENTD_JSON_DATA        "data"           ///< The information of the response
#define W_AGENTD_FIELD_STATUS     "status"         ///< Agent status
#define W_AGENTD_FIELD_KEEP_ALIVE "last_keepalive" ///< Last time a keepalive was sent
#define W_AGENTD_FIELD_LAST_ACK   "last_ack"       ///< Last time a control message was received
#define W_AGENTD_FIELD_MSG_COUNT  "msg_count"      ///< Number of generated events
#define W_AGENTD_FIELD_MSG_SENT   "msg_sent"       ///< Number of messages sent to the manager
#define W_AGENTD_FIELD_MSG_BUFF   "msg_buffer"     ///< Number of current buffered events
#define W_AGENTD_FIELD_EN_BUFF    "buffer_enabled" ///< Anti-flooding mechanism (buffer) is enable

#include "shared.h"
#include "read-agents.h"
#include "agentd.h"

/**
 * @brief Represent the update field of the statistics
 */
typedef enum {
    UPDATE_STATUS = 0,   ///< Update status represented by agent_state_t
    UPDATE_KEEPALIVE,    ///< Update keepalive represented by time_t
    UPDATE_ACK,          ///< Update last ack represented by time_t
    INCREMENT_MSG_COUNT, ///< Increment number of messages sent to the buffer
    INCREMENT_MSG_SEND,   ///< Increment number of messages sent to the manager
    RESET_MSG_COUNT_ON_SHRINK ///< Reset message counter due to buffer shrinking, taking into account new buffer capacity.
} w_agentd_state_update_t;

/**
 * @brief A agent_state_t instance stores agent statistics
 */
typedef struct agent_state_t {
    agent_status_t status;  ///< Agent status
    time_t last_keepalive;  ///< Last time a keepalive was sent
    time_t last_ack;        ///< Last time a control message was received
    unsigned int msg_count; ///< Number of generated events
    unsigned int msg_sent;  ///< Number of messages (events + control messages) sent to the manager
} agent_state_t;

/**
 * @brief Configure and initialize statistics
 */
void w_agentd_state_init();

/**
 * @brief Main thread, write the statistics in the file
 */
#ifdef WIN32
DWORD WINAPI state_main(__attribute__((unused)) LPVOID arg);
#else
void * state_main(__attribute__((unused)) void * args);
#endif
/**
 * @brief Update agent statistics
 * @param type Action
 * @param data New data value (if required)
 */
void w_agentd_state_update(w_agentd_state_update_t type, void * data);

/**
 * @brief Returns statistics in real time
 * @return Statistics in raw json format
 */
char * w_agentd_state_get();

#endif /* AGENTD_STATE_H */
