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

/* The JSON surfaces (getstate and the /stats push) report UTC in ISO 8601. Only
 * the agent knows its own offset, so a naive local time cannot be recovered
 * downstream; emitting the instant unambiguously makes the manager's
 * normalize_agent_timestamps() a no-op. The .state text file above keeps the
 * local-time format, which is operator-facing. */
#define W_AGENTD_STATE_TIME_FORMAT_ISO8601 "%Y-%m-%dT%H:%M:%SZ"
#define W_AGENTD_STATE_TIME_ISO8601_LENGHT (20 + 1)

/* State file and JSON responses field's names */
#define W_AGENTD_JSON_ERROR       "error"          ///< An error code
#define W_AGENTD_JSON_DATA        "data"           ///< The information of the response
#define W_AGENTD_FIELD_STATUS     "status"         ///< Agent status
#define W_AGENTD_FIELD_KEEP_ALIVE "last_keepalive" ///< Last time a keepalive was sent
#define W_AGENTD_FIELD_MSG_COUNT  "msg_count"      ///< Number of generated events
#define W_AGENTD_FIELD_MSG_SENT   "msg_sent"       ///< Number of messages sent to the manager
#define W_AGENTD_FIELD_MSG_BUFF   "msg_buffer"     ///< Number of current buffered events
#define W_AGENTD_FIELD_EN_BUFF    "buffer_enabled" ///< Anti-flooding mechanism (buffer) is enable

/* Field names for the JSON report. The manager indexes what the agent sends with
 * no compensation of its own, so these are the contract with wazuh-agent-stats
 * (wazuh.agent.statistics.agent.*) rather than a local choice. Nesting follows
 * the schema's dotted convention (wazuh.agent.id, host.os.name); ".total" is the
 * wcs marker for a counter monotonic over the process's uptime. */
#define W_AGENTD_FIELD_MESSAGES       "messages" ///< Message counters, grouped
#define W_AGENTD_FIELD_MESSAGES_COUNT "count"    ///< Number of generated events

#define W_AGENTD_FIELD_TASKS            "tasks"               ///< /control task counters, grouped
#define W_AGENTD_FIELD_TASK_DISPATCHED  "dispatched"          ///< Tasks routed to a handler
#define W_AGENTD_FIELD_TASK_DUPLICATE   "discarded_duplicate" ///< Tasks discarded as duplicates
#define W_AGENTD_FIELD_TASK_FAILED      "failed"              ///< Tasks that failed to dispatch/execute
#define W_AGENTD_FIELD_TOTAL            "total"               ///< Monotonic counter under each

#include "shared.h"
#include "read-agents.h"
#include "agentd.h"

/**
 * @brief Represent the update field of the statistics
 */
typedef enum {
    UPDATE_STATUS = 0,   ///< Update status represented by agent_state_t
    UPDATE_KEEPALIVE,    ///< Update keepalive represented by time_t
    INCREMENT_MSG_COUNT, ///< Increment number of messages sent to the buffer
    INCREMENT_MSG_SEND,   ///< Increment number of messages sent to the manager
    RESET_MSG_COUNT_ON_SHRINK, ///< Reset message counter due to buffer shrinking, taking into account new buffer capacity.
    INCREMENT_TASK_DISPATCHED,         ///< A /control task was routed to a handler
    INCREMENT_TASK_DISCARDED_DUPLICATE, ///< A /control task was discarded as a duplicate
    INCREMENT_TASK_FAILED              ///< A /control task failed to dispatch/execute
} w_agentd_state_update_t;

/**
 * @brief A agent_state_t instance stores agent statistics
 */
typedef struct agent_state_t {
    agent_status_t status;  ///< Agent status
    time_t last_keepalive;  ///< Last time a keepalive was sent
    unsigned int msg_count; ///< Number of generated events
    unsigned int msg_sent;  ///< Number of messages (events + control messages) sent to the manager
    unsigned int task_dispatched;         ///< /control tasks routed to a handler
    unsigned int task_discarded_duplicate; ///< /control tasks discarded as duplicates
    unsigned int task_failed;             ///< /control tasks that failed to dispatch/execute
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
/**
 * @brief Build the agent's statistics body.
 *
 * The bare body, with no {"error","data"} envelope: that is socket framing for
 * "getstate", which its own call site adds, while over HTTPS the error is the
 * response status. Fields with no producer left on this branch are omitted
 * rather than sent empty -- an empty string does not parse as a `date` and the
 * indexer rejects the whole document for it.
 *
 * @return Allocated object the caller owns, or NULL on allocation failure.
 */
cJSON * w_agentd_state_get(void);

#endif /* AGENTD_STATE_H */
