/*
 * Wazuh Manager Task producer client
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef MANAGER_TASK_OP_H
#define MANAGER_TASK_OP_H

#include <stdbool.h>

/**
 * The producer side of the manager task queue: creating rows, counting them, and asking what an
 * agent still owes. Everything here speaks the `task <sub-command> <json>` protocol over
 * `queue/db/wdb`, which is how a producer OUTSIDE modulesd reaches the queue.
 *
 * It lives in shared/ rather than in the Task Manager because its callers cannot link the Task
 * Manager: `create_manager_task` is in modulesd's static library, modulesd is not built with
 * -rdynamic, and authd and the vulnerability scanner are a separate daemon and a separate shared
 * object respectively. A second copy of the wire protocol in each of them is the alternative.
 *
 * The dispatcher's own client is deliberately NOT this one -- it holds a long-lived connection per
 * lane and needs the claim, requeue and sweep commands a producer has no business issuing.
 */

/* The task types a producer outside the Task Manager may create. Spelled here rather than taken
 * from the registry for the same linkage reason; the registry remains the authority on everything
 * ELSE about a type (lane, timeouts, retry policy), and a producer needs none of that. */
#define MANAGER_TASK_TYPE_AGENT_DELETE "agent_delete_indexer"
#define MANAGER_TASK_TYPE_VD_SCAN      "vd_scan"

/* The statuses a producer needs to name. The full set lives in the schema's CHECK constraint. */
#define MANAGER_TASK_STATUS_PENDING "pending"
#define MANAGER_TASK_STATUS_CLAIMED "claimed"

/// What a creation did. Every value except FAILED means the row exists.
typedef enum {
    MANAGER_TASK_CREATE_FAILED = -1, ///< The request did not complete; nothing can be assumed.
    MANAGER_TASK_CREATED = 0,
    /// A pending row for this agent and type already existed and was returned instead. Only
    /// reachable for a type whose descriptor sets coalesce.
    MANAGER_TASK_COALESCED,
    /// The id was already taken. NORMAL for a deterministic-id type -- it is what makes a creator
    /// that can run twice for one logical event idempotent -- and a broken RNG for a random-id one.
    MANAGER_TASK_COLLIDED,
    /// The type's admission bound is full. The row was NOT created.
    MANAGER_TASK_QUEUE_FULL
} manager_task_create_result;

/// What an agent still owes for one task type.
typedef enum {
    MANAGER_TASK_STATUS_FAILED = -1, ///< Could not be determined. Callers must fail safe.
    MANAGER_TASK_STATUS_NONE = 0,    ///< No row for this agent and type at all.
    MANAGER_TASK_STATUS_OUTSTANDING, ///< A row exists and has not reached a terminal status.
    MANAGER_TASK_STATUS_TERMINAL     ///< The newest row is done, one way or another.
} manager_task_status;

/**
 * @brief One row to create.
 *
 * `payload` is the CONSUMER's request body, verbatim: the dispatcher POSTs it unchanged and adds no
 * headers, so whoever creates a row owns the shape of what the consumer receives. There is no
 * body-construction hook anywhere in the Task Manager, by design -- module knowledge lives in the
 * producer, not in the queue.
 */
typedef struct manager_task_request_t {
    const char *task_id;   ///< 64 hex characters; see the id helpers below.
    const char *task_type;
    const char *agent_id;  ///< Optional: agent-subject types only.
    const char *payload;   ///< JSON, capped at 16 KB once escaped (wazuh-db enforces it).
    long long create_time;
    /// When the dispatcher may first attempt it. 0 defers to CREATE_TIME.
    long long next_attempt_at;
    /// Fold into an existing pending row of the same agent and type instead of inserting.
    bool coalesce;
    /// Admission bound on pending rows of this type; 0 for unbounded.
    int max_pending;
} manager_task_request_t;

/**
 * @brief The task id of one agent deletion: SHA-256("mt:del:" agent_id ":" journal_seq).
 *
 * DETERMINISTIC because a single deletion has two legitimate creators -- the writer's phase 3 and
 * startup reconciliation -- and only a stable id makes the second one a no-op.
 *
 * Keyed on the journal SEQUENCE rather than a timestamp. With a timestamp, a second genuine
 * deletion of the same agent in the same second would derive the first one's id and be silently
 * swallowed by the collision -- and the collision target need not even be live, since a completed
 * row inside the retention window collides just as well.
 *
 * @return 64 lowercase hex characters, caller-owned, or NULL on a bad argument.
 */
char* manager_task_id_agent_delete(const char *agent_id, long long journal_seq);

/**
 * @brief A random task id: SHA-256("mt:" tag ":" <128 random bits>).
 *
 * RANDOM because its creator can be called twice meaning two different things, and deduplication is
 * the create command's job rather than the id's. Hashed rather than used raw so every task id is
 * the same 64 characters whatever produced it.
 *
 * @param tag Short type tag, e.g. "scan".
 * @return 64 lowercase hex characters, caller-owned, or NULL on failure.
 */
char* manager_task_id_random(const char *tag);

/**
 * @brief Create one manager task.
 *
 * @param request The row.
 * @param timeout Seconds to allow for the round trip; 0 waits indefinitely.
 * @param sock Reusable wazuh-db socket, or NULL for a private one.
 * @param[out] surviving_task_id Optional. The id of the row that actually exists, which on a
 *                               coalesce is NOT the one that was asked for. Caller frees.
 * @return A manager_task_create_result.
 */
int manager_task_create(const manager_task_request_t *request, int timeout, int *sock, char **surviving_task_id);

/**
 * @brief Count the rows of one type in one status.
 *
 * @return The count, or -1 when it could not be measured. -1 is NOT zero, and callers that use this
 *         as a bound must keep their previous value rather than treating a failure as an empty
 *         queue.
 */
int manager_task_count(const char *task_type, const char *status, int timeout, int *sock);

/**
 * @brief What the newest row of this type says about one agent.
 *
 * @return A manager_task_status.
 */
int manager_task_agent_status(const char *agent_id, const char *task_type, int timeout, int *sock);

#endif /* MANAGER_TASK_OP_H */
