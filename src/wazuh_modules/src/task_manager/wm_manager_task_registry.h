/*
 * Wazuh Module for Task management: manager task registry.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The dispatcher holds no module-specific code. Everything it needs to know about a task type
 * is a row in the table this header describes: which lane runs it, how to reach the consumer,
 * how long to wait, how many times to retry and what to do when the budget runs out. Adding a
 * manager task is a row here plus a handler; it is not a change to the dispatcher, and it is not
 * a change to wazuh-db, which treats TASK_TYPE as opaque text.
 *
 * What does NOT live here is the request body. PAYLOAD is the consumer's body verbatim, authored
 * by whoever creates the row, so a new task type carries its body-building code to its producer
 * rather than looking for a hook in this table.
 */
#ifndef WM_MANAGER_TASK_REGISTRY_H
#define WM_MANAGER_TASK_REGISTRY_H

#include "shared.h"
#include "http_op.h"

/// Per-type override meaning "take the value configured for every type".
#define WM_MANAGER_TASK_USE_DEFAULT (-1)

/// Retry, deferral and admission bounds all use zero to mean "no bound".
#define WM_MANAGER_TASK_UNBOUNDED 0

/**
 * @brief Lanes, the sets of worker threads a task type can be assigned to.
 *
 * Per-type separation exists to stop head-of-line blocking behind a long scan or a bulk
 * deletion. That argument does not reach the periodic core tasks, which run every fifteen
 * minutes, every hour and once a day, so they share one lane rather than holding three threads
 * alive to avoid a daily rotation delaying a disconnect sweep by minutes.
 */
typedef enum _wm_manager_task_lane {
    WM_MANAGER_TASK_LANE_DELETE = 0,
    WM_MANAGER_TASK_LANE_SCAN,
    WM_MANAGER_TASK_LANE_LOCAL,
    WM_MANAGER_TASK_LANE_COUNT
} wm_manager_task_lane;

/**
 * @brief What a handler reports back about one attempt.
 *
 * Note there is no result for "superseded": that is decided at re-queue time by whether another
 * pending row has taken this one's slot, and no handler can observe it.
 */
typedef enum _wm_manager_task_result {
    WM_MANAGER_TASK_OK = 0,   ///< Executed. The row is completed.
    WM_MANAGER_TASK_RETRYABLE,///< Failed in a way that may pass later. Consumes an attempt.
    WM_MANAGER_TASK_TIMEOUT,  ///< Abandoned at the deadline. Consumes an attempt.
    WM_MANAGER_TASK_TERMINAL, ///< Will never succeed. The row fails without consuming budget.
    WM_MANAGER_TASK_NOT_READY,///< The consumer has not bound its socket yet. Costs no attempt.
    WM_MANAGER_TASK_BUSY,     ///< The consumer is still running an abandoned earlier attempt.
    WM_MANAGER_TASK_INCOMPLETE///< The handler bounded its own work and has more to do.
} wm_manager_task_result;

/**
 * @brief A handler that runs inside this process rather than over a socket.
 *
 * @param[in] agent_id Subject agent, or NULL for a task with none.
 * @param[in] payload The task's payload, verbatim.
 * @param[out] error Buffer for a short reason, written on any non-OK result.
 * @param[in] error_len Size of that buffer.
 * @return The outcome of this attempt.
 */
typedef wm_manager_task_result (*wm_manager_task_handler)(const char *agent_id,
                                                          const char *payload,
                                                          char *error,
                                                          size_t error_len);

/**
 * @brief Everything the dispatcher knows about one task type.
 */
typedef struct _wm_manager_task_descriptor {
    const char *name;              ///< Wire name, and the value stored in TASK_TYPE.
    wm_manager_task_lane lane;

    /* Route, for types executed by another module over its Unix socket. NULL path means the
     * type is executed in-process by handler below. */
    const char *method;
    const char *path;
    long connect_timeout_ms;       ///< Routed types only. Never 0: libcurl reads that as its own 300 s default.

    /* Two meanings, one field, because both are "how long one attempt may take" and the watchdog
     * reads it for every type:
     *
     *  - For a ROUTED type it is enforced, by libcurl, and must never be 0 -- libcurl reads a zero
     *    request timeout as "wait forever".
     *  - For a LOCAL type nothing can enforce it: there is no cancellation primitive in the tree. It
     *    is the point past which the watchdog reports the handler as stalled, and must never be 0
     *    either, or the watchdog measures against its bare margin and warns on healthy work. */
    long request_timeout_ms;

    wm_manager_task_handler handler;   ///< Set for in-process types, NULL for routed ones.

    int max_attempts;              ///< Attempts before dead_letter, or UNBOUNDED, or USE_DEFAULT.
    int max_defer;                 ///< Deferrals before dead_letter, or UNBOUNDED, or USE_DEFAULT.
    bool allow_terminal_failure;   ///< When false, a 4xx re-queues instead of failing the row.
    bool coalesce;                 ///< Fold a new row into an existing pending one for the agent.
    int max_pending;               ///< Admission bound on the pending set, or UNBOUNDED.

    char socket_path[PATH_MAX];    ///< Resolved at registry construction, not a compile-time constant.
} wm_manager_task_descriptor;

/**
 * @brief The tunables shared by every task type.
 *
 * Per-type overrides for the two budgets live in the descriptor and are deliberately not
 * operator knobs: a deployment that gave the deletion lane a finite budget would silently
 * reintroduce the orphaned documents this feature exists to prevent.
 */
typedef struct _wm_manager_task_policy {
    int backoff_base;   ///< First retry delay, doubling from there.
    int backoff_cap;    ///< Ceiling for both ladders.
    int defer_base;     ///< First deferral delay, doubling from there.
    int max_attempts;   ///< Default attempt budget.
    int max_defer;      ///< Default deferral budget.
} wm_manager_task_policy;

/**
 * @brief The row state a handler result implies.
 */
typedef struct _wm_manager_task_transition {
    const char *status;        ///< Terminal state to write, or NULL to return the row to pending.
    int attempts;              ///< Value to store. Never lower than the value passed in.
    int defer_count;           ///< Value to store.
    long long next_attempt_at; ///< Only meaningful when status is NULL.
} wm_manager_task_transition_t;

/**
 * @brief Populate a policy from the internal options, applying the documented defaults.
 *
 * @param[out] policy Policy to fill.
 */
void wm_manager_task_policy_load(wm_manager_task_policy *policy);

/**
 * @brief Build the registry, resolving each routed type's consumer socket.
 *
 * @param[in] inventory_sync_socket Socket path inventory-sync is configured to listen on.
 * @return 0 on success, -1 when a descriptor is inconsistent.
 */
int wm_manager_task_registry_init(const char *inventory_sync_socket);

/**
 * @brief Look up a task type by name.
 *
 * @param[in] name Task type.
 * @return The descriptor, or NULL when the type is not registered.
 */
const wm_manager_task_descriptor* wm_manager_task_registry_get(const char *name);

/**
 * @brief Iterate the registry.
 *
 * @param[in] index Position, from zero.
 * @return The descriptor, or NULL once the end is reached.
 */
const wm_manager_task_descriptor* wm_manager_task_registry_at(size_t index);

/**
 * @brief Number of registered task types.
 */
size_t wm_manager_task_registry_count(void);

/**
 * @brief The task types assigned to one lane, in the order that lane rotates through them.
 *
 * @param[in] lane Lane to enumerate.
 * @param[out] count Number of types returned.
 * @return Array of descriptors owned by the registry.
 */
const wm_manager_task_descriptor** wm_manager_task_registry_lane(wm_manager_task_lane lane, size_t *count);

/**
 * @brief Number of worker threads a lane runs.
 *
 * @param[in] lane Lane.
 * @return Thread count, or 0 for an unknown lane.
 */
int wm_manager_task_lane_depth(wm_manager_task_lane lane);

/**
 * @brief Human-readable lane name, for OWNER strings and log lines.
 */
const char* wm_manager_task_lane_name(wm_manager_task_lane lane);

/**
 * @brief Effective attempt budget for a type, resolving USE_DEFAULT against the policy.
 */
int wm_manager_task_max_attempts(const wm_manager_task_descriptor *desc, const wm_manager_task_policy *policy);

/**
 * @brief Effective deferral budget for a type, resolving USE_DEFAULT against the policy.
 */
int wm_manager_task_max_defer(const wm_manager_task_descriptor *desc, const wm_manager_task_policy *policy);

/**
 * @brief Delay before the next attempt of a row that has failed a given number of times.
 *
 * Doubles from the base to the cap. State the arithmetic when changing the budget: at the
 * default base and cap, eight attempts span 30 + 60 + 120 + 240 + 480 + 900 + 900 seconds, about
 * forty-five minutes. A budget of five would be seven and a half, shorter than a routine indexer
 * restart and short enough that the cap is never reached.
 *
 * @param[in] attempts Attempts already made, at least one.
 * @param[in] base First delay.
 * @param[in] cap Ceiling.
 * @return Delay in seconds.
 */
int wm_manager_task_backoff(int attempts, int base, int cap);

/**
 * @brief Delay before retrying a row that was deferred rather than attempted.
 *
 * Starts well below the retry ladder because the common case is a boot race: the dispatcher
 * starts before its in-process consumers bind, and starting at the cap would tax every restart
 * with a fifteen minute delay to price a failure that resolves in seconds.
 *
 * @param[in] defer_count Consecutive deferrals, at least one.
 * @param[in] base First delay.
 * @param[in] cap Ceiling.
 * @return Delay in seconds.
 */
int wm_manager_task_defer_delay(int defer_count, int base, int cap);

/**
 * @brief Decide what a handler result does to the row.
 *
 * @param[in] desc Task type.
 * @param[in] policy Shared tunables.
 * @param[in] result What the handler reported.
 * @param[in] attempts The row's current attempt count.
 * @param[in] defer_count The row's current consecutive deferral count.
 * @param[in] now Current time.
 * @param[out] transition The row state to write.
 */
void wm_manager_task_apply_result(const wm_manager_task_descriptor *desc,
                                  const wm_manager_task_policy *policy,
                                  wm_manager_task_result result,
                                  int attempts,
                                  int defer_count,
                                  long long now,
                                  wm_manager_task_transition_t *transition);

/**
 * @brief Classify a consumer's answer.
 *
 * Read the mapping as Unix-socket, not TCP: every request goes over CURLOPT_UNIX_SOCKET_PATH, so
 * name resolution cannot fail and no DNS, TLS or proxy code is reachable. Anything of that shape
 * appearing here is a sign it was copied from a TCP client.
 *
 * @param[in] rc Return of uhttp_post: a negated libcurl code, an HTTP status, or 0 for success.
 * @param[in] result Result metadata, which must have been zeroed before the call.
 * @param[in] body Response body, which is caller-owned, not NUL-terminated and silently truncated.
 * @param[in] body_len Bytes written into body.
 * @param[in] allow_terminal_failure Whether a 4xx may end the row.
 * @param[out] error Buffer for a short reason.
 * @param[in] error_len Size of that buffer.
 * @return The outcome of this attempt.
 */
wm_manager_task_result wm_manager_task_classify_response(int rc,
                                                         const uhttp_result_t *result,
                                                         const char *body,
                                                         size_t body_len,
                                                         bool allow_terminal_failure,
                                                         char *error,
                                                         size_t error_len);

#endif
