/*
 * Wazuh Module for Task management: manager task dispatcher.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Lane threads claim manager tasks, run them, and record the outcome with retry accounting. One
 * scheduler thread finds the work and wakes the lanes; the lanes never poll on their own, because
 * six threads running the same claim on a timer would multiply contention on the one per-database
 * mutex that every tasks.db command already serialises on.
 *
 * The thread bodies here are deliberately thin. Every decision they make -- which type to claim
 * next, whether a claimed row may be reclaimed, whether a lane has stalled -- is a pure function
 * so it can be tested without threads, a socket or a database.
 */
#ifndef WM_MANAGER_TASK_DISPATCHER_H
#define WM_MANAGER_TASK_DISPATCHER_H

#include "shared.h"
#include "wm_manager_task_registry.h"
#include "wm_manager_task_client.h"
#include "wm_manager_task_owner.h"

/// Per-lane response buffer. Bodies are small status objects; the payload travels the other way.
#define WM_MANAGER_TASK_RESPONSE_LEN 4096

/// Task ids are 64 hex characters.
#define WM_MANAGER_TASK_ID_LEN 65

struct _wm_manager_task_dispatcher;

/**
 * @brief One lane worker thread and the state it publishes to the sweep and the watchdog.
 */
typedef struct _wm_manager_task_worker {
    struct _wm_manager_task_dispatcher *dispatcher; ///< Owner, for the lane's shared wake state.
    wm_manager_task_lane lane;
    int index;
    char owner[WM_MANAGER_TASK_OWNER_LEN];

    pthread_t thread;
    bool started;

    wm_manager_task_client client; ///< This worker's own wazuh-db connection.
    void *http;                    ///< This worker's own uhttp_client_t; never shared.
    char response[WM_MANAGER_TASK_RESPONSE_LEN];

    /* Published state. Read by the scheduler's sweep and by the watchdog, so it is guarded
     * rather than assumed atomic: the task id is a string. */
    pthread_mutex_t published_mutex;
    char inflight_task_id[WM_MANAGER_TASK_ID_LEN];
    bool inflight;
    time_t last_progress_at;
    long request_timeout_ms; ///< Deadline of the call in flight, for the watchdog.

    /* Where this lane is in its type rotation. Only the worker touches it. */
    size_t rotation;
} wm_manager_task_worker;

/**
 * @brief The dispatcher: its workers, its scheduler and the state they share.
 */
typedef struct _wm_manager_task_dispatcher {
    wm_manager_task_owner self;
    wm_manager_task_policy policy;

    wm_manager_task_worker *workers;
    size_t worker_count;

    /* One condition variable per lane. The scheduler signals a lane when any of its types has
     * work due; the mapping from type to lane is many to one and the signal does not say which. */
    pthread_mutex_t lane_mutex[WM_MANAGER_TASK_LANE_COUNT];
    pthread_cond_t lane_cond[WM_MANAGER_TASK_LANE_COUNT];
    bool lane_signalled[WM_MANAGER_TASK_LANE_COUNT];

    pthread_t scheduler;
    bool scheduler_started;
    wm_manager_task_client scheduler_client;

    int poll_interval;
    int sweep_interval;
    int claim_grace;
} wm_manager_task_dispatcher;

/**
 * @brief Start the dispatcher: build the registry, capture identity, run the startup sweep and
 *        spawn the lane and scheduler threads.
 *
 * @param[out] dispatcher Dispatcher to start.
 * @param[in] consumer_socket Socket the routed task types' consumer listens on.
 * @return 0 on success, -1 on failure, in which case nothing has been started.
 */
int wm_manager_task_dispatcher_start(wm_manager_task_dispatcher *dispatcher, const char *consumer_socket);

/**
 * @brief Wake every worker and join every thread.
 *
 * Called by the module's own main thread, which is the one thread modulesd joins, so that the
 * lanes are joined inside the shared shutdown budget rather than killed wherever they happen to
 * be. A half-written query to wazuh-db becomes impossible rather than unlikely.
 *
 * @param[in,out] dispatcher Dispatcher to stop.
 */
void wm_manager_task_dispatcher_stop(wm_manager_task_dispatcher *dispatcher);

/**
 * @brief Report any lane that has been in one call for longer than its deadline plus a margin.
 *
 * Observation only. There is no cancellation primitive in the tree -- no pthread_cancel, no
 * usable alarm -- so making a hang visible instead of silent is the whole of what is achievable.
 *
 * @param[in] dispatcher Dispatcher to inspect.
 * @param[in] now Current time.
 */
void wm_manager_task_dispatcher_watchdog(wm_manager_task_dispatcher *dispatcher, time_t now);

/* The decisions, separated from the threads that make them. */

/**
 * @brief Pick the next task type a lane should try to claim, advancing its rotation.
 *
 * A lane that carries several types walks them in a fixed order and starts each pass at the type
 * after the one it last claimed from, so a busy type cannot starve its siblings. The claim
 * predicate stays scoped to a single type: an IN clause would give up the single-seek property
 * the claim index exists for.
 *
 * @param[in] lane Lane to rotate.
 * @param[in,out] rotation Lane's position, carried between calls.
 * @param[in] offset Which type of this pass to return, from zero.
 * @return The type to try, or NULL once the pass has covered every type on the lane.
 */
const wm_manager_task_descriptor* wm_manager_task_rotate(wm_manager_task_lane lane, size_t *rotation, size_t offset);

/**
 * @brief Whether a lane has been in one call long enough to be worth reporting.
 *
 * @param[in] inflight Whether the lane is executing anything.
 * @param[in] last_progress_at When it started.
 * @param[in] request_timeout_ms Deadline of the call in flight.
 * @param[in] now Current time.
 * @return true when the lane is past its own deadline by a clear margin.
 */
bool wm_manager_task_worker_stalled(bool inflight, time_t last_progress_at, long request_timeout_ms, time_t now);

/**
 * @brief Look up what a named lane worker says it is executing.
 *
 * @param[in] dispatcher Dispatcher holding the workers.
 * @param[in] owner OWNER string naming the worker.
 * @param[out] task_id Buffer for the id, set to an empty string when the lane is idle or unknown.
 * @param[in] len Size of that buffer.
 * @return true when the owner named a worker of this process.
 */
bool wm_manager_task_worker_inflight(const wm_manager_task_dispatcher *dispatcher,
                                     const char *owner,
                                     char *task_id,
                                     size_t len);

#endif
