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
#include "wm_manager_task_schedules.h"

/**
 * @brief Work a lane performs between tasks, with no row behind it.
 *
 * THE ESCAPE HATCH FOR WORK THAT IS NOT WORTH A ROW. Size-based log rotation is two w_stat() calls
 * every minute: idempotent, instantaneous, and harmless to miss, since a skipped tick just rotates
 * a minute later. Giving it a task type would cost about 1440 rows a day, each one inserted,
 * polled, claimed, committed, executed and eventually retained, to buy durability nothing needs.
 *
 * A direct action still runs on a LANE thread rather than on the scheduler that signals it, because
 * the scheduler is also the work poller and the ownership sweeper, and w_rotate_log() with
 * compression on gzips a file of up to the configured threshold inline.
 *
 * The cost of putting one here rather than in a task type: no retry, no record, no visibility
 * beyond its own log lines. Anything that needs any of those is a task.
 */
typedef void (*wm_manager_task_direct_action)(void);

/**
 * @brief One registered direct action.
 */
typedef struct _wm_manager_task_direct_def {
    const char *name;                 ///< For the log line when it is signalled.
    wm_manager_task_lane lane;        ///< Lane whose thread performs it.
    int interval;                     ///< Seconds between signals.
    wm_manager_task_direct_action run;
} wm_manager_task_direct_def;

/// Number of registered direct actions.
size_t wm_manager_task_direct_count(void);

/**
 * @brief Iterate the registered direct actions.
 *
 * @param[in] index Position, from zero.
 * @return The definition, or NULL once the end is reached.
 */
const wm_manager_task_direct_def* wm_manager_task_direct_at(size_t index);

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

    /* One pending flag per direct action, guarded by its own lane's mutex. A flag rather than a
     * counter: repeated signals coalesce into one run, which is what makes a lane that spent two
     * minutes on a bounded task perform one size-rotation check rather than two. */
    bool *direct_pending;

    pthread_t scheduler;
    bool scheduler_started;
    wm_manager_task_client scheduler_client;

    /* The recurring schedules, with their configuration resolved once at startup. Held here rather
     * than read per spawn so that an operator editing ossec.conf cannot change the interval of a
     * schedule halfway through a poll, and so the whole set is one restart away from consistent. */
    wm_manager_task_schedule *schedules;
    size_t schedule_count;

    int poll_interval;
    int sweep_interval;
    int claim_grace;

    /* Stop signal owned by the dispatcher, checked alongside wm_shutdown_requested by every loop
     * that can outlive this struct. Two callers need it: a start() that failed partway has live
     * threads to bring down while the module is NOT shutting down, and stop() itself, which used to
     * rely on the module's flag already being set and would otherwise wake workers that go straight
     * back to claiming while it joins them. */
    volatile bool stopping;

    /* Whether the per-lane mutexes and condition variables have been initialised, so stop() knows
     * whether there is anything to destroy -- and destroys them exactly once. */
    bool primed;
} wm_manager_task_dispatcher;

/**
 * @brief Start the dispatcher: build the registry, capture identity, run the startup sweep and
 *        spawn the lane and scheduler threads.
 *
 * @param[out] dispatcher Dispatcher to start.
 * @param[in] consumer_socket Socket the routed task types' consumer listens on.
 * @return 0 on success, -1 on failure, in which case everything this call started has already been
 *         brought down and joined -- so the caller must NOT call wm_manager_task_dispatcher_stop()
 *         on a failed start, and must not treat the dispatcher as running.
 */
int wm_manager_task_dispatcher_start(wm_manager_task_dispatcher *dispatcher, const char *consumer_socket);

/**
 * @brief Wake every worker and join every thread.
 *
 * Called by the module's own main thread, which is the one thread modulesd joins, so that the
 * lanes are joined rather than killed wherever they happen to be.
 *
 * IT IS NOT BOUNDED BY THE SHUTDOWN BUDGET, and that is worth stating plainly. A worker parked
 * inside its consumer call returns only when that call's own deadline expires -- up to
 * `manager_task_delete_timeout` (600 s by default) on the delete lane -- and there is no
 * cancellation primitive here to cut it short. wazuh-control waits MAX_KILL_TRIES (30) seconds and
 * then sends SIGKILL, so in that case the process is killed rather than joined, and this function
 * never returns.
 *
 * What makes that survivable is the state machine, not the join: the claim was committed before the
 * handler ran and the outcome write is deliberately left in the deferred transaction, so a SIGKILL
 * mid-call leaves the row `claimed`, the next start's ownership sweep reclaims it, and the handler
 * -- required to be idempotent -- runs again. A half-written wazuh-db query is impossible for the
 * same reason it always was: every sub-command is one round trip, and an unfinished one is simply
 * not applied.
 *
 * So the cost of a shutdown that catches a delete in flight is a 30 s stop and a hard kill, not
 * lost or duplicated work. Lowering the delete lane's request timeout under 30 s would make the
 * join fit the budget, at the price of abandoning purges that legitimately take longer.
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
 * @brief What the spawn loop should do with one due schedule.
 *
 * Separated from the loop so the interaction between the three rules -- node scope, overlap-skip
 * and missed-run coalescing -- is testable without a database or a cluster.
 */
typedef enum _wm_manager_task_spawn_decision {
    WM_MANAGER_TASK_SPAWN = 0, ///< Create an instance, then advance the slot.
    WM_MANAGER_TASK_SPAWN_SKIP,///< Advance the slot without creating anything.
    WM_MANAGER_TASK_SPAWN_HOLD ///< Leave the slot where it is and reconsider on the next poll.
} wm_manager_task_spawn_decision;

/**
 * @brief Decide whether a due schedule spawns an instance now.
 *
 * SKIP AND HOLD ARE DIFFERENT, and the difference is what keeps `w_is_worker()` off the poll path:
 * it re-parses ossec.conf from disk on every call, so a worker that merely held its master-scoped
 * schedules would re-read the file every five seconds forever. Skipping advances the slot instead,
 * which re-asks once per interval -- the cadence the check belongs at.
 *
 * Overlap skips too, rather than holding, which is the rule that makes a multi-batch
 * `agent_delete_old` suppress its OWN next scheduled run until it finishes. That is correct -- a
 * retention sweep should not start again while the previous one is still walking -- but it means
 * the effective interval under a large backlog is however long the sweep takes, not the configured
 * one.
 *
 * A slot whose overlap could not be determined HOLDS, and that asymmetry is deliberate: advancing
 * on an unanswered question would skip a legitimate run outright, while holding costs one extra
 * query on the next poll and self-heals as soon as wazuh-db answers.
 *
 * @param[in] known Whether this build knows the schedule id and its task type.
 * @param[in] node_allows Whether this node's role permits the schedule to spawn.
 * @param[in] overlap_known Whether the overlap check produced an answer.
 * @param[in] has_active Whether a non-terminal instance of this schedule already exists.
 * @return What to do with the slot.
 */
wm_manager_task_spawn_decision wm_manager_task_spawn_decide(bool known,
                                                            bool node_allows,
                                                            bool overlap_known,
                                                            bool has_active);

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
