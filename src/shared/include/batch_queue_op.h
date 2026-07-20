/* Copyright (C) 2015, Wazuh Inc.
 * May, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef BATCH_QUEUE_OP_H
#define BATCH_QUEUE_OP_H

#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include "hashmap_op.h"
#include "queue_linked_op.h"

/**
 * @brief Agent slot within the scheduler ring.
 *
 * Each slot owns:
 *  - the agent key string
 *  - the per-agent FIFO queue
 *  - the link to the next active agent in the singly-linked circular ring
 *
 * @note `in_ring` is an atomic latch indicating whether the slot currently
 *       participates in the active ring (0 = not in ring, 1 = in ring).
 */
typedef struct w_rr_agent_slot {
    char *key;                        ///< Agent key (owned by the slot)
    w_linked_queue_t *q;              ///< Per-agent queue (see queue_linked_op.h)
    struct w_rr_agent_slot *next;     ///< Next link in singly-linked circular ring
    _Atomic int in_ring;              ///< 0/1: slot is currently in the active ring
} w_rr_agent_slot_t;

/**
 * @brief Main structure for the per-agent round-robin scheduler.
 *
 * The ring is a singly-linked circular list. The consumer advances `cursor`
 * each turn (agent), drains the selected agent queue outside of the ring lock,
 * and producers may reinsert the slot (set `in_ring=1`) if new items arrive
 * while the consumer is draining.
 */
typedef struct w_rr_queue {
    /* Active agents ring (singly-linked, circular) */
    w_rr_agent_slot_t *ring_head;
    w_rr_agent_slot_t *ring_tail;
    w_rr_agent_slot_t *cursor;        ///< Next agent to drain (RR)
    w_rr_agent_slot_t *prev_cursor;   ///< Previous node to `cursor` (for removal in a singly-linked ring)

    /* Index: agent_key -> slot (average O(1)) */
    hashmap_t agent_index;

    /* Scheduler-level synchronization (ring + index) */
    pthread_mutex_t ring_mu;
    pthread_cond_t any_available;

    size_t ring_slots;                ///< Number of slots currently in the ring

    /* Limits and counters */
    size_t max_items_global;          ///< Global item limit (0 = unlimited)
    size_t max_items_per_agent;       ///< Per-agent item limit (0 = unlimited)
    _Atomic size_t items_global;      ///< Approximate global item count

    /* Callbacks */
    void (*dispose)(void *);          ///< Called to dispose an item dropped without processing (optional)
} w_rr_queue_t;

/*==============================================================================
 * Initialization / Configuration
 *============================================================================*/

/**
 * @brief Create the scheduler. The global limit controls overall backpressure.
 *
 * @param max_items_global Global item limit across all agents (0 = unlimited).
 * @return A new scheduler instance, or NULL on allocation failure.
 */
w_rr_queue_t *batch_queue_init(size_t max_items_global);

/**
 * @brief Free the scheduler and all internal queues.
 *
 * If there are unprocessed items remaining and `dispose` is set, `dispose`
 * will be called on each item before freeing structures.
 *
 * @param sched Scheduler to free (NULL-safe).
 */
void batch_queue_free(w_rr_queue_t *sched);

/**
 * @brief Set the disposal callback for items dropped without being processed.
 *
 * @param sched Scheduler
 * @param dispose Function pointer to dispose items; may be NULL to disable.
 */
void batch_queue_set_dispose(w_rr_queue_t *sched, void (*dispose)(void *));

/**
 * @brief Set a per-agent item limit (0 = unlimited).
 *
 * Enqueue operations that would exceed this limit return `-ENOSPC`.
 *
 * @param sched Scheduler
 * @param max_items_per_agent Maximum number of queued items per agent
 */
void batch_queue_set_agent_max(w_rr_queue_t *sched, size_t max_items_per_agent);

/*==============================================================================
 * Production (Multiple Producers)
 *============================================================================*/

/**
 * @brief Enqueue an item for the given agent.
 *
 * If the agent slot does not exist, it is created. If the slot is not in the
 * active ring, it is inserted and `any_available` is signaled.
 *
 * Synchronization:
 *  - Takes the scheduler’s `ring_mu` to update the index/ring membership.
 *  - Pushes into the per-agent queue using its own synchronization.
 *
 * Error handling:
 *  - Returns `0` on success.
 *  - Returns `-ENOSPC` if global/per-agent limits would be exceeded.
 *  - Returns `-ENOMEM` or other negative errno on allocation errors.
 *
 * Ownership:
 *  - On success, ownership of `data` is transferred to the scheduler.
 *  - On failure, the caller retains ownership of `data`.
 *
 * @param sched Scheduler
 * @param agent_key Agent key (copied internally)
 * @param data Pointer to the item payload
 * @return 0 on success, negative errno on failure.
 */
int batch_queue_enqueue_ex(w_rr_queue_t *sched, const char *agent_key, void *data);

/*==============================================================================
 * Consumption (Single Consumer)
 *============================================================================*/

/**
 * @brief Drain the next agent queue (single RR turn).
 *
 * Behavior:
 *  - Blocks until there is at least one active agent or the absolute timeout
 *    is reached.
 *  - Captures the current `cursor` slot, advances the cursor (RR) under lock,
 *    and temporarily marks the captured slot as "not in ring" (`in_ring=0`).
 *  - Drains that agent’s queue **outside** the ring lock by repeatedly calling
 *    `consume(data, user)` for each item present at the time of capture.
 *  - If new items for the same agent arrive during the drain, producers will
 *    reinsert the slot into the ring (since `in_ring=0`) for a future turn.
 *
 * @param sched Scheduler
 * @param abstime Absolute timeout; if NULL, blocks indefinitely.
 * @param consume Callback invoked once per dequeued item.
 * @param user Opaque user pointer passed to `consume`.
 * @param out_agent_key If non-NULL, set to a borrowed pointer to the agent key
 *                      of the drained slot (valid until slot is dropped).
 * @return Number of items drained in this turn, or 0 on timeout/none.
 */
size_t batch_queue_drain_next_ex(w_rr_queue_t *sched,
                                 const struct timespec *abstime,
                                 void (*consume)(void *data, void *user),
                                 void *user,
                                 const char **out_agent_key);

/*==============================================================================
 * Utilities / Metrics
 *============================================================================*/

/**
 * @brief Check whether there are no active agents in the ring.
 *
 * @param sched Scheduler
 * @return 1 if empty, 0 otherwise.
 */
int batch_queue_empty(const w_rr_queue_t *sched);

/**
 * @brief Approximate global size (sum of per-agent queues).
 *
 * @param sched Scheduler
 * @return Approximate number of queued items.
 */
size_t batch_queue_size(const w_rr_queue_t *sched);

/**
 * @brief Number of active slots currently in the ring.
 *
 * @param sched Scheduler
 * @return Count of ring slots.
 */
size_t batch_queue_ring_size(const w_rr_queue_t *sched);

/**
 * @brief Approximate queue size for a given agent.
 *
 * @param sched Scheduler
 * @param agent_key Agent key
 * @return Size of the agent queue, or 0 if the agent does not exist.
 */
size_t batch_queue_agent_size(w_rr_queue_t *sched, const char *agent_key);

/**
 * @brief Drop (remove) an agent and dispose all its queued items.
 *
 * If `dispose` is configured, it will be called for each item in the agent’s
 * queue before freeing the nodes. The slot is removed from the ring and the
 * index, and its key is freed.
 *
 * @param sched Scheduler
 * @param agent_key Agent key
 * @return 1 if the agent existed and was removed, 0 if it did not exist.
 */
int batch_queue_drop_agent(w_rr_queue_t *sched, const char *agent_key);

#endif /* BATCH_QUEUE_OP_H */
