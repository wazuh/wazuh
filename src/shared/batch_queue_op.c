#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <stdio.h>

#include "shared.h"
#include "batch_queue_op.h"
#include "hashmap_op.h"
#include "queue_linked_op.h"

/**
 * @file batch_queue_op.c
 * @brief Round-robin batch queue per agent using a singly linked circular ring
 *        plus a hashmap to index agent slots.
 *
 * #### High-level design
 * - Each agent has its own intrusive FIFO queue (`w_linked_queue_t`).
 * - Active agents are placed in a **singly linked circular ring** to implement
 *   fair, O(1) round-robin drains.
 * - A **hashmap** (string key -> slot*) indexes agent slots by `agent_key`.
 *
 * #### Concurrency model
 * - **Global monitor:** `ring_mu` protects the ring, the agent index lifecycle,
 *   and cursor bookkeeping (`ring_head`, `ring_tail`, `cursor`, `prev_cursor`,
 *   and `ring_slots`).
 * - **Per-agent queue mutex:** `slot->q->mutex` protects each agent’s queue.
 * - **Lock order:** always acquire `ring_mu` **before** any `slot->q->mutex`.
 * - Producers may temporarily release `ring_mu` while holding the per-queue
 *   mutex to reduce global contention (see enqueue handover).
 *
 * #### Ring invariants (when non-empty)
 * - `tail->next == head` (circular, singly linked).
 * - `cursor` points to the next slot to drain; `prev_cursor` points to its
 *   predecessor in the ring.
 * - `s->in_ring` indicates membership (0/1).
 */

// ======================= Ring helpers (singly linked, circular) =======================
//
// Invariants:
// - If the ring is NOT empty: tail->next == head
// - cursor points to the next slot to drain; prev_cursor to the previous of cursor
// - s->in_ring flags membership (0/1)
// - All operations here require ring_mu to be held

/**
 * @brief Append a slot to the active ring (O(1)).
 * @pre ring_mu must be held.
 */
static inline void ring_append(w_rr_queue_t *sched, w_rr_agent_slot_t *s) {
    // pre: ring_mu held
    if (!sched->ring_head) {
        s->next = s; // single-node cycle
        sched->ring_head   = s;
        sched->ring_tail   = s;
        sched->cursor      = s;
        sched->prev_cursor = s;      // valid: single node
    } else {
        s->next = sched->ring_head;
        sched->ring_tail->next = s;
        sched->ring_tail = s;
        // if cursor is at head, its previous is now the new tail
        if (sched->cursor == sched->ring_head) {
            sched->prev_cursor = sched->ring_tail;
        }
    }
    s->in_ring = 1;
    sched->ring_slots++;
}

/**
 * @brief Remove a node from the ring given its predecessor (O(1)).
 * @pre ring_mu must be held.
 */
static inline void ring_remove_node(w_rr_queue_t *sched, w_rr_agent_slot_t *node, w_rr_agent_slot_t *prev) {
    if (!sched->ring_head || !node || !prev) return;

    if (node == prev) {
        // only element
        sched->ring_head = sched->ring_tail = NULL;
        sched->cursor = sched->prev_cursor = NULL;
        sched->ring_slots = 0;
        node->in_ring = 0;
        node->next = NULL;
        return;
    }

    prev->next = node->next;
    if (node == sched->ring_head)  sched->ring_head  = node->next;
    if (node == sched->ring_tail)  sched->ring_tail  = prev;
    if (sched->cursor == node)     sched->cursor     = node->next;
    if (sched->prev_cursor == node) sched->prev_cursor = prev;

    node->in_ring = 0;
    node->next = NULL;
    if (sched->ring_slots) sched->ring_slots--;
}

/**
 * @brief Return the number of slots currently in the ring.
 * @note Takes and releases ring_mu internally.
 */
size_t batch_queue_ring_size(const w_rr_queue_t *sched) {
    if (!sched) return 0;
    pthread_mutex_lock((pthread_mutex_t *)&sched->ring_mu);
    size_t n = sched->ring_slots;
    pthread_mutex_unlock((pthread_mutex_t *)&sched->ring_mu);
    return n;
}

// ======================= O(1) drain of an agent queue =======================
//
// Atomically "steals" the entire chain of nodes from the agent's queue under
// its own mutex and leaves the queue empty. Returns the count of stolen items.

/**
 * @brief Remove and return the entire node chain from a linked queue (O(1)).
 * @param q         Target queue (per-agent).
 * @param out_first Output: first node of the stolen chain (or NULL).
 * @return Number of elements stolen.
 */
static size_t steal_chain(w_linked_queue_t *q, w_linked_queue_node_t **out_first) {
    if (!q || !out_first) return 0;
    pthread_mutex_lock(&q->mutex);
    w_linked_queue_node_t *first = q->first;
    size_t cnt = q->elements;
    q->first = q->last = NULL;
    q->elements = 0;
    pthread_mutex_unlock(&q->mutex);
    *out_first = first;
    return cnt;
}

// ======================= Slot creation / destruction =======================

/**
 * @brief Allocate and initialize a slot for a given agent key.
 * @return New slot pointer or NULL on failure.
 */
static w_rr_agent_slot_t *make_slot(const char *agent_key) {
    w_rr_agent_slot_t *s;
    os_calloc(1, sizeof(*s), s);
    if (!s) return NULL;
    os_strdup(agent_key, s->key);                 // slot owns its key
    if (!s->key) { os_free(s); return NULL; }
    s->q = linked_queue_init();
    if (!s->q) { os_free(s->key); os_free(s); return NULL; }
    s->in_ring = 0;
    s->next = NULL;
    return s;
}

/**
 * @brief Free a slot and optionally adjust the global item counter.
 * @param sched          Scheduler handle (for dispose and global counters).
 * @param s              Slot to free.
 * @param adjust_global  If non-zero, subtract drained items from global counter.
 */
static void free_slot(w_rr_queue_t *sched, w_rr_agent_slot_t *s, int adjust_global) {
    if (!s) return;
    w_linked_queue_node_t *chain = NULL;
    size_t n = steal_chain(s->q, &chain);

    while (chain) {
        w_linked_queue_node_t *nx = chain->next;
        if (sched->dispose) sched->dispose(chain->data);
        os_free(chain);
        chain = nx;
    }
    if (adjust_global && n) {
        atomic_fetch_sub_explicit(&sched->items_global, n, memory_order_relaxed);
    }

    linked_queue_free(s->q);
    os_free(s->key);
    os_free(s);
}

// ======================= API: init / free / config =======================

/**
 * @brief Create a batch queue scheduler.
 * @param max_items_global Optional soft cap for total enqueued items (>0 to enable).
 * @return Initialized scheduler or NULL on error.
 */
w_rr_queue_t *batch_queue_init(size_t max_items_global) {
    w_rr_queue_t *q;
    os_calloc(1, sizeof(*q), q);
    if (!q) return NULL;

    q->ring_head = q->ring_tail = q->cursor = q->prev_cursor = NULL;

    // Embedded hashmap: initialize with a bootstrap capacity
    if (hm_init(&q->agent_index, 64) != 0) { free(q); return NULL; }

    pthread_mutex_init(&q->ring_mu, NULL);
    pthread_cond_init(&q->any_available, NULL);

    q->max_items_global = max_items_global;
    q->max_items_per_agent = 0;
    q->ring_slots = 0;
    atomic_store(&q->items_global, 0);
    q->dispose = NULL;
    return q;
}

/**
 * @brief Destroy the scheduler and all agent slots/queues.
 * @note No producers/consumer should be active at this point.
 */
void batch_queue_free(w_rr_queue_t *sched) {
    if (!sched) return;

    // For maximum safety, you may take ring_mu around the iteration.
    hm_iter_t it;
    const char *k;
    void *val;
    hm_iter_init(&sched->agent_index, &it);
    while (hm_iter_next(&it, &k, &val)) {
        w_rr_agent_slot_t *slot = (w_rr_agent_slot_t*)val;
        // No need to touch the ring: we are shutting everything down.
        free_slot(sched, slot, /*adjust_global=*/0);
    }

    hm_destroy(&sched->agent_index);
    pthread_cond_destroy(&sched->any_available);
    pthread_mutex_destroy(&sched->ring_mu);
    os_free(sched);
}

/**
 * @brief Set a disposer callback to free item payloads on drop/free.
 */
void batch_queue_set_dispose(w_rr_queue_t *sched, void (*dispose)(void *)) {
    if (!sched) return;
    pthread_mutex_lock(&sched->ring_mu);
    sched->dispose = dispose;
    pthread_mutex_unlock(&sched->ring_mu);
}

/**
 * @brief Set a per-agent queue size limit (0 = unlimited).
 */
void batch_queue_set_agent_max(w_rr_queue_t *sched, size_t max_items_per_agent) {
    if (!sched) return;
    pthread_mutex_lock(&sched->ring_mu);
    sched->max_items_per_agent = max_items_per_agent;
    pthread_mutex_unlock(&sched->ring_mu);
}

// ======================= Enqueue (multi-producer) =======================
//
// Single monitor: ring_mu protects the index, ring, and slot lifecycles.
// Lock order: ring_mu → slot->q->mutex

/**
 * @brief Enqueue an item for a given agent.
 * @return 0 on success; -ENOSPC if limits exceeded; -ENOMEM on allocation errors;
 *         -EINVAL on invalid args.
 *
 * Steps (summarized):
 * 0) Approximate global limit check (lock-free); roll back on failure later.
 * 1) Under ring_mu: lookup or create the agent slot in the hashmap.
 * 2) Lock the per-agent queue BEFORE releasing ring_mu (safe handover).
 * 3) Release ring_mu to reduce global contention.
 * 4) Push the item into the agent queue (respecting per-agent cap).
 * 5) If the queue transitioned empty→non-empty, (re)append to ring and signal.
 */
int batch_queue_enqueue_ex(w_rr_queue_t *sched, const char *agent_key, void *data) {
    if (!sched || !agent_key || !data) return -EINVAL;

    // 0) Approximate global limit (lock-free). Roll back if later steps fail.
    size_t prev = atomic_fetch_add_explicit(&sched->items_global, 1, memory_order_relaxed);
    if (sched->max_items_global && prev + 1 > sched->max_items_global) {
        atomic_fetch_sub_explicit(&sched->items_global, 1, memory_order_relaxed);
        if (sched->dispose) sched->dispose(data);
        return -ENOSPC;
    }

    pthread_mutex_lock(&sched->ring_mu);

    // 1) Lookup/create slot in the HASHMAP (protected by ring_mu)
    void *val = NULL;
    w_rr_agent_slot_t *slot = NULL;
    if (hm_get(&sched->agent_index, agent_key, &val)) {
        slot = (w_rr_agent_slot_t*)val;
    } else {
        slot = make_slot(agent_key);
        if (!slot) {
            pthread_mutex_unlock(&sched->ring_mu);
            atomic_fetch_sub_explicit(&sched->items_global, 1, memory_order_relaxed);
            if (sched->dispose) sched->dispose(data);
            return -ENOMEM;
        }
        if (hm_put(&sched->agent_index, agent_key, slot) != 0) {
            pthread_mutex_unlock(&sched->ring_mu);
            free_slot(sched, slot, /*adjust_global=*/0);
            atomic_fetch_sub_explicit(&sched->items_global, 1, memory_order_relaxed);
            if (sched->dispose) sched->dispose(data);
            return -ENOMEM;
        }
    }

    // 2) Take the queue lock **before releasing ring_mu** (safe handover)
    pthread_mutex_lock(&slot->q->mutex);

    // 3) Release ring_mu to reduce global contention
    pthread_mutex_unlock(&sched->ring_mu);

    // 4) Enqueue into the agent queue
    int reject = 0;
    int need_ring_append = (slot->q->elements == 0);

    if (sched->max_items_per_agent && slot->q->elements >= sched->max_items_per_agent) {
        reject = 1;
    } else {
        w_linked_queue_node_t *n;
        os_malloc(sizeof(*n), n);
        if (!n) {
            pthread_mutex_unlock(&slot->q->mutex);
            atomic_fetch_sub_explicit(&sched->items_global, 1, memory_order_relaxed);
            if (sched->dispose) sched->dispose(data);
            return -ENOMEM;
        }
        n->data = data;
        n->next = NULL;
        if (slot->q->last) {
            n->prev = slot->q->last;
            slot->q->last->next = n;
            slot->q->last = n;
        } else {
            // empty queue
            n->prev = NULL;
            slot->q->first = slot->q->last = n;
        }
        slot->q->elements++;
    }

    pthread_mutex_unlock(&slot->q->mutex);

    if (reject) {
        atomic_fetch_sub_explicit(&sched->items_global, 1, memory_order_relaxed);
        if (sched->dispose) sched->dispose(data);
        return -ENOSPC;
    }

    // 5) If queue transitioned empty->non-empty, (re)insert into the ring and signal availability
    if (need_ring_append) {
        pthread_mutex_lock(&sched->ring_mu);
        if (!slot->in_ring) {
            ring_append(sched, slot);
            pthread_cond_signal(&sched->any_available);
        }
        pthread_mutex_unlock(&sched->ring_mu);
    }

    return 0;
}

// ======================= Drain-next (single consumer) =======================

/**
 * @brief Drain the next agent in round-robin order, consuming all its items.
 *
 * Snapshot-drain: detach the entire per-agent queue once (under its mutex),
 * release all locks, and process the detached chain without further locking.
 */
size_t batch_queue_drain_next_ex(w_rr_queue_t *sched,
                                 const struct timespec *abstime,
                                 void (*consume)(void *data, void *user),
                                 void *user,
                                 const char **out_agent_key) {
    if (!sched || !consume) return 0;

    pthread_mutex_lock(&sched->ring_mu);

    // Wait until there is at least one active slot in the ring
    while (!sched->cursor) {
        if (abstime) {
            int r = pthread_cond_timedwait(&sched->any_available, &sched->ring_mu, abstime);
            if (r == ETIMEDOUT) { pthread_mutex_unlock(&sched->ring_mu); return 0; }
            if (r != 0)        { pthread_mutex_unlock(&sched->ring_mu); return 0; }
        } else {
            pthread_cond_wait(&sched->any_available, &sched->ring_mu);
        }
    }

    // Select next slot and advance RR cursor
    w_rr_agent_slot_t *slot = sched->cursor;
    w_rr_agent_slot_t *prev = sched->prev_cursor ? sched->prev_cursor : sched->ring_tail;

    sched->cursor      = slot->next;
    sched->prev_cursor = prev;     // the new "previous" of the next cursor will be this slot

    // Remove from ring for this turn
    ring_remove_node(sched, slot, prev);
    if (out_agent_key) *out_agent_key = slot->key;

    // Queue handover: lock per-queue BEFORE releasing ring_mu (lock order respected)
    pthread_mutex_lock(&slot->q->mutex);
    pthread_mutex_unlock(&sched->ring_mu);

    // Snapshot-detach the whole queue in O(1)
    w_linked_queue_node_t *head = slot->q->first;
    slot->q->first = NULL;
    slot->q->last  = NULL;
    slot->q->elements = 0;
    pthread_mutex_unlock(&slot->q->mutex);

    // Process detached chain without any locks
    size_t drained = 0;
    for (w_linked_queue_node_t *n = head; n; ) {
        w_linked_queue_node_t *next = n->next;
        drained++;
        consume(n->data, user);
        os_free(n);
        n = next;
    }

    // Adjust global items metric
    if (drained) {
        atomic_fetch_sub_explicit(&sched->items_global, drained, memory_order_relaxed);
    }

    // If new items arrived meanwhile, producers have already re-appended this slot
    // to the ring (because in_ring==0). They will be picked up next turn.
    return drained;
}

// ======================= Utilities / Metrics =======================

/**
 * @brief Whether the scheduler has no ready agents in the ring.
 * @return 1 if empty; 0 otherwise.
 */
int batch_queue_empty(const w_rr_queue_t *sched) {
    if (!sched) return 1;
    pthread_mutex_lock((pthread_mutex_t *)&sched->ring_mu);
    int empty = (sched->cursor == NULL);
    pthread_mutex_unlock((pthread_mutex_t *)&sched->ring_mu);
    return empty;
}

/**
 * @brief Total number of items enqueued across all agents (approximate).
 */
size_t batch_queue_size(const w_rr_queue_t *sched) {
    if (!sched) return 0;
    return atomic_load_explicit(&sched->items_global, memory_order_relaxed);
}

/**
 * @brief Current number of items queued for a specific agent.
 */
size_t batch_queue_agent_size(w_rr_queue_t *sched, const char *agent_key) {
    if (!sched || !agent_key) return 0;
    pthread_mutex_lock(&sched->ring_mu);
    void *val = NULL;
    if (!hm_get(&sched->agent_index, agent_key, &val)) {
        pthread_mutex_unlock(&sched->ring_mu);
        return 0;
    }
    w_rr_agent_slot_t *slot = (w_rr_agent_slot_t*)val;
    pthread_mutex_lock(&slot->q->mutex);
    size_t n = slot->q->elements;
    pthread_mutex_unlock(&slot->q->mutex);
    pthread_mutex_unlock(&sched->ring_mu);
    return n;
}

/**
 * @brief Find the predecessor of a slot within the ring.
 * @note Used for rare operations such as forced drop.
 */
static w_rr_agent_slot_t *ring_find_prev(w_rr_queue_t *sched, w_rr_agent_slot_t *slot) {
    if (!sched->ring_head || !slot) return NULL;
    w_rr_agent_slot_t *p = sched->ring_head;
    do {
        w_rr_agent_slot_t *nx = p->next;
        if (nx == slot) return p;
        p = nx;
    } while (p && p != sched->ring_head);
    return NULL;
}

/**
 * @brief Remove an agent entirely: from ring (if present) and from the index.
 *        Frees the slot and its queued items (using `dispose` if set).
 * @return 1 if the agent was found and dropped; 0 if it did not exist.
 */
int batch_queue_drop_agent(w_rr_queue_t *sched, const char *agent_key) {
    if (!sched || !agent_key) return 0;

    pthread_mutex_lock(&sched->ring_mu);

    void *val = NULL;
    if (!hm_get(&sched->agent_index, agent_key, &val)) {
        pthread_mutex_unlock(&sched->ring_mu);
        return 0;
    }
    w_rr_agent_slot_t *slot = (w_rr_agent_slot_t*)val;

    if (slot->in_ring) {
        w_rr_agent_slot_t *prev = ring_find_prev(sched, slot);
        if (!prev) {
            // Should exist; for robustness, do not remove if not found
            pthread_mutex_unlock(&sched->ring_mu);
            return 0;
        }
        ring_remove_node(sched, slot, prev);
    }

    // Remove from index under the same monitor
    (void)hm_del(&sched->agent_index, agent_key);

    // Lock the queue to safely free
    pthread_mutex_lock(&slot->q->mutex);
    pthread_mutex_unlock(&slot->q->mutex);

    pthread_mutex_unlock(&sched->ring_mu);

    // Outside the monitor: free and adjust global counter
    free_slot(sched, slot, /*adjust_global=*/1);
    return 1;
}
