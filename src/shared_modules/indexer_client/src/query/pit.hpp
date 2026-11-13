/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_PIT_HPP
#define _INDEXER_CLIENT_PIT_HPP

// Managed point in time. NORMATIVE: the contract of IQuery::pit(), Pit, PitSession and
// the PitRegistry; pit.cpp, pitRegistry.cpp and their tests follow it. Nothing here is public API.
//
// ENGINE. Every PIT request (create, page, search) runs through execute() (engine.hpp) with the QueryOptions given to
// pit(): the same clocks, verdicts and wake-ups as the queries. The DELETE is the registry's (below).
//
// CREATE (pit(indices, PitOptions, QueryOptions, deadline)). Reentrancy, then validation without a request
// (InvalidArgument with the field: indices as the queries, keepAlive > 0, the QueryOptions checks), then
// POST /<i1,i2>/_search/point_in_time?keep_alive=<ms>ms&allow_partial_pit_creation=false[&expand_wildcards=all], no
// body. A 2xx needs a non-empty string `pit_id` (else ItemPermanent); a 404 index_not_found_exception ⇒ NotFound.
// A partial PIT is never accepted: the flag makes the indexer refuse one (its default is to create it), and a 2xx that
// still reports _shards.failed > 0 is retried within the budget (an unavailable shard is usually transient) whose
// PIT, since it exists, goes to PitRegistry::discard() to be deleted.
// Slots: before every attempt preAttempt() takes one slot with PitRegistry::acquire() (none ⇒ the call
// ends QueueFull "too many open PITs (N)", N = open + reserved + acquired, no request, refusedFull + 1). The
// observer settles each attempt's slot:
// Answered 2xx with an id ⇒ the slot becomes the PIT's (open); a refused 2xx naming a PIT (partial) ⇒ discard(): open,
// its DELETE queued at once; any other refused 2xx (over the response cap, unparsable, no pit_id: a PIT may exist that
// cannot be addressed) ⇒ reserve(now + keepAlive); any other Answered ⇒ released; Failed with
// mayHaveSent or Abandoned ⇒ reserve(now + keepAlive) (the PIT may exist: an orphan until its keep_alive);
// Failed without mayHaveSent ⇒ released. Late results change nothing (the reservation stays until it lapses).
// A wait for a usable node is no attempt: the slot stays held through it (up to the call's deadline), while a
// backoff after a settled attempt holds none (the next attempt acquires again).
//
// STATE. PitState {id (renewable, under its mutex), keepAlive, generation (process-wide counter), expired (atomic),
// lastUse, the QueryOptions of pit(), indices, client (shared_ptr: the consumer name stays reserved while a handle
// lives), registry (weak)}. Pit and every PitSession share it; Pit is copyable; cursor(), next() and search() are safe
// from different threads (a consumer may page up to 32 slices at once, one cursor each). One next() at a time per
// cursor: a cursor (and its copies) is one sequence of pages, each continuing from the previous one's search_after, so
// a next() called while another is in progress on the same cursor ⇒ InvalidState "another next() is in progress on this
// cursor", at once and without a request. Different cursors, even of the same Pit and slice, never wait on each other.
//
// SEARCH (PitSession::next, Pit::search). POST /_search?allow_partial_search_results=false with
// pit {id, keep_alive: <ms>ms} on every request (it renews the PIT), and:
//   next()    size = pageSize, query, sort (empty ⇒ [{"_shard_doc":"asc"}]; a consumer sort gets no tiebreaker added:
//             the consumer decides), _source when not null, slice {id, max} when given, and search_after = the last
//             hit's sort or, on the cursor's first page, track_total_hits: true ⇒ PitPage::total. last = hits <
//             pageSize; next() after last ⇒ Ok, empty page, last, no request. A retried page repeats the same body
//             (same id and search_after): the body is built once per page. Invalid cursor parameters (slice.id >= max,
//             max < 2, pageSize == 0) ⇒ the first next() returns InvalidArgument with the field, no request.
//   search()  the consumer's body with `pit` overwritten by {id, keep_alive}; nothing else touched.
// A `pit_id` in a 2xx that differs from the current one replaces it (last arrival wins: every id of the same PIT
// addresses the same contexts); the DELETE uses the id current when the last handle goes. lastUse = when the end of
// the last attempt that may have been sent was observed: an upper bound of the last real use, so the expiry clock of
// the DELETE below is conservative.
//
// EXPIRY (k3-6). A 404 whose error.type or any root_cause[].type is search_context_missing_exception, or a 2xx
// with _shards.failed > 0 and that type in _shards.failures ⇒ expired = true and PitExpired. preAttempt() aborts any
// attempt of an expired PIT with PitExpired (a cursor asleep in a backoff included) and every later next()/search()
// returns PitExpired without a request. A 2xx that arrives when the PIT is already expired is discarded: PitExpired,
// stale + 1. The library never recreates a PIT; the consumer restarts its whole query.
//
// LIFETIME AND DELETE. When the last handle (Pit or PitSession) goes, PitState's hand-over (PitState::handoff)
// gives {id, keepAlive, lastUse} to PitRegistry::release() without blocking, on any thread; a PitState whose registry
// is gone (runtime shut down) does nothing (keep_alive frees it). The registry sends DELETE /_search/point_in_time with
// {"pit_id": id} through the transport (choose() for the node, callback on the pool) and classifies with
// classifyRequest(r, 1): a 2xx whose `pits` entry for the id (or, when none names it, any entry) says
// `successful: false` ⇒ retried like a Failover (the context may still be open: not a confirmed delete); any other 2xx
// (a body without a readable `pits` included) or 404 ⇒ confirmed; Throttled ⇒ wait max(Retry-After, backoff);
// Failover/Retry ⇒ backoffDelay(DELETE_RETRY: 1 s, 15 s); no usable node ⇒ min(backoff, probeInterval) without counting
// a retry; any other final answer (another 4xx, a response too large) ⇒ given up at once (deletesExpired + 1):
// keep_alive frees the PIT. Until lastUse + keepAlive (saturated); past it ⇒ expired (deletesExpired + 1). Each
// DELETE's timeout is min(requestTimeout, lastUse + keepAlive − now). Confirmed or expired frees the slot. Retries run
// on a loop-0 timer; release() is idempotent per id.
//
// SHUTDOWN. RuntimeState::stopAndJoin calls drain(shutdownDeadline − min(DRAIN_STOP_MARGIN,
// (shutdownDeadline − now) / 2)) before transport->stop() (a short deadline still leaves half of it to the deletes):
// every pending delete is sent at once with timeout min(requestTimeout, drainEnd − now) and the call waits for them;
// at drainEnd the rest are cancelled and counted expired. PITs whose handles are still alive are deleted too (the
// registry keeps a weak_ptr to every open PitState, opened()): their id and lastUse are read at the drain, the state
// is marked `drained` so that its later hand-over gives nothing, and any later request on it returns Shutdown (the
// runtime is gone). A creation that ends after the drain started (opened() while draining) is marked drained the
// same way and its DELETE joins the drain while before drainEnd; after it, it is counted expired without a request.
//
// STATS (process-wide, never reset). open, reserved (lapsed reservations are purged on acquire() and on every
// stats read), deletesPending (gauge), created, deletesConfirmed, deletesExpired, deleteRetries, expired, stale,
// refusedFull. The metrics publish pit.open, pit.delete.pending, pit.delete.retries, pit.expired.

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "indexer_client/client.hpp"
#include "indexer_client/types.hpp"

namespace indexer_client::detail
{
    struct ClientState;
    class NodeSet;
    struct PitState;
    struct RuntimeState;
    class Transport;
} // namespace indexer_client::detail

namespace indexer_client::detail::query
{
    constexpr Duration DELETE_RETRY_BASE {Duration {1000}};
    constexpr Duration DELETE_RETRY_CAP {Duration {15000}};
    /// Room left between the end of the PIT drain and the shutdown deadline, for transport->stop() and the joins.
    constexpr Duration DRAIN_STOP_MARGIN {Duration {1000}};

    /// Text of the "no usable slot" refusal; the count is appended.
    constexpr const char* PIT_FULL = "too many open PITs";

    /// Bytes of a PIT id the log summary shows (an id is ~100+ bytes of base64; its head identifies it).
    constexpr std::size_t EXPIRED_ID_LOG_MAX = 16;

    struct PitStats final
    {
        std::uint64_t open {0};
        std::uint64_t reserved {0};
        std::uint64_t deletesPending {0};
        std::uint64_t created {0};
        std::uint64_t deletesConfirmed {0};
        std::uint64_t deletesExpired {0};
        std::uint64_t deleteRetries {0};
        std::uint64_t expired {0};
        std::uint64_t stale {0};
        std::uint64_t refusedFull {0};
    };

    /// One per runtime; created by RuntimeOwner::start after the transport, drained by stopAndJoin. Thread-safe.
    class PitRegistry
    {
    public:
        struct Pending final
        {
            std::string id;
            Duration keepAlive {Duration {0}};
            TimePoint lastUse;
        };

        virtual ~PitRegistry() = default;

        /// Takes one slot (open + reserved + acquired < maxOpenPits, lapsed reservations purged first); false ⇒
        /// refusedFull + 1 and `occupied` = open + reserved + acquired at the refusal.
        virtual bool acquire(std::uint64_t& occupied) = 0;
        /// Gives back a slot that never became a PIT.
        virtual void releaseSlot() = 0;
        /// Turns an acquired slot into a reservation until `until` (a creation of unknown result).
        virtual void reserve(TimePoint until) = 0;
        /// Marks an acquired slot as an open PIT (created + 1) and remembers it for the shutdown drain; while or after
        /// draining, deletes it in the drain or counts it expired (SHUTDOWN).
        virtual void opened(const std::weak_ptr<PitState>& pit) = 0;
        /// The last handle of an open PIT went: delete it. Never blocks; idempotent per id.
        virtual void release(Pending pit) = 0;
        /// An acquired slot whose creation answered with a PIT the library refused (a partial one): it becomes an open
        /// PIT (created + 1, it does exist) and is released at once, so it is deleted like any other. Never blocks.
        virtual void discard(Pending pit) = 0;
        /// Shutdown: sends and waits for the pending deletes until `drainEnd`, then cancels the rest.
        virtual void drain(TimePoint drainEnd) = 0;

        virtual PitStats stats() = 0;

        /// For the log summary (runtime/logSummary.hpp): the deletes given up (expired) since the previous call, with
        /// the first id truncated to EXPIRED_ID_LOG_MAX bytes, for the log summary's WARN.
        struct ExpiredDeletes final
        {
            std::uint64_t count {0};
            std::string firstId;
        };
        virtual ExpiredDeletes takeExpiredDeletes() = 0;
    };

    /// What the runtime lends its registry (RuntimeOwner::start). Transport and NodeSet are weak: the registry never
    /// keeps them alive. `after` runs `task` on loop 0 once `delay` has passed; false (task dropped) once the runtime
    /// stopped arming timers. The registry never calls it under its mutex.
    struct PitRegistryEnvironment final
    {
        std::uint32_t maxOpenPits {64};
        Duration requestTimeout {Duration {60000}};
        Duration probeInterval {Duration {10000}};
        std::weak_ptr<Transport> transport;
        std::weak_ptr<NodeSet> nodes;
        std::function<bool(Duration, std::function<void()>)> after;
    };

    /// `from + span`, TimePoint::max() when it would overflow (keepAlive has no upper bound).
    TimePoint addSaturated(TimePoint from, Duration span);

    /// The registry of pitRegistry.cpp; the newest one is the live one read by registryStats().
    std::shared_ptr<PitRegistry> makePitRegistry(PitRegistryEnvironment environment);

    /// The live registry's gauges (open, reserved, deletesPending; zeros without one) plus the process-wide counters
    /// of the registries (created, deletesConfirmed, deletesExpired, deleteRetries, refusedFull). pitStats() adds
    /// the PIT engine's expired and stale.
    PitStats registryStats();

    /// Process-wide counters of the running runtime's registry plus the ones of the PIT engine (expired, stale).
    PitStats pitStats();

    /// IQuery::pit() of a client whose runtime is alive.
    Outcome<Pit> createPit(const std::shared_ptr<ClientState>& client,
                           std::vector<std::string> indices,
                           PitOptions pitOptions,
                           const QueryOptions& options,
                           Deadline deadline);
} // namespace indexer_client::detail::query

#endif // _INDEXER_CLIENT_PIT_HPP
