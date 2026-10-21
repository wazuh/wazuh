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

#ifndef _INDEXER_CLIENT_QUERY_HPP
#define _INDEXER_CLIENT_QUERY_HPP

// Query engine (stage E4a, plan 18 I81-I88). NORMATIVE: this header is the contract of every IQuery operation; the
// implementation (query.cpp) and its tests follow it. Nothing here is public API.
//
// EXECUTION (I87). Every operation runs synchronously on the calling consumer thread; no runtime thread ever runs a
// query and no task is posted for it, so a query never blocks the IoLoops or the CPU pool.
//   1. onRuntimeThread() ⇒ Reentrancy (RF-27), before anything else.
//   2. Validation, without a request ⇒ InvalidArgument with the field first in `reason`: every index non-empty,
//      only [A-Za-z0-9_.*-] (v1 isSafeIndexName), not only dots (libcurl collapses "." and "..") and not starting
//      with '_'; a non-empty index list; retry as validateBucket (base > 0, cap >= base, jitter in [0, 1], maxAttempts
//      and maxDuration > 0 or unset), pageDeadline > 0; searchAfter: body.sort a non-empty array, body.size an integer
//      > 0 and `page` callable.
//   3. The client gone (closeRequested) ⇒ ClientClosed; its runtime gone or another epoch ⇒ Shutdown.
//
// CLOCKS. `deadline` bounds the whole call; `pageDeadline` bounds each page (one search, one DBQ...) from its first
// attempt (the clock starts when that attempt is built: a "no node" wait before it counts only against `deadline`),
// waits included; each attempt's HTTP timeout is min(RuntimeConfig.requestTimeout, what is left of the page). The
// consumer's deadline is NEVER an HTTP timeout: when the deadline or the page expires with an attempt in flight, the
// engine calls transport->cancel(id) (Cancelled is never node-attributable) and returns Unavailable with reason
// "deadline expired, last cause: ..." (or "page deadline expired, ..."). A Timeout reaches NodeSet::report (⇒ Down,
// failover) only when the attempt had the whole per-attempt budget min(requestTimeout, pageDeadline) — always the
// page's first attempt, whose result wait runs TIMEOUT_GRACE past the page (never past `deadline`) so curl's Timeout
// wins that race; a later attempt whose budget the page cut short ⇒ Unavailable "page deadline expired".
//
// ONE ATTEMPT. runtimeTransport(runtime, epoch) and runtimeNodeSet(runtime, epoch) (null ⇒ Shutdown; neither is held
// past the attempt) → NodeSet::choose() → Transport::submit(HttpRequest{url = host + route, timeout}) → wait for the
// result on the client's QueryGate (the transport callback captures the attempt state by shared_ptr: it may land
// after the engine returned) → NodeSet::report(node, result) → classifyRequest(result, 1) and the operation's
// classifier (queryResponse.hpp). No node to choose ⇒ wait max(50 ms, min(retry.base, probeInterval)) and choose
// again, without an attempt.
//
// VERDICTS (I82, the I65 table). Failover ⇒ another attempt at once (counted only with mayHaveSent). Throttled ⇒ wait
// max(retryAfter, backoffDelay(retry, ++throttles)) without an attempt: `throttles` grows the exponent so a 429 storm
// without Retry-After backs off. Retry (408, 5xx, 401, 403, TlsConfig, LocalError, timed_out) ⇒ an attempt and
// backoffDelay(retry, attempts) (runtime/backoff.hpp, I66). maxAttempts or maxDuration (from the page's first
// attempt) exhausted ⇒ Failed(RetryExhausted), the last cause in reason. FailBatch ⇒ its cause. Conflict (DBQ/UBQ,
// I86) ⇒ its own budget: CONFLICT_ATTEMPTS attempts, CONFLICT_BASE doubled up to CONFLICT_CAP, exhausted ⇒
// VersionConflict with the counts in reason; each conflict retry opens a fresh I82 series (independent clocks).
//
// WAKE-UP. Every wait (result, backoff, no node) sleeps on the client's QueryGate (runtimeInternal.hpp): one mutex and
// condition variable shared by the runtime and all its clients. The transport callback, Client::requestClose() and
// RuntimeState::stopAndJoin() (before writePath->stop(); it also sets `stopping`) notify it. Woken by a close: cancel
// the attempt in flight and return ClientClosed (Shutdown when the gate is stopping). No busy wait (RNF-4).
//
// RESPONSES (I84). A 2xx body with body.size() * QUERY_DOM_FACTOR > maxResponseBytes ⇒ Failed(ItemPermanent)
// "response too large for a query" without parsing (the effective wire cap of a query is maxResponseBytes /
// QUERY_DOM_FACTOR); an unparsable 2xx body ⇒ Failed(ItemPermanent). A 4xx reason = the OpenSearch error type and at
// most REASON_BODY_BYTES of the body, within OpResult::MAX_REASON.
//
// ROUTES (I88). QueryOptions.expandWildcardsAll adds expand_wildcards=all to every one of them.
//   search(i, body)       POST /<i>/_search; the whole response. 404 index_not_found_exception ⇒ NotFound (I85);
//                         any other 404 ⇒ Client4xx.
//   searchAfter(i, b, f)  pages of search; f(response) on the consumer thread for every page, the empty one included
//                         (an exception from f propagates, no request pending); stops with f = false (⇒ Ok), no hits,
//                         hits < size, or a last hit without `sort`; advances with search_after = the last hit's sort.
//   deleteByQuery(is, q)  POST /<i1,i2>/_delete_by_query[?conflicts=proceed]; body q. 404 index_not_found_exception ⇒
//                         Ok({}); any other 404 ⇒ Client4xx.
//   updateByQuery(is, q)  POST /<i1,i2>/_update_by_query?conflicts=proceed; body q. 404 index_not_found ⇒ NotFound.
//   indexExists(i)        HEAD /<i>; 200 ⇒ true, 404 ⇒ false, the rest by I82 (I83). Never false on an outage.
//   pit(...)              Unavailable "PIT not implemented yet (E4b)".
//
// STATS. queryStats() counts requests, failovers, throttles, Unavailable results, responses the classifier refused
// for size (QueryResponse::tooLarge) and conflict retries: process-wide since process start, never reset (they survive
// shutdown() + start()); E5 publishes them and decides whether they reset per runtime (D48/D50).
//
// E4b (D51). (1) PIT reuses execute(), RouteSpec and Classifier, today in query.cpp's anonymous namespace: move them
// to a header. target("", route, params) already omits the index segment (POST /_search, DELETE
// /_search/point_in_time). (2) The classifier only sees a 2xx or a 404: the PIT classifier must intercept the 404
// search_context_missing_exception of an expired PIT ⇒ PitExpired (otherwise it is Fail Client4xx). (3) A DELETE with
// a body (PIT delete): verify that curlLoop.cpp sends CUSTOMREQUEST DELETE together with POSTFIELDS.

#include <chrono>
#include <cstdint>
#include <memory>

#include "indexer_client/client.hpp"
#include "indexer_client/types.hpp"

namespace indexer_client::detail
{
    struct ClientState;
} // namespace indexer_client::detail

namespace indexer_client::detail::query
{
    /// Upper bound of nlohmann DOM bytes per response byte, measured by QueryDomFactorMeasured (≥ 3 compact shapes,
    /// ceil(max × 1.25)). Measured (glibc heap in use, chunk headers included): ISS checksum page 6.19, VD packages
    /// page 5.74, DBQ 3.5-5.2, UBQ 3.5-5.2 ⇒ ceil(6.19 × 1.25) = 8.
    constexpr std::uint64_t QUERY_DOM_FACTOR = 8;

    /// I86: the v1 conflict budget of DBQ/UBQ (SYNC:430-457).
    constexpr std::uint32_t CONFLICT_ATTEMPTS = 3;
    constexpr Duration CONFLICT_BASE {Duration {3000}};
    constexpr Duration CONFLICT_CAP {Duration {15000}};

    /// How long past the page an attempt with the whole budget waits for curl's own Timeout (so it reaches
    /// NodeSet::report); never past the consumer's deadline.
    constexpr Duration TIMEOUT_GRACE {Duration {1000}};

    /// Floor of the "no usable node" wait.
    constexpr Duration NO_NODE_WAIT_FLOOR {Duration {50}};

    /// Body bytes quoted in a 4xx reason.
    constexpr std::size_t REASON_BODY_BYTES = 256;

    /// Text of the E4a pit() answer (the verificar.sh stub grep looks for it).
    constexpr const char* PIT_NOT_YET = "PIT not implemented yet (E4b)";

    struct QueryStats final
    {
        std::uint64_t requests {0};
        std::uint64_t failovers {0};
        std::uint64_t throttles {0};
        std::uint64_t unavailable {0};
        std::uint64_t tooLarge {0};
        std::uint64_t conflictRetries {0};
    };

    /// The real IQuery of a client whose runtime is alive.
    std::shared_ptr<IQuery> makeQuery(std::shared_ptr<ClientState> client);

    /// Process-wide counters (zeros before the first query; never reset).
    QueryStats queryStats();
} // namespace indexer_client::detail::query

#endif // _INDEXER_CLIENT_QUERY_HPP
