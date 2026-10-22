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

#ifndef _INDEXER_CLIENT_LOG_SUMMARY_HPP
#define _INDEXER_CLIENT_LOG_SUMMARY_HPP

// Edge-triggered and summarized logging (stage E5c, plan 18 I102/I104, RF-16, CA-16). NORMATIVE.
//
// EMISSION. Every line is decided under the mutex that owns its state and emitted after that mutex is dropped (the
// NodeSet's `pending.lines` pattern, health/nodeSet.cpp): the process log function has its own lock and does I/O. No
// line is ever emitted under a bucket mutex or inside GlobalBudget::tryReserve. The quota-edge lines are written by the
// submitting thread that crossed the edge, once per crossing, when it leaves Bucket::reserve()/reserveForGroup(),
// with no mutex held; the summary's timer drains whatever is still pending (e.g. what a Block left behind).
//
// AMBIGUOUS EDGE (E6a, plan 18 I105/I105b). One more edge, per bucket: the first Failed(Ambiguous) after a 2xx _bulk of
// the bucket (or since its creation) ⇒ WARN; the next 2xx _bulk re-arms it (Bucket::countBulk). Unlike the quota edges
// it is NOT written by a submitting thread: the completion thread of the _bulk decides it under the bucket mutex
// (Bucket::countAmbiguous) and writes it once that mutex is dropped (EmitPendingOnExit), like every other line.
//
// QUOTA EDGES, per bucket and for the global cap. Two edges, each logged once until re-armed:
//   80 %    the charge crosses 0.8 x quota upwards ⇒ WARN.
//   full    the first admission refused by THAT quota and resolved by overflow (QueueFull refusal, DropNewest, a
//           DropOldest eviction or a Block that has to wait) ⇒ WARN. A refusal of the global cap fires the global
//           edge only, never the bucket's (Bucket::tryChargeLocked says which cap refused).
//   Both re-arm when the charge crosses 70 % DOWNWARDS (an edge, not a level: a QueueFull storm at a low charge logs a
//   single WARN). Bucket edges are decided under the bucket mutex (two integer compares per reserve/release); for the
//   global cap the flags are atomics and the thread whose CAS or refusal crossed the threshold claims the line with an
//   exchange, so a crossing logs exactly once under concurrency.
//
// PERIODIC SUMMARY. A loop-0 timer (LoopTimers' pattern, weak captures) every RuntimeConfig::logSummaryInterval:
//   - per bucket with activity in the interval: ONE WARN listing up to K = 8 keys (cause, itemErrorType) with their
//     counts plus `other` for the rest (first-come; counted in Bucket::countResolved under the bucket mutex, swapped
//     out by the timer), and ONE INFO with the interval's totals (accepted, ok, failed, dropped). No reason, document,
//     id or URL at INFO or above; one sample reason per bucket and interval goes to DEBUG, truncated to 256 bytes.
//     The interval's length is printed in whole seconds, rounded up, never below 1.
//   - per client: the delta of callbackOverruns and the maximum duration of the interval (WARN), through the weak
//     client registry of RuntimeState (written by RuntimeRef::client(), erased by releaseClientName). The body keeps
//     no client reference while it emits.
//   - a WARN when a PIT delete expired (given up) in the interval, with the id truncated.
// The summary body has its own mutex (the timer's handler and the final summary may overlap). stopAndJoin disarms the
// summary and stops its timer BEFORE writePath->stop(), and emits the last summary synchronously AFTER
// writePath->stop() and the PIT drain, so the shutdown sweep's Dropped(Shutdown) and the deletes the drain gives up
// are in it. Limiter changes stay at DEBUG.
//
// TEST SEAM. detail::testing::flushLogSummary() runs the summary body now on loop 0 and returns when it is done; false
// (without waiting) once the runtime stopped accepting work.

#include <chrono>
#include <cstddef>
#include <memory>

namespace indexer_client::detail
{
    struct RuntimeState;
} // namespace indexer_client::detail

namespace indexer_client::detail::logging
{
    /// Keys (cause, itemErrorType) tracked per bucket and interval before `other` (CA-16).
    constexpr std::size_t SUMMARY_KEYS = 8;
    /// Bytes of the sample reason logged at DEBUG.
    constexpr std::size_t SAMPLE_REASON_MAX = 256;

    class LogSummary
    {
    public:
        virtual ~LogSummary() = default;
        /// Arms the timer (RuntimeOwner::start, after the write path, the NodeSet and the PIT registry).
        virtual void start() = 0;
        /// Emits the summary of the current interval now (the timer's body and the test seam's).
        virtual void flush() = 0;
        /// Disarms the timer: no re-arm afterwards; idempotent (stopAndJoin, before summaryTimers and writePath stop).
        virtual void stop() = 0;
        /// The last summary, synchronous, once (stopAndJoin, after writePath->stop() and the PIT drain).
        virtual void finish() = 0;
    };

    std::shared_ptr<LogSummary> makeLogSummary(const std::weak_ptr<RuntimeState>& runtime);
} // namespace indexer_client::detail::logging

#endif // _INDEXER_CLIENT_LOG_SUMMARY_HPP
