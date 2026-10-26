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

#ifndef _INDEXER_CLIENT_SEAMS_HPP
#define _INDEXER_CLIENT_SEAMS_HPP

// Test seams (I45b). In the production objects (the .so) every seam is an empty inline function and nothing of the
// test machinery is compiled; with INDEXER_CLIENT_TESTING (the static library the component suite links) they call
// the hooks of src/testing/seams.cpp. VisibilityTest checks that the .so carries none of them.

#include <cstddef>
#include <cstdint>
#include <optional>

#include <sys/types.h>

namespace indexer_client::detail::seams
{
#ifdef INDEXER_CLIENT_TESTING
    void afterAdmissionCheck();   ///< Between the admission check and the post.
    int injectMultiError(int rc); ///< Replaces curl_multi_socket_action's result.
    void throwOnAdd();            ///< Before curl_multi_add_handle.
    void beforeRetryAfterParse(); ///< On the CPU pool, before parsing Retry-After.
    void onTimerHandler(std::uint64_t generation, std::uint64_t current); ///< Every timer handler run.
    std::optional<int> openSocket();                                      ///< CURL_SOCKET_BAD forces a connect failure.
    void onRuntimeThreadStart(pid_t tid);                                 ///< Each runtime thread, at start.
    void onPostRejected();                                                ///< A post refused by a closed loop.
    /// E3b-2: true makes the bulk sender treat its Transport::submit as refused (InvalidState) without submitting.
    bool refuseSubmit();
    /// G-diff E3b-2: in a bulk completion, after the slot was released (may throw: the completion's fallback).
    void beforeCompletion();
    /// G-diff E3b-2: in the bulk sender's NodeSet hook, before it refreshes the Down mirror (may block: mirror lag).
    void beforeSenderMirror();
    /// E3c-2: in the bulk sender's pool task, before it drops the cancelled ops and assembles the body.
    void beforeAssembly();
    /// E4a: replaces the DBQ/UBQ conflict-retry base (I86) in milliseconds; nullopt keeps CONFLICT_BASE.
    std::optional<std::int64_t> queryConflictBaseMs();
    /// G-diff E5b: in CallbackCompletion::run, under completionsMutex, between the cutoff comparison and the started
    /// (or skipped) mark (may block: it holds the client's completionsMutex).
    void inCallbackGate();
    /// G-diff E5b: in WritePath::resolve, right after the op's payload was released (it is no longer retained).
    void afterPayloadReleased();
    /// E6e (A): in WritePath::resolveBulk, before each chunk is settled (may throw: the claimed ops are settled all the
    /// same).
    void midBulkSettle();
    /// E6e (B): in Bucket::stage, after the relaxed check of `closing` and before the stripe's mutex (may block).
    void beforeStagePush();
    /// E6e (D116): in Bucket::stage, after a stripe's empty -> non-empty transition stored `oldest` and before the load
    /// of the armed deadline, with the stripe's mutex held (may block; must not need that stripe).
    void beforeArmedDueLoad();
    /// E6e (D116): on loop 0, in the scheduler's armTimer, after the bucket's nextDue was read and before the deadline
    /// armed for it is published (may block loop 0).
    void beforePublishArmedDue();
    /// E6e (B): in the stripe flush (Bucket::flushStripeLocked; the seam and its tests keep the plan's first name,
    /// admitBatch), before each op is admitted and once more before a DropNewest drop's
    /// interval keys are counted (after its counters moved), with the stripe's and the bucket's mutex held (may throw;
    /// must not block on the bucket).
    void midAdmitBatch();
    /// E6e (A): in Bucket::settleBulk, before each op is counted, with the bucket's mutex held (may throw: the ops
    /// settled so far are released and the rest go back to resolveBulk's settlement; must not block on the bucket).
    void inSettleBulk();
    /// E6e (B): K, the stripes of a staging bucket, fixed by INDEXER_CLIENT_TEST_STRIPES (an integer 1-64, read once;
    /// anything else aborts the run); nullopt when unset or empty (the library's K).
    std::optional<std::size_t> stripeCount();
#else
    // always_inline: even at -O0 no out-of-line copy is emitted, so the .so carries no seams:: symbol (VisibilityTest).
    [[gnu::always_inline]] inline void afterAdmissionCheck() {}
    [[gnu::always_inline]] inline int injectMultiError(int rc)
    {
        return rc;
    }
    [[gnu::always_inline]] inline void throwOnAdd() {}
    [[gnu::always_inline]] inline void beforeRetryAfterParse() {}
    [[gnu::always_inline]] inline void onTimerHandler(std::uint64_t, std::uint64_t) {}
    [[gnu::always_inline]] inline std::optional<int> openSocket()
    {
        return std::nullopt;
    }
    [[gnu::always_inline]] inline void onRuntimeThreadStart(pid_t) {}
    [[gnu::always_inline]] inline void onPostRejected() {}
    [[gnu::always_inline]] inline bool refuseSubmit()
    {
        return false;
    }
    [[gnu::always_inline]] inline void beforeCompletion() {}
    [[gnu::always_inline]] inline void beforeSenderMirror() {}
    [[gnu::always_inline]] inline void beforeAssembly() {}
    [[gnu::always_inline]] inline std::optional<std::int64_t> queryConflictBaseMs()
    {
        return std::nullopt;
    }
    [[gnu::always_inline]] inline void inCallbackGate() {}
    [[gnu::always_inline]] inline void afterPayloadReleased() {}
    [[gnu::always_inline]] inline void midBulkSettle() {}
    [[gnu::always_inline]] inline void beforeStagePush() {}
    [[gnu::always_inline]] inline void beforeArmedDueLoad() {}
    [[gnu::always_inline]] inline void beforePublishArmedDue() {}
    [[gnu::always_inline]] inline void midAdmitBatch() {}
    [[gnu::always_inline]] inline void inSettleBulk() {}
    [[gnu::always_inline]] inline std::optional<std::size_t> stripeCount()
    {
        return std::nullopt;
    }
#endif
} // namespace indexer_client::detail::seams

#endif // _INDEXER_CLIENT_SEAMS_HPP
