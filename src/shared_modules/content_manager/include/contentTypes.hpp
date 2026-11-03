/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _CONTENT_TYPES_HPP
#define _CONTENT_TYPES_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <json.hpp>
#include <string>
#include <string_view>

/**
 * @file contentTypes.hpp
 * @brief The value types of the content-delivery contract.
 *
 * This header depends on nlohmann's json and the standard library only, and compiles under
 * `-std=c++17` although the library is built as C++20: it is included by hosts on the other side of
 * the `.so` boundary, the Engine among them. The `content_manager_public_abi_c17` target enforces
 * both properties.
 */
namespace content_manager
{

    /**
     * @brief What kind of content delivery a cycle is about to perform.
     */
    enum class SessionKind : std::uint8_t
    {
        FullReload,  ///< Everything the source holds; the sink should replace its content wholesale.
        Incremental, ///< Only what changed since the stored token.
        NoChange     ///< The remote token matches the local one; no document will be delivered.
    };

    /**
     * @brief Everything the sink needs to decide whether, and how, to accept this cycle.
     */
    struct SessionInfo
    {
        std::string topic;                          ///< Registered topic name.
        SessionKind kind {SessionKind::FullReload}; ///< Delivery shape for this cycle.
        std::string remoteToken;                    ///< Token probed from the source ("" in cursor mode).
        nlohmann::json probeMetadata;               ///< Detector extras, e.g. `{"enabled": false}`. Always an object.
    };

    /**
     * @brief The sink's answer to `beginSession`.
     */
    enum class SessionDecision : std::uint8_t
    {
        Proceed, ///< Ready to receive pages.
        Skip,    ///< Declines this cycle. NOT an error: the token is left untouched.
        Abort    ///< The sink is unusable right now. Transient failure; the token is left untouched.
    };

    /**
     * @brief One page of raw source documents.
     *
     * `hits` points into storage owned by the paginator and is only valid for the duration of the
     * `acceptPage` call: a sink that needs the data past that must copy it.
     */
    struct ContentPage
    {
        std::string_view topic;               ///< Registered topic name.
        const nlohmann::json* hits {nullptr}; ///< Raw hit array (`_id`, `_index`, `_source`, `sort`).
        std::string pageToken;                ///< Highest page token in this page ("" when not tokenised).
    };

    /**
     * @brief How far the sink got with a page.
     */
    enum class PageStatus : std::uint8_t
    {
        Accepted, ///< Buffered. NOT yet durable: a crash loses it.
        Durable,  ///< Everything up to `ContentPage::pageToken` is on stable storage.
        Reject    ///< Unrecoverable for this session; the fetch aborts immediately.
    };

    /**
     * @brief Result of one `acceptPage` call.
     */
    struct PageAck
    {
        PageStatus status {PageStatus::Accepted}; ///< Outcome for this page.
        std::string detail;                       ///< Human-readable reason, used for logging on Reject.
    };

    /**
     * @brief Summary handed to the sink when every page has been delivered.
     */
    struct CommitInfo
    {
        std::string topic;                          ///< Registered topic name.
        SessionKind kind {SessionKind::FullReload}; ///< Delivery shape this cycle used.
        std::string finalToken;                     ///< Token to persist if the commit succeeds.
        std::size_t documentsDelivered {0};         ///< Documents handed to `acceptPage` this cycle.
    };

    /**
     * @brief Whether the sink promoted the content, and what should happen to the token.
     */
    enum class CommitStatus : std::uint8_t
    {
        Committed,         ///< Promoted and durable. `CommitInfo::finalToken` is persisted.
        RejectedRetryFull, ///< The content is invalid: the token is cleared, forcing a full reload next cycle.
        RejectedRetrySame  ///< Transient failure: the token is kept, the same cycle is retried later.
    };

    /**
     * @brief Result of one `commit` call.
     */
    struct CommitResult
    {
        CommitStatus status {CommitStatus::Committed}; ///< Outcome of the promotion.
        std::string detail;                            ///< Human-readable reason, used for logging on rejection.
    };

    /**
     * @brief Why a session was abandoned before commit.
     */
    enum class AbortReason : std::uint8_t
    {
        StopRequested,   ///< The host asked the registration to stop.
        FetchError,      ///< The source could not be read to completion.
        SinkRejectedPage ///< The sink answered `PageStatus::Reject`.
    };

    /**
     * @brief The terminal state of one cycle.
     */
    enum class CycleStatus : std::uint8_t
    {
        Updated,                  ///< Content changed and was committed.
        Unchanged,                ///< Nothing to do: the source token matches the stored one.
        SkippedConsumerNotReady,  ///< The source's consumer is not in a queryable state.
        SkippedPreconditionUnmet, ///< A configured precondition (e.g. required documents) is not satisfied.
        SkippedStopRequested,     ///< A stop was requested before or during the cycle.
        SkippedAlreadyRunning,    ///< A cycle for this topic was already in progress; this one did not run.
        FailedTransport,          ///< The source could not be reached or answered an error.
        FailedSink,               ///< The sink rejected a page, aborted, or its token could not be stored.
        FailedConfig              ///< The registration does not match the live data (e.g. an ambiguous probe).
    };

    /**
     * @brief What one cycle did, and when the driver should come back.
     */
    struct CycleOutcome
    {
        CycleStatus status {CycleStatus::Unchanged}; ///< Terminal state of the cycle.
        std::size_t documentsDelivered {0};          ///< Documents handed to the sink.
        std::string token;                           ///< Token in force after the cycle ("" when none).
        std::string detail;                          ///< Human-readable summary, safe to log.

        /**
         * @brief How long the driver should wait before the next attempt.
         *
         * Zero means "use the configured interval". A deferral or a transport or sink failure carries a
         * short backoff instead, so a topic whose consumer is briefly busy is not postponed by a whole
         * scheduler period.
         */
        std::chrono::seconds retryAfter {0};
    };

    /**
     * @brief What the caller wants from one cycle.
     */
    struct RunRequest
    {
        /// Fetch everything, whatever the stored token says. The token is cleared once the sink has
        /// accepted the full session, so a crash mid-reload starts over instead of resuming.
        bool forceFullReload {false};
    };

    /**
     * @brief How a requested cycle ended, in the terms a request handler answers with.
     */
    enum class OnDemandCode : std::uint8_t
    {
        Completed,      ///< The cycle ran: the content is up to date (`Updated` or `Unchanged`).
        Deferred,       ///< The cycle could not proceed yet (consumer busy, required documents missing). Retryable.
        AlreadyRunning, ///< A cycle for this topic was running or already requested; this one was not queued.
        ShuttingDown,   ///< The topic is stopping. Retryable once it is back.
        Failed          ///< The cycle ran and failed, or the topic is not driven by the library.
    };

    /**
     * @brief Result of `ContentRegister::requestRun`.
     */
    struct OnDemandResult
    {
        OnDemandCode code {OnDemandCode::Completed}; ///< Outcome class.
        std::string detail;                          ///< Human-readable context, safe to log or return.
        CycleOutcome outcome;                        ///< The cycle's own outcome, when one ran.
    };

} // namespace content_manager

#endif // _CONTENT_TYPES_HPP
