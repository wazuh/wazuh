/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
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
 * This header is deliberately poor in dependencies: nlohmann's json plus the standard library,
 * nothing else. It is included by hosts that live on the other side of the `.so` boundary (the
 * Engine links `wazuh-engine` with `-static-libstdc++` while `content_manager.so` links libstdc++
 * dynamically), so it must not drag in `loggerHelper.h`, rocksdb or the UDS transport, and it must
 * compile under `-std=c++17` even though the library itself is built as C++20. The
 * `content_manager_public_abi_c17` CI target enforces both properties.
 *
 * Nothing here throws and nothing here owns a resource: every type is a plain aggregate of
 * layout-stable members, so passing one across the DSO boundary by value is defined.
 */
namespace content_manager
{

/**
 * @brief Version of the delivery contract this header describes.
 *
 * Checked by `ContentRegister`'s constructor against the value compiled into the `.so`. A host
 * built against an older header is refused at registration instead of being allowed to misread a
 * struct whose layout moved.
 */
constexpr std::uint32_t CONTRACT_ABI_VERSION = 2;

/**
 * @brief What kind of content delivery a cycle is about to perform.
 */
enum class SessionKind : std::uint8_t
{
    FullReload,  ///< Everything the source holds; the sink should replace its content wholesale.
    Incremental, ///< Only what changed since `SessionInfo::localToken`.
    NoChange     ///< The remote token matches the local one; no document will be delivered.
};

/**
 * @brief Everything the sink needs to decide whether, and how, to accept this cycle.
 */
struct SessionInfo
{
    std::string topic;                   ///< Registered topic name.
    SessionKind kind {SessionKind::FullReload}; ///< Delivery shape for this cycle.
    std::string localToken;              ///< Token from the previous successful commit ("" on first run).
    std::string remoteToken;             ///< Token probed from the source ("" in cursor mode).
    nlohmann::json probeMetadata;        ///< Detector extras, e.g. `{"enabled": false}`.
    bool onDemand {false};               ///< True when the cycle was triggered by an on-demand request.
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
    std::string_view topic;                ///< Registered topic name.
    const nlohmann::json* hits {nullptr};  ///< Raw hit array (`_id`, `_index`, `_source`, `sort`).
    std::string pageToken;                 ///< Highest page token in this page ("" when not tokenised).
    std::size_t sliceId {0};               ///< Slice that produced the page (0 when unsliced).
    std::size_t pageIndex {0};             ///< 0-based page counter within the slice.
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
    bool changed {false};                       ///< True when at least one document was delivered.
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
    StopRequested,      ///< The host asked the registration to stop.
    FetchError,         ///< The source could not be read to completion.
    SinkRejectedPage,   ///< The sink answered `PageStatus::Reject`.
    TokenPersistFailed  ///< The content was committed but the token could not be written.
};

/**
 * @brief The terminal state of one `runOnce`.
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
    FailedConfig              ///< The registration's configuration is invalid.
};

/**
 * @brief What one `runOnce` did, and when the driver should come back.
 */
struct CycleOutcome
{
    CycleStatus status {CycleStatus::Unchanged}; ///< Terminal state of the cycle.
    std::size_t documentsDelivered {0};          ///< Documents handed to the sink.
    std::string token;                           ///< Token in force after the cycle.
    std::string detail;                          ///< Human-readable summary, safe to log.

    /**
     * @brief How long the driver should wait before the next attempt.
     *
     * Zero means "use the configured interval". Every `Skipped*`/`Failed*` status carries a short
     * backoff instead, so a deferred cycle is not postponed by a full scheduler period — with VD's
     * 60-minute default interval that difference is the whole feed.
     */
    std::chrono::seconds retryAfter {0};
};

/**
 * @brief What the caller wants from one `runOnce`.
 */
struct RunRequest
{
    bool forceFullReload {false}; ///< Clear the token before probing, forcing a `FullReload` session.
    bool onDemand {false};        ///< Mark the resulting `SessionInfo` as on-demand.
};

} // namespace content_manager

#endif // _CONTENT_TYPES_HPP
