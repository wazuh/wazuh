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

#ifndef _CONTENT_CYCLE_HPP
#define _CONTENT_CYCLE_HPP

#include "changeDetector.hpp"
#include "consumerGate.hpp"
#include "contentIndexer.hpp"
#include "contentSink.hpp"
#include "contentTokenStore.hpp"
#include "contentTypes.hpp"
#include "loggerHelper.h"
#include "pitPaginator.hpp"
#include "pitSession.hpp"
#include "sharedDefs.hpp"
#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

/**
 * @brief One content cycle: probe, fetch, deliver, promote, persist. Exactly once.
 *
 * Every gate is single-pass and every non-terminal outcome carries a `retryAfter` for the driver to
 * honour, so a cycle never parks its thread and is safe to run on a shared scheduler worker.
 *
 * ### Who writes the token
 *
 * Exactly four paths, and no others:
 *  - `RunRequest::forceFullReload` clears it once the sink has accepted the full session, before the
 *    first page: if the process dies mid-reload, the next boot starts over instead of resuming from
 *    a cursor whose content was already partially overwritten. A forced cycle that a gate stops
 *    leaves the token as it was;
 *  - a `Durable` page acknowledgement stores that page's token immediately;
 *  - `CommitStatus::Committed` stores the final token;
 *  - `CommitStatus::RejectedRetryFull` clears it.
 *
 * `Skip`, `Abort`, `RejectedRetrySame`, interruption and transport errors all leave it untouched.
 *
 * ### Exception containment
 *
 * `run` is `noexcept` and everything that can throw — the indexer, the PIT session's constructor,
 * the detectors — is called inside its `try`. The sink may live in a DSO with its own libstdc++, and
 * an exception unwinding across that boundary is undefined, so sink calls get a second `catch (...)`
 * of their own, on this side of the boundary.
 */
class ContentCycle final
{
public:
    /// Everything about a topic that does not change between cycles.
    struct Config
    {
        std::string topic;                               ///< Registered topic name.
        PitSession::Config pit;                          ///< Indices and consumer document to snapshot.
        FetchSpec fetchTemplate;                         ///< Sort, source filter, page size. Query is per-cycle.
        std::size_t fullSlices {1};                      ///< Slices to use on a full fetch.
        std::vector<std::string> requiredDocumentIds;    ///< Documents that must exist before a full load.
        std::chrono::seconds consumerRetryInterval {60}; ///< Backoff when the consumer is not ready.
        std::chrono::seconds consumerCacheTtl {5};       ///< Pre-flight probe cache lifetime.
    };

    /**
     * @brief Assemble a cycle.
     *
     * @param config Static per-topic configuration.
     * @param port Indexer access, owned for the lifetime of the registration.
     * @param detector How this topic decides its content moved.
     * @param sink Where the content goes.
     * @param tokenStore Where the token lives. May be null: the topic is then tokenless and every
     *                   cycle is a full reload.
     * @param stop Cooperative stop flag owned by the driver; must outlive the cycle.
     */
    ContentCycle(Config config,
                 std::shared_ptr<content_manager::IContentIndexer> port,
                 std::unique_ptr<IChangeDetector> detector,
                 std::shared_ptr<content_manager::IContentSink> sink,
                 std::shared_ptr<content_manager::IContentTokenStore> tokenStore,
                 const std::atomic<bool>& stop)
        : m_config {std::move(config)}
        , m_port {std::move(port)}
        , m_detector {std::move(detector)}
        , m_sink {std::move(sink)}
        , m_tokenStore {std::move(tokenStore)}
        , m_stop {stop}
    {
    }

    /**
     * @brief Run the cycle.
     *
     * @param request What the caller wants from it.
     * @return What happened, and when to come back. Never throws.
     */
    content_manager::CycleOutcome run(const content_manager::RunRequest& request) noexcept
    {
        using content_manager::CycleStatus;

        try
        {
            if (m_stop.load())
            {
                return make(CycleStatus::SkippedStopRequested, "stop requested before the cycle started");
            }

            // Cost gate: cheap, non-PIT, and cached across topics watching the same consumer. Its
            // job is only to avoid paying for a PIT over a multi-gigabyte index when the indexer is
            // visibly mid-update; the authoritative check happens inside the snapshot below.
            const auto preflight = ConsumerGate::probe(
                *m_port, m_config.pit.consumerStatusIndex, m_config.pit.consumerStatusId, m_config.consumerCacheTtl);
            if (preflight.status == ConsumerGate::Status::Unreachable)
            {
                return make(CycleStatus::FailedTransport, "indexer unreachable: " + preflight.error);
            }
            if (preflight.status != ConsumerGate::Status::Ready)
            {
                return make(CycleStatus::SkippedConsumerNotReady,
                            std::string {"pre-flight consumer status: "} + ConsumerGate::describe(preflight.status));
            }

            PitSession session {*m_port, m_config.pit};
            return runInSession(session, request);
        }
        catch (const std::exception& e)
        {
            return make(CycleStatus::FailedTransport, e.what());
        }
        catch (...)
        {
            return make(CycleStatus::FailedTransport, "unknown error");
        }
    }

private:
    content_manager::CycleOutcome runInSession(PitSession& session, const content_manager::RunRequest& request)
    {
        using namespace content_manager;

        // Correctness gate. Unlike the pre-flight it reads the consumer document from inside the
        // very snapshot the content will be read from, so a consumer that starts rewriting between
        // the two cannot be missed.
        const auto consumer = session.validateConsumerReady();
        if (consumer.status != ConsumerGate::Status::Ready)
        {
            return make(CycleStatus::SkippedConsumerNotReady,
                        std::string {"in-PIT consumer status: "} + ConsumerGate::describe(consumer.status));
        }

        const auto localToken = request.forceFullReload ? std::string {} : loadToken();
        const auto probe = m_detector->probe(session, *m_port);

        // A probe that cannot identify the remote state unambiguously is a configuration fault, not
        // a transient one: the driver must not retry it as if it were.
        if (!probe.configError.empty())
        {
            logError(WM_CONTENTUPDATER,
                     "Content update for '%s' cannot run: %s",
                     m_config.topic.c_str(),
                     probe.configError.c_str());
            return make(CycleStatus::FailedConfig, probe.configError);
        }

        const auto plan = m_detector->plan(probe, localToken);

        // Checked on a full plan only. An incremental run means a previous cycle committed, so the
        // required documents were present then; if they have since gone, the sink's own validation
        // rejects the commit with RetryFull, and the next cycle — a full one — is checked here.
        if (plan.mode == FetchPlan::Mode::Full && !m_config.requiredDocumentIds.empty())
        {
            const auto found = session.countDocuments(m_config.requiredDocumentIds);
            if (found < m_config.requiredDocumentIds.size())
            {
                return make(CycleStatus::SkippedPreconditionUnmet,
                            "required documents not indexed yet (" + std::to_string(found) + "/" +
                                std::to_string(m_config.requiredDocumentIds.size()) + ")");
            }
        }

        SessionInfo info;
        info.topic = m_config.topic;
        info.kind = toKind(plan.mode);
        info.remoteToken = probe.remoteToken;
        info.probeMetadata = probe.metadata.is_object() ? probe.metadata : nlohmann::json::object();

        const auto decision = beginSession(info);
        if (decision == SessionDecision::Skip)
        {
            return make(CycleStatus::Unchanged, "sink declined this cycle");
        }
        if (decision == SessionDecision::Abort)
        {
            return make(CycleStatus::FailedSink, "sink is not accepting content right now");
        }

        if (request.forceFullReload && plan.mode == FetchPlan::Mode::Full && m_tokenStore)
        {
            m_tokenStore->clear(m_config.topic);
        }

        return fetchAndCommit(session, info, probe, plan, localToken);
    }

    content_manager::CycleOutcome fetchAndCommit(PitSession& session,
                                                 const content_manager::SessionInfo& info,
                                                 const ProbeResult& probe,
                                                 const FetchPlan& plan,
                                                 const std::string& localToken)
    {
        using namespace content_manager;

        FetchOutcome fetch;
        if (plan.mode != FetchPlan::Mode::NoChange)
        {
            fetch = runFetch(session, plan);
            if (fetch.interrupted)
            {
                abortSession(AbortReason::StopRequested, "stop requested during fetch");
                return make(CycleStatus::SkippedStopRequested, "fetch interrupted by a stop request");
            }
            if (fetch.sinkRejected)
            {
                abortSession(AbortReason::SinkRejectedPage, fetch.error);
                return make(CycleStatus::FailedSink, "sink rejected a page: " + fetch.error);
            }
            if (!fetch.error.empty())
            {
                abortSession(AbortReason::FetchError, fetch.error);
                return make(CycleStatus::FailedTransport, fetch.error);
            }
        }

        // Nothing tokenised this cycle (an empty incremental fetch, or a hash-tracked topic): keep
        // the bound we already had so the final token does not regress it.
        const auto highest = fetch.highestPageToken.empty() ? localToken : fetch.highestPageToken;

        CommitInfo commitInfo;
        commitInfo.topic = m_config.topic;
        commitInfo.kind = info.kind;
        commitInfo.finalToken = m_detector->finalToken(probe, highest);
        commitInfo.documentsDelivered = fetch.documentsDelivered;

        auto outcome = commit(commitInfo);
        outcome.documentsDelivered = fetch.documentsDelivered;
        return outcome;
    }

    FetchOutcome runFetch(PitSession& session, const FetchPlan& plan)
    {
        auto spec = m_config.fetchTemplate;
        spec.query = session.scopeToData(plan.query);
        spec.pageTokenPointer = m_detector->pageTokenPointer();
        // Slicing discards per-page durability, so it is only ever used where there is none to lose:
        // a full reload, which restarts from scratch anyway.
        spec.slices = plan.mode == FetchPlan::Mode::Full ? m_config.fullSlices : 1U;

        PitPaginator::DurableCallback onDurable;
        if (m_tokenStore)
        {
            onDurable = [this](const std::string& token)
            {
                if (!m_tokenStore->store(m_config.topic, token))
                {
                    logWarn(WM_CONTENTUPDATER,
                            "Failed to persist the durable resume point '%s' for '%s'; the next cycle will "
                            "re-fetch from the previous one.",
                            token.c_str(),
                            m_config.topic.c_str());
                }
            };
        }

        PitPaginator paginator {*m_port, session, m_stop};
        return paginator.run(spec, *m_sink, m_config.topic, onDurable);
    }

    content_manager::CycleOutcome commit(const content_manager::CommitInfo& commitInfo)
    {
        using namespace content_manager;

        CommitResult result;
        try
        {
            result = m_sink->commit(commitInfo);
        }
        catch (...)
        {
            result = CommitResult {CommitStatus::RejectedRetrySame, "sink threw from commit"};
        }

        if (result.status == CommitStatus::RejectedRetryFull)
        {
            if (m_tokenStore)
            {
                m_tokenStore->clear(m_config.topic);
            }
            const auto detail = result.detail.empty() ? std::string {"sink rejected the content; forcing a full reload"}
                                                      : result.detail;
            logWarn(WM_CONTENTUPDATER,
                    "Content update for '%s' was rejected on commit (%s); the stored token was cleared and the "
                    "next cycle will perform a full reload.",
                    m_config.topic.c_str(),
                    detail.c_str());
            return make(CycleStatus::FailedSink, detail);
        }

        if (result.status != CommitStatus::Committed)
        {
            return make(CycleStatus::FailedSink,
                        result.detail.empty() ? std::string {"sink could not promote the content"} : result.detail);
        }

        if (!commitInfo.finalToken.empty() && m_tokenStore &&
            !m_tokenStore->store(m_config.topic, commitInfo.finalToken))
        {
            // The content is live and the token is not. Reporting failure re-fetches next cycle,
            // which is the safe direction; the sink is NOT aborted, its content is already promoted.
            logWarn(WM_CONTENTUPDATER,
                    "Content update for '%s' committed but its token could not be persisted; the next cycle "
                    "will re-fetch.",
                    m_config.topic.c_str());
            return make(CycleStatus::FailedSink, "content committed but the token could not be persisted");
        }

        return make(commitInfo.documentsDelivered > 0 ? CycleStatus::Updated : CycleStatus::Unchanged, result.detail);
    }

    content_manager::SessionDecision beginSession(const content_manager::SessionInfo& info) noexcept
    {
        try
        {
            return m_sink->beginSession(info);
        }
        catch (...)
        {
            return content_manager::SessionDecision::Abort;
        }
    }

    void abortSession(content_manager::AbortReason reason, const std::string& detail) noexcept
    {
        try
        {
            m_sink->abort(reason, detail);
        }
        catch (...)
        {
            logWarn(WM_CONTENTUPDATER, "Sink threw from abort() for '%s'; ignored.", m_config.topic.c_str());
        }
    }

    std::string loadToken() noexcept
    {
        return m_tokenStore ? m_tokenStore->load(m_config.topic) : std::string {};
    }

    /// The outcome of @p status, with the token now in force and the backoff that status carries.
    content_manager::CycleOutcome make(content_manager::CycleStatus status, std::string detail)
    {
        using content_manager::CycleStatus;

        content_manager::CycleOutcome outcome;
        outcome.status = status;
        outcome.detail = std::move(detail);
        outcome.token = loadToken();
        switch (status)
        {
            case CycleStatus::SkippedConsumerNotReady:
            case CycleStatus::SkippedPreconditionUnmet: outcome.retryAfter = m_config.consumerRetryInterval; break;
            case CycleStatus::FailedTransport:
            case CycleStatus::FailedSink: outcome.retryAfter = FAILURE_RETRY_INTERVAL; break;
            default: break;
        }
        return outcome;
    }

    static content_manager::SessionKind toKind(FetchPlan::Mode mode) noexcept
    {
        switch (mode)
        {
            case FetchPlan::Mode::Incremental: return content_manager::SessionKind::Incremental;
            case FetchPlan::Mode::NoChange: return content_manager::SessionKind::NoChange;
            case FetchPlan::Mode::Full:
            default: return content_manager::SessionKind::FullReload;
        }
    }

    /// Flat: the driver escalates consecutive transport failures, since a cycle keeps no state.
    static constexpr std::chrono::seconds FAILURE_RETRY_INTERVAL {30};

    Config m_config;
    std::shared_ptr<content_manager::IContentIndexer> m_port;
    std::unique_ptr<IChangeDetector> m_detector;
    std::shared_ptr<content_manager::IContentSink> m_sink;
    std::shared_ptr<content_manager::IContentTokenStore> m_tokenStore;
    const std::atomic<bool>& m_stop;
};

#endif // _CONTENT_CYCLE_HPP
