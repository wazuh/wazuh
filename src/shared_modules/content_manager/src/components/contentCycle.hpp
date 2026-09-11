/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTENT_CYCLE_HPP
#define _CONTENT_CYCLE_HPP

#include "changeDetector.hpp"
#include "conditionSync.hpp"
#include "consumerGate.hpp"
#include "contentSink.hpp"
#include "contentTokenStore.hpp"
#include "contentTypes.hpp"
#include "indexerQueryPort.hpp"
#include "loggerHelper.h"
#include "pitPaginator.hpp"
#include "pitSession.hpp"
#include "sharedDefs.hpp"
#include <chrono>
#include <memory>
#include <string>
#include <utility>

/**
 * @brief One content cycle: probe, fetch, deliver, promote, persist. Exactly once.
 *
 * This class replaces `IndexerDownloader`, and the difference that matters is not the size: it runs
 * the cycle **once** and returns a value. The old one owned three unbounded polling loops, so a
 * caller could not know how long `handleRequest` would take, and "wait for the consumer" was
 * expressed as a parked thread. Here every gate is single-pass and every non-terminal outcome
 * carries a `retryAfter` for the driver to honour, which is what makes it safe to run on a shared
 * scheduler worker pool.
 *
 * ### Who writes the token
 *
 * Exactly four paths, and no others:
 *  - `RunRequest::forceFullReload` clears it **before** probing. This is the one pre-cycle write and
 *    it is deliberate: if the process dies mid-reload, a cleared token makes the next boot start
 *    over instead of resuming from a cursor whose content was already partially overwritten.
 *  - a `Durable` page acknowledgement stores that page's token immediately;
 *  - `CommitStatus::Committed` stores the final token;
 *  - `CommitStatus::RejectedRetryFull` clears it.
 *
 * `Skip`, `Abort`, `RejectedRetrySame`, interruption and transport errors all leave it untouched.
 *
 * ### Exception containment
 *
 * `run` is `noexcept` and everything that can throw — the port, the PIT session's constructor, the
 * detectors — is constructed or called inside its `try`. This is load-bearing rather than tidy: the
 * sink may live in a DSO with its own libstdc++, and an exception unwinding across that boundary is
 * undefined. Sink calls get a second `catch (...)` of their own, on this side of the boundary.
 */
class ContentCycle final
{
public:
    /// Everything about a topic that does not change between cycles.
    struct Config
    {
        std::string topic;                        ///< Registered topic name.
        PitSession::Config pit;                   ///< Indices and consumer document to snapshot.
        FetchSpec fetchTemplate;                  ///< Sort, source filter, page size. Query is per-cycle.
        std::size_t fullSlices {1};               ///< Slices to use on a full fetch.
        nlohmann::json requiredDocumentIds;       ///< Documents that must exist before a full load.
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
     * @param stop Cooperative stop flag shared with the driver.
     */
    ContentCycle(Config config,
                 std::shared_ptr<IIndexerQueryPort> port,
                 std::unique_ptr<IChangeDetector> detector,
                 std::shared_ptr<content_manager::IContentSink> sink,
                 std::shared_ptr<content_manager::IContentTokenStore> tokenStore,
                 std::shared_ptr<ConditionSync> stop)
        : m_config {std::move(config)}
        , m_port {std::move(port)}
        , m_detector {std::move(detector)}
        , m_sink {std::move(sink)}
        , m_tokenStore {std::move(tokenStore)}
        , m_stop {std::move(stop)}
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
        using namespace content_manager;

        CycleOutcome outcome;

        try
        {
            if (m_stop->check())
            {
                outcome.status = CycleStatus::SkippedStopRequested;
                outcome.detail = "stop requested before the cycle started";
                outcome.token = loadToken();
                return outcome;
            }

            if (request.forceFullReload && m_tokenStore)
            {
                logDebug2(WM_CONTENTUPDATER,
                          "Clearing the stored token for '%s' to force a full reload.",
                          m_config.topic.c_str());
                m_tokenStore->clear(m_config.topic);
            }

            // Cost gate: cheap, non-PIT, and cached across topics watching the same consumer. Its
            // job is only to avoid paying for a PIT over a multi-gigabyte index when the indexer is
            // visibly mid-update; the authoritative check happens inside the snapshot below.
            const auto preflight = ConsumerGate::probe(
                *m_port, m_config.pit.consumerStatusIndex, m_config.pit.consumerStatusId, m_config.consumerCacheTtl);

            if (preflight.status == ConsumerGate::Status::Unreachable)
            {
                return transportFailure("indexer unreachable: " + preflight.error);
            }
            if (preflight.status != ConsumerGate::Status::Ready)
            {
                return consumerNotReady(std::string {"pre-flight consumer status: "} +
                                        ConsumerGate::describe(preflight.status));
            }

            return runInSession(request);
        }
        catch (const std::exception& e)
        {
            return transportFailure(e.what());
        }
        catch (...)
        {
            return transportFailure("unknown error");
        }
    }

private:
    content_manager::CycleOutcome runInSession(const content_manager::RunRequest& request)
    {
        using namespace content_manager;

        PitSession session {*m_port, m_config.pit};

        // Correctness gate. Unlike the pre-flight it reads the consumer document from inside the
        // very snapshot the content will be read from, so a consumer that starts rewriting between
        // the two cannot be missed.
        std::string rawStatus;
        switch (session.validateConsumerReady(&rawStatus))
        {
            case PitSession::Readiness::Ready: break;

            case PitSession::Readiness::Missing:
                reportMissingConsumer();
                return consumerNotReady("consumer document '" + m_config.pit.consumerStatusId + "' not found");

            case PitSession::Readiness::Unusable:
                return consumerNotReady("consumer document '" + m_config.pit.consumerStatusId +
                                        "' carries no readable status");

            case PitSession::Readiness::NotReady:
            default: return consumerNotReady("in-PIT consumer status: " + rawStatus);
        }
        m_missingConsumerCycles = 0;

        const auto localToken = loadToken();
        const auto probe = m_detector->probe(session, *m_port);

        // A probe that cannot identify the remote state unambiguously is a configuration fault, not
        // a transient one. Reporting it as such stops the driver from retrying something that
        // cannot succeed, and names the key at fault instead of silently syncing the wrong content.
        if (!probe.configError.empty())
        {
            CycleOutcome outcome;
            outcome.status = CycleStatus::FailedConfig;
            outcome.detail = probe.configError;
            outcome.token = localToken;
            logError(WM_CONTENTUPDATER,
                     "Content update for '%s' cannot run: %s",
                     m_config.topic.c_str(),
                     outcome.detail.c_str());
            return outcome;
        }

        const auto plan = m_detector->plan(probe, localToken);

        // Checked on a full plan only, matching the behaviour it replaces. An incremental run means
        // a previous cycle committed successfully, so the required documents were present then; if
        // they have since gone, the sink's own validation in commit() rejects with RetryFull, which
        // clears the token and makes the next cycle full — where this is checked.
        if (plan.mode == FetchPlan::Mode::Full && !m_config.requiredDocumentIds.empty())
        {
            const auto found = session.countDocuments(m_config.requiredDocumentIds);
            if (found < m_config.requiredDocumentIds.size())
            {
                CycleOutcome outcome;
                outcome.status = CycleStatus::SkippedPreconditionUnmet;
                outcome.detail = "required documents not indexed yet (" + std::to_string(found) + "/" +
                                 std::to_string(m_config.requiredDocumentIds.size()) + ")";
                outcome.token = localToken;
                outcome.retryAfter = m_config.consumerRetryInterval;
                logInfo(WM_CONTENTUPDATER,
                        "Content update for '%s' deferred: %s",
                        m_config.topic.c_str(),
                        outcome.detail.c_str());
                return outcome;
            }
        }

        SessionInfo info;
        info.topic = m_config.topic;
        info.kind = toKind(plan.mode);
        info.localToken = localToken;
        info.remoteToken = probe.remoteToken;
        info.probeMetadata = probe.metadata;
        info.onDemand = request.onDemand;

        const auto decision = beginSession(info);
        if (decision == SessionDecision::Skip)
        {
            CycleOutcome outcome;
            outcome.status = CycleStatus::Unchanged;
            outcome.detail = "sink declined this cycle";
            outcome.token = localToken;
            return outcome;
        }
        if (decision == SessionDecision::Abort)
        {
            return sinkFailure("sink is not accepting content right now", localToken);
        }

        FetchOutcome fetch;
        if (plan.mode != FetchPlan::Mode::NoChange)
        {
            fetch = runFetch(session, plan, localToken);

            if (fetch.interrupted)
            {
                abortSession(AbortReason::StopRequested, "stop requested during fetch");
                CycleOutcome outcome;
                outcome.status = CycleStatus::SkippedStopRequested;
                outcome.detail = "fetch interrupted by a stop request";
                outcome.token = loadToken();
                return outcome;
            }
            if (fetch.sinkRejected)
            {
                abortSession(AbortReason::SinkRejectedPage, fetch.error);
                return sinkFailure("sink rejected a page: " + fetch.error, loadToken());
            }
            if (!fetch.error.empty())
            {
                abortSession(AbortReason::FetchError, fetch.error);
                return transportFailure(fetch.error);
            }
        }

        return commit(info, probe, fetch, localToken);
    }

    FetchOutcome runFetch(PitSession& session, const FetchPlan& plan, const std::string& localToken)
    {
        auto spec = m_config.fetchTemplate;
        spec.query = session.scopeToData(plan.query);
        spec.pageTokenPointer = m_detector->pageTokenPointer();
        // Slicing discards per-page durability, so it is only ever used where there is none to lose:
        // a full reload, which restarts from scratch anyway.
        spec.slices = plan.mode == FetchPlan::Mode::Full ? m_config.fullSlices : 1U;

        PitPaginator paginator {*m_port, session, *m_stop};

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

        auto outcome = paginator.run(spec, *m_sink, m_config.topic, std::move(onDurable));
        if (outcome.highestPageToken.empty())
        {
            // Nothing tokenised this cycle (an empty incremental fetch, or a hash-tracked topic):
            // keep the bound we already had so finalToken does not regress it.
            outcome.highestPageToken = localToken;
        }
        return outcome;
    }

    content_manager::CycleOutcome commit(const content_manager::SessionInfo& info,
                                         const ProbeResult& probe,
                                         const FetchOutcome& fetch,
                                         const std::string& localToken)
    {
        using namespace content_manager;

        CommitInfo commitInfo;
        commitInfo.topic = m_config.topic;
        commitInfo.kind = info.kind;
        commitInfo.finalToken = m_detector->finalToken(probe, fetch.highestPageToken);
        commitInfo.documentsDelivered = fetch.documentsDelivered;
        commitInfo.changed = fetch.documentsDelivered > 0;

        CommitResult result;
        try
        {
            result = m_sink->commit(commitInfo);
        }
        catch (...)
        {
            result = CommitResult {CommitStatus::RejectedRetrySame, "sink threw from commit"};
        }

        CycleOutcome outcome;
        outcome.documentsDelivered = fetch.documentsDelivered;

        switch (result.status)
        {
            case CommitStatus::Committed:
            {
                if (m_tokenStore && !m_tokenStore->store(m_config.topic, commitInfo.finalToken))
                {
                    // The content is live and the token is not. Reporting failure re-fetches next
                    // cycle, which is the safe direction; the sink is deliberately NOT aborted,
                    // since its content has already been promoted.
                    outcome.status = CycleStatus::FailedSink;
                    outcome.detail = "content committed but the token could not be persisted";
                    outcome.token = localToken;
                    outcome.retryAfter = SINK_RETRY_INTERVAL;
                    logWarn(WM_CONTENTUPDATER,
                            "Content update for '%s' committed but its token could not be persisted; the next "
                            "cycle will re-fetch.",
                            m_config.topic.c_str());
                    return outcome;
                }

                outcome.status = commitInfo.changed ? CycleStatus::Updated : CycleStatus::Unchanged;
                outcome.token = commitInfo.finalToken.empty() ? localToken : commitInfo.finalToken;
                outcome.detail = result.detail;
                return outcome;
            }

            case CommitStatus::RejectedRetryFull:
            {
                if (m_tokenStore)
                {
                    m_tokenStore->clear(m_config.topic);
                }
                outcome.status = CycleStatus::FailedSink;
                outcome.detail = result.detail.empty() ? "sink rejected the content; forcing a full reload"
                                                       : result.detail;
                outcome.token.clear();
                outcome.retryAfter = SINK_RETRY_INTERVAL;
                logWarn(WM_CONTENTUPDATER,
                        "Content update for '%s' was rejected on commit (%s); the stored token was cleared and "
                        "the next cycle will perform a full reload.",
                        m_config.topic.c_str(),
                        outcome.detail.c_str());
                return outcome;
            }

            case CommitStatus::RejectedRetrySame:
            default:
            {
                outcome.status = CycleStatus::FailedSink;
                outcome.detail =
                    result.detail.empty() ? "sink could not promote the content" : result.detail;
                outcome.token = localToken;
                outcome.retryAfter = SINK_RETRY_INTERVAL;
                return outcome;
            }
        }
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

    content_manager::CycleOutcome consumerNotReady(const std::string& detail)
    {
        content_manager::CycleOutcome outcome;
        outcome.status = content_manager::CycleStatus::SkippedConsumerNotReady;
        outcome.detail = detail;
        outcome.token = loadToken();
        outcome.retryAfter = m_config.consumerRetryInterval;
        return outcome;
    }

    content_manager::CycleOutcome transportFailure(const std::string& detail)
    {
        content_manager::CycleOutcome outcome;
        outcome.status = content_manager::CycleStatus::FailedTransport;
        outcome.detail = detail;
        outcome.token = loadToken();
        // Flat here on purpose: escalating this into a growing backoff needs state that survives
        // between cycles, and this object does not — ContentProvider owns that escalation.
        outcome.retryAfter = TRANSPORT_RETRY_INTERVAL;
        return outcome;
    }

    content_manager::CycleOutcome sinkFailure(const std::string& detail, const std::string& token)
    {
        content_manager::CycleOutcome outcome;
        outcome.status = content_manager::CycleStatus::FailedSink;
        outcome.detail = detail;
        outcome.token = token;
        outcome.retryAfter = SINK_RETRY_INTERVAL;
        return outcome;
    }

    /// A missing consumer document is the *normal* state of a fresh install, so it stays quiet for
    /// the first few cycles and only then becomes worth an operator's attention.
    void reportMissingConsumer()
    {
        ++m_missingConsumerCycles;
        if (m_missingConsumerCycles <= ConsumerGate::WARN_AFTER_ATTEMPTS)
        {
            logDebug2(WM_CONTENTUPDATER,
                      "Consumer '%s' not found for '%s' (cycle %zu/%zu).",
                      m_config.pit.consumerStatusId.c_str(),
                      m_config.topic.c_str(),
                      m_missingConsumerCycles,
                      ConsumerGate::WARN_AFTER_ATTEMPTS);
        }
        else
        {
            logInfo(WM_CONTENTUPDATER,
                    "Consumer '%s' is still not present in '%s'; content for '%s' cannot be downloaded yet.",
                    m_config.pit.consumerStatusId.c_str(),
                    m_config.pit.consumerStatusIndex.c_str(),
                    m_config.topic.c_str());
        }
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

    static constexpr std::chrono::seconds TRANSPORT_RETRY_INTERVAL {30};
    static constexpr std::chrono::seconds SINK_RETRY_INTERVAL {30};

    Config m_config;
    std::shared_ptr<IIndexerQueryPort> m_port;
    std::unique_ptr<IChangeDetector> m_detector;
    std::shared_ptr<content_manager::IContentSink> m_sink;
    std::shared_ptr<content_manager::IContentTokenStore> m_tokenStore;
    std::shared_ptr<ConditionSync> m_stop;
    std::size_t m_missingConsumerCycles {0};
};

#endif // _CONTENT_CYCLE_HPP
