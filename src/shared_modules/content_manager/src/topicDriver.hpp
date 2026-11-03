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

#ifndef _TOPIC_DRIVER_HPP
#define _TOPIC_DRIVER_HPP

#include "components/contentCycle.hpp"
#include "components/factoryContentUpdater.hpp"
#include "components/rocksDbTokenStore.hpp"
#include "components/topicSpecValidation.hpp"
#include "contentIndexer.hpp"
#include "contentSink.hpp"
#include "contentTokenStore.hpp"
#include "contentTopicSpec.hpp"
#include "contentTypes.hpp"
#include "loggerHelper.h"
#include "sharedDefs.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

/**
 * @brief One topic: its cycle, its run slot, and — when the library drives it — its thread.
 *
 * At most one cycle of a topic runs at a time, whoever asks for it: the host through @ref runOnce,
 * the driver thread on its interval, or a request queued with @ref requestRun. The thread exists
 * only when the registration has an interval; it runs a cycle at start, then waits for the cycle's
 * `retryAfter` (or the interval) or for a request, whichever comes first.
 */
class TopicDriver final
{
public:
    using Completion = std::function<void(content_manager::OnDemandResult)>;

    /**
     * @brief Validate the registration, open its token store and start its thread.
     *
     * @param topicName Topic name.
     * @param spec The registration.
     * @param sink Where the content goes. Must not be null.
     * @param indexer The host's indexer. Must not be null.
     * @param tokenStore Host-supplied token store; when null, one is opened under
     *                   `state.databasePath` if there is one.
     * @throws std::invalid_argument for an invalid registration.
     * @throws std::exception if the token database cannot be opened.
     */
    TopicDriver(std::string topicName,
                const content_manager::TopicSpec& spec,
                std::shared_ptr<content_manager::IContentSink> sink,
                std::shared_ptr<content_manager::IContentIndexer> indexer,
                std::shared_ptr<content_manager::IContentTokenStore> tokenStore)
        : m_topic {std::move(topicName)}
        , m_sink {std::move(sink)}
        , m_interval {spec.schedule.intervalSeconds.value_or(0)}
    {
        if (!m_sink)
        {
            throw std::invalid_argument {"A content sink is required to register '" + m_topic + "'"};
        }
        if (!indexer)
        {
            throw std::invalid_argument {"A content registration needs the host's indexer: '" + m_topic + "'"};
        }
        validateTopicSpec(spec);

        m_tokenStore = std::move(tokenStore);
        if (!m_tokenStore && !spec.state.databasePath.empty())
        {
            m_tokenStore = RocksDbTokenStore::open(spec.state.databasePath, m_topic);
        }
        if (m_tokenStore && spec.state.resetOnRegister)
        {
            logInfo(WM_CONTENTUPDATER,
                    "Clearing the stored content token for '%s' as requested at registration.",
                    m_topic.c_str());
            m_tokenStore->clear(m_topic);
        }

        m_cycle = FactoryContentUpdater::create(spec, m_topic, m_sink, m_tokenStore, m_stop, std::move(indexer));

        if (m_interval > 0)
        {
            m_thread = std::thread([this] { driverLoop(); });
        }
    }

    /// Stop the thread, answer a pending request, and wait for an in-flight cycle.
    ~TopicDriver()
    {
        std::optional<Pending> pending;
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_stop = true;
            m_shutdown = true;
        }
        m_cv.notify_all();
        if (m_thread.joinable())
        {
            m_thread.join();
        }

        {
            std::unique_lock<std::mutex> lock {m_mutex};
            m_cv.wait(lock, [this] { return !m_running; });
            pending.swap(m_pending);
        }
        if (pending.has_value())
        {
            complete(pending->completion,
                     content_manager::OnDemandResult {
                         content_manager::OnDemandCode::ShuttingDown, "the topic is stopping", {}});
        }
    }

    TopicDriver(const TopicDriver&) = delete;
    TopicDriver& operator=(const TopicDriver&) = delete;

    /**
     * @brief Run one cycle on the calling thread, unless one is already running.
     *
     * @param request What the caller wants.
     * @return The outcome; `SkippedAlreadyRunning` when another cycle held the slot.
     */
    content_manager::CycleOutcome runOnce(const content_manager::RunRequest& request) noexcept
    {
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            if (m_running)
            {
                content_manager::CycleOutcome outcome;
                outcome.status = content_manager::CycleStatus::SkippedAlreadyRunning;
                outcome.detail = "an update for this topic is already in progress";
                return outcome;
            }
            m_running = true;
        }

        auto outcome = m_cycle->run(request);
        applyTransportBackoff(outcome);
        report(outcome);
        try
        {
            m_sink->cycleFinished(outcome);
        }
        catch (...)
        {
            logWarn(WM_CONTENTUPDATER, "Sink threw from cycleFinished() for '%s'; ignored.", m_topic.c_str());
        }

        {
            // Notified under the lock: the destructor may be waiting for this slot, and once it sees
            // it free it destroys the condition variable.
            std::lock_guard<std::mutex> lock {m_mutex};
            m_running = false;
            m_cv.notify_all();
        }
        return outcome;
    }

    /**
     * @brief Queue a cycle for the driver thread, or answer at once why it cannot be.
     *
     * @param request What the cycle should do.
     * @param completion Invoked exactly once with the result. May be empty.
     */
    void requestRun(const content_manager::RunRequest& request, Completion completion) noexcept
    {
        using content_manager::OnDemandCode;

        std::optional<content_manager::OnDemandResult> rejection;
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            if (!m_thread.joinable())
            {
                rejection = content_manager::OnDemandResult {
                    OnDemandCode::Failed, "'" + m_topic + "' is run by its host, not by the library", {}};
            }
            else if (m_stop)
            {
                rejection = content_manager::OnDemandResult {OnDemandCode::ShuttingDown, "the topic is stopping", {}};
            }
            else if (m_running || m_pending.has_value())
            {
                rejection = content_manager::OnDemandResult {
                    OnDemandCode::AlreadyRunning, "an update for this topic is already in progress", {}};
            }
            else
            {
                m_pending = Pending {request, std::move(completion)};
            }
        }

        if (rejection.has_value())
        {
            complete(completion, std::move(*rejection));
            return;
        }
        m_cv.notify_all();
    }

    /// @return The token in force for this topic, or "" when there is none.
    std::string currentToken() const noexcept
    {
        return m_tokenStore ? m_tokenStore->load(m_topic) : std::string {};
    }

    /// @brief Stop this topic for good: the in-flight cycle winds down, later ones are skipped.
    void requestStop() noexcept
    {
        m_stop = true;
        m_cv.notify_all();
    }

    /**
     * @brief Map a cycle's outcome onto the answer a request handler gives.
     *
     * @param outcome The cycle's outcome.
     * @return The result.
     */
    static content_manager::OnDemandResult toResult(const content_manager::CycleOutcome& outcome)
    {
        using content_manager::CycleStatus;
        using content_manager::OnDemandCode;

        auto code = OnDemandCode::Failed;
        switch (outcome.status)
        {
            case CycleStatus::Updated:
            case CycleStatus::Unchanged: code = OnDemandCode::Completed; break;
            case CycleStatus::SkippedConsumerNotReady:
            case CycleStatus::SkippedPreconditionUnmet: code = OnDemandCode::Deferred; break;
            case CycleStatus::SkippedAlreadyRunning: code = OnDemandCode::AlreadyRunning; break;
            case CycleStatus::SkippedStopRequested: code = OnDemandCode::ShuttingDown; break;
            case CycleStatus::FailedTransport:
            case CycleStatus::FailedSink:
            case CycleStatus::FailedConfig: code = OnDemandCode::Failed; break;
        }
        return content_manager::OnDemandResult {code, outcome.detail, outcome};
    }

private:
    struct Pending
    {
        content_manager::RunRequest request;
        Completion completion;
    };

    /// The driver thread: a cycle now, then one per wake-up — a request, or the timer running out.
    void driverLoop()
    {
        auto wait = std::chrono::seconds {0};
        std::unique_lock<std::mutex> lock {m_mutex};
        while (!m_shutdown)
        {
            if (wait.count() > 0)
            {
                m_cv.wait_for(lock, wait, [this] { return m_shutdown || m_pending.has_value(); });
                if (m_shutdown)
                {
                    break;
                }
            }

            std::optional<Pending> pending;
            pending.swap(m_pending);
            lock.unlock();

            const auto outcome = runOnce(pending.has_value() ? pending->request : content_manager::RunRequest {});
            if (pending.has_value())
            {
                complete(pending->completion, toResult(outcome));
            }
            wait = outcome.retryAfter.count() > 0 ? outcome.retryAfter : std::chrono::seconds {m_interval};

            lock.lock();
        }
    }

    /// Invoke a completion with no lock held; a throwing one is the host's bug, contained here.
    void complete(const Completion& completion, content_manager::OnDemandResult result) noexcept
    {
        if (!completion)
        {
            return;
        }
        try
        {
            completion(std::move(result));
        }
        catch (...)
        {
            logWarn(WM_CONTENTUPDATER, "An update completion for '%s' threw; ignored.", m_topic.c_str());
        }
    }

    /**
     * @brief Turn the cycle's flat transport backoff into an escalating one.
     *
     * A cycle keeps nothing between runs, so it cannot count consecutive failures; the driver can.
     * The ceiling is five minutes, and never longer than the interval — backing off past it would
     * make the driver slower than simply waiting for the next scheduled run.
     */
    void applyTransportBackoff(content_manager::CycleOutcome& outcome) noexcept
    {
        if (outcome.status != content_manager::CycleStatus::FailedTransport)
        {
            m_consecutiveTransportFailures = 0;
            return;
        }

        ++m_consecutiveTransportFailures;
        const auto shift = std::min<std::size_t>(m_consecutiveTransportFailures - 1, MAX_BACKOFF_DOUBLINGS);
        auto ceiling = MAX_TRANSPORT_BACKOFF;
        if (m_interval > 0)
        {
            ceiling = std::min(ceiling, std::chrono::seconds {m_interval});
        }
        outcome.retryAfter = std::min(std::chrono::seconds {BASE_TRANSPORT_BACKOFF.count() << shift}, ceiling);
    }

    void report(const content_manager::CycleOutcome& outcome) const
    {
        using content_manager::CycleStatus;

        switch (outcome.status)
        {
            case CycleStatus::Updated:
                logInfo(WM_CONTENTUPDATER,
                        "Content update for '%s' completed: %zu document(s), token '%s'.",
                        m_topic.c_str(),
                        outcome.documentsDelivered,
                        outcome.token.c_str());
                break;

            case CycleStatus::Unchanged:
                logDebug1(WM_CONTENTUPDATER, "Content for '%s' is up to date.", m_topic.c_str());
                break;

            case CycleStatus::FailedTransport:
            case CycleStatus::FailedSink:
                logWarn(WM_CONTENTUPDATER,
                        "Content update for '%s' failed: %s. Retrying in %llds.",
                        m_topic.c_str(),
                        outcome.detail.c_str(),
                        static_cast<long long>(outcome.retryAfter.count()));
                break;

            case CycleStatus::SkippedPreconditionUnmet:
                logInfo(WM_CONTENTUPDATER,
                        "Content update for '%s' deferred: %s. Retrying in %llds.",
                        m_topic.c_str(),
                        outcome.detail.c_str(),
                        static_cast<long long>(outcome.retryAfter.count()));
                break;

            case CycleStatus::SkippedConsumerNotReady:
                // The consumer gate escalates on its own cadence, once per consumer rather than per topic.
                logDebug1(WM_CONTENTUPDATER,
                          "Content update for '%s' deferred: %s. Retrying in %llds.",
                          m_topic.c_str(),
                          outcome.detail.c_str(),
                          static_cast<long long>(outcome.retryAfter.count()));
                break;

            case CycleStatus::FailedConfig: // Logged as an error by the cycle, naming the field.
            case CycleStatus::SkippedStopRequested:
            case CycleStatus::SkippedAlreadyRunning:
                logDebug2(WM_CONTENTUPDATER,
                          "Content update for '%s' did not run: %s",
                          m_topic.c_str(),
                          outcome.detail.c_str());
                break;
        }
    }

    static constexpr std::chrono::seconds BASE_TRANSPORT_BACKOFF {30};
    static constexpr std::chrono::seconds MAX_TRANSPORT_BACKOFF {300};
    static constexpr std::size_t MAX_BACKOFF_DOUBLINGS {4};

    std::string m_topic;
    std::shared_ptr<content_manager::IContentSink> m_sink;
    std::shared_ptr<content_manager::IContentTokenStore> m_tokenStore;
    const std::size_t m_interval;
    std::atomic<bool> m_stop {false};
    std::unique_ptr<ContentCycle> m_cycle;
    std::size_t m_consecutiveTransportFailures {0}; ///< Touched only while holding the run slot.

    std::mutex m_mutex; ///< Guards the three fields below.
    std::condition_variable m_cv;
    bool m_running {false};  ///< The run slot.
    bool m_shutdown {false}; ///< The driver thread must exit.
    std::optional<Pending> m_pending;

    std::thread m_thread; ///< Last: started once every other member exists.
};

#endif // _TOPIC_DRIVER_HPP
