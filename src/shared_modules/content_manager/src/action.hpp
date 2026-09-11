/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ACTION_MODULE_HPP
#define _ACTION_MODULE_HPP

#include "actionOrchestrator.hpp"
#include "conditionSync.hpp"
#include "contentTypes.hpp"
#include "loggerHelper.h"
#include "onDemandManager.hpp"
#include "sharedDefs.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <json.hpp>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

/**
 * @brief One topic's driver: exclusivity, the optional scheduler thread, and the on-demand route.
 *
 * The scheduler thread is now opt-in — a host that owns a scheduler (the Engine) drives
 * @ref runOnce itself — and, when it exists, it waits for `CycleOutcome::retryAfter` rather than
 * always for the configured interval. That single change is what keeps bounding the in-cycle gates
 * from becoming a regression: with VD's 60-minute default interval, a manager that boots while the
 * indexer is mid-content-update used to re-probe every minute from inside the cycle and proceed the
 * moment the consumer turned ready. Returning `SkippedConsumerNotReady` and sleeping a full
 * interval instead would leave it with no CVE data for an hour.
 */
class Action final
{
public:
    /**
     * @brief Build a topic driver.
     *
     * @param topicName Topic name.
     * @param parameters Registration parameters.
     * @param sink Where the content goes.
     * @param tokenStore Host-supplied token store; may be null.
     * @param port Indexer access.
     */
    Action(std::string topicName,
           nlohmann::json parameters,
           std::shared_ptr<content_manager::IContentSink> sink,
           std::shared_ptr<content_manager::IContentTokenStore> tokenStore,
           std::shared_ptr<IIndexerQueryPort> port)
        : m_topicName {std::move(topicName)}
        , m_stopActionCondition {std::make_shared<ConditionSync>(false)}
        , m_orchestration {std::make_unique<ActionOrchestrator>(
              parameters, m_stopActionCondition, std::move(sink), std::move(tokenStore), std::move(port))}
    {
        m_parameters = std::move(parameters);
    }

    /**
     * @brief Stop the driver and drain whatever it is doing.
     *
     * Returns only once nothing can still be inside the sink: the stop flag is raised first so an
     * in-flight cycle winds down at its next checkpoint, then each of the three possible drivers is
     * drained in turn — the on-demand lane, the optional scheduler thread, and any host thread that
     * called @ref runOnce directly.
     */
    ~Action()
    {
        m_stopActionCondition->set(true);

        unregisterActionOnDemand();
        stopActionScheduler();
        waitForIdle();
    }

    /**
     * @brief Claim this topic's single run slot.
     *
     * Split out of @ref runOnce so a caller holding a registry lock can claim the slot before
     * releasing it — otherwise a teardown could begin its drain in the gap between finding the
     * topic and starting to run it, and would then miss the cycle it is supposed to wait for.
     *
     * @return False when a cycle for this topic is already in progress.
     */
    bool tryBeginRun() noexcept
    {
        std::lock_guard<std::mutex> lock {m_runStateMutex};
        if (m_running)
        {
            return false;
        }
        m_running = true;
        return true;
    }

    /**
     * @brief Run one cycle on an already-claimed slot.
     *
     * @param request What the caller wants.
     * @return The outcome. Never throws.
     * @pre @ref tryBeginRun returned true and the slot has not been released since.
     */
    content_manager::CycleOutcome runClaimed(const content_manager::RunRequest& request) noexcept
    {
        auto outcome = m_orchestration->run(request);
        applyTransportBackoff(outcome);
        report(outcome);
        endRun();
        return outcome;
    }

    /**
     * @brief Run one cycle, unless one is already running for this topic.
     *
     * @param request What the caller wants.
     * @param[out] ran Set to false when a cycle for this topic was already in progress.
     * @return The outcome, or a skipped outcome when @p ran comes back false.
     */
    content_manager::CycleOutcome runOnce(const content_manager::RunRequest& request, bool& ran) noexcept
    {
        if (!tryBeginRun())
        {
            ran = false;
            content_manager::CycleOutcome outcome;
            outcome.status = content_manager::CycleStatus::SkippedAlreadyRunning;
            outcome.detail = "an update for this topic is already in progress";
            return outcome;
        }

        ran = true;
        return runClaimed(request);
    }

    /**
     * @brief Block until no cycle is running for this topic.
     *
     * Does not itself prevent a new one from starting: the caller is expected to have already made
     * the topic unreachable (removed it from the registry) before calling this.
     */
    void waitForIdle() noexcept
    {
        std::unique_lock<std::mutex> lock {m_runStateMutex};
        m_runStateCv.wait(lock, [this] { return !m_running; });
    }

    /**
     * @brief Start the library's own driver thread.
     *
     * @param interval Nominal interval, in seconds.
     */
    void startActionScheduler(const size_t interval)
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_schedulerRunning = true;
        }
        m_interval = interval;
        m_schedulerThread = std::thread(
            [this]()
            {
                // Run on start, independently of the interval, and with no lock held: a cycle can
                // take minutes, and holding m_mutex across it would make stopping or re-configuring
                // the driver wait for the download. Checked first so a registration torn down
                // before its thread was scheduled does not pay for a whole cycle it will discard.
                if (!m_schedulerRunning)
                {
                    return;
                }
                auto wait = runScheduled();

                std::unique_lock<std::mutex> lock(m_mutex);
                while (m_schedulerRunning)
                {
                    m_cv.wait_for(lock, wait);
                    if (!m_schedulerRunning)
                    {
                        break;
                    }

                    lock.unlock();
                    wait = runScheduled();
                    lock.lock();
                }
            });
    }

    /**
     * @brief Stop and join the driver thread, if there is one.
     */
    void stopActionScheduler()
    {
        {
            // Under the lock the waiter also holds when it tests the flag. Without it, a stop
            // landing between the test and the wait is lost, and the join below then blocks for a
            // whole interval — up to an hour with the vulnerability scanner's default.
            std::lock_guard<std::mutex> lock(m_mutex);
            m_schedulerRunning = false;
        }
        m_cv.notify_one();

        if (m_schedulerThread.joinable())
        {
            m_schedulerThread.join();
        }
        logDebug2(WM_CONTENTUPDATER, "Scheduler stopped for '%s'", m_topicName.c_str());
    }

    /**
     * @brief Publish this topic on the on-demand lane.
     */
    void registerActionOnDemand()
    {
        OnDemandManager::instance().addEndpoint(
            m_topicName,
            [this](content_manager::RunRequest request)
            {
                OnDemandManager::RunResult result;
                bool ran = false;
                result.outcome = this->runOnce(request, ran);
                result.ran = ran;
                return result;
            });
    }

    /**
     * @brief Withdraw this topic from the on-demand lane.
     *
     * Blocks until no on-demand callback for this topic is in flight.
     */
    void unregisterActionOnDemand()
    {
        OnDemandManager::instance().removeEndpoint(m_topicName);
    }

    /**
     * @brief Change the driver thread's interval.
     *
     * @param interval New interval, in seconds.
     */
    void changeSchedulerInterval(size_t interval)
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_interval = interval;
        }
        m_cv.notify_one();
    }

    /// @return The token in force for this topic.
    std::string currentToken() const noexcept
    {
        return m_orchestration->currentToken();
    }

    /// @brief Ask any in-flight cycle to wind down at its next checkpoint.
    void requestStop() noexcept
    {
        m_stopActionCondition->set(true);
    }

private:
    /// Release the run slot and wake anything draining this topic.
    void endRun() noexcept
    {
        {
            std::lock_guard<std::mutex> lock {m_runStateMutex};
            m_running = false;
        }
        m_runStateCv.notify_all();
    }

    /// @return How long the driver should wait before the next cycle.
    std::chrono::seconds runScheduled()
    {
        logDebug2(WM_CONTENTUPDATER, "Starting scheduled action for '%s'", m_topicName.c_str());

        bool ran = false;
        const auto outcome = runOnce(content_manager::RunRequest {}, ran);
        if (!ran)
        {
            logDebug2(WM_CONTENTUPDATER, "Action in progress for '%s', scheduled request ignored", m_topicName.c_str());
            return std::chrono::seconds {m_interval.load()};
        }

        return outcome.retryAfter > std::chrono::seconds {0} ? outcome.retryAfter
                                                             : std::chrono::seconds {m_interval.load()};
    }

    /**
     * @brief Turn the cycle's flat transport backoff into an escalating one.
     *
     * A `ContentCycle` runs once and keeps nothing between runs, so it cannot count consecutive
     * failures; this object can. The ceiling is five minutes, and never longer than the configured
     * interval — backing off past the interval would make the driver slower than simply waiting for
     * the next scheduled run.
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
        const auto step = std::chrono::seconds {BASE_TRANSPORT_BACKOFF.count() << shift};

        auto ceiling = MAX_TRANSPORT_BACKOFF;
        if (const auto interval = m_interval.load(); interval > 0)
        {
            ceiling = std::min(ceiling, std::chrono::seconds {interval});
        }

        outcome.retryAfter = std::min(step, ceiling);
    }

    void report(const content_manager::CycleOutcome& outcome) const
    {
        using content_manager::CycleStatus;

        switch (outcome.status)
        {
            case CycleStatus::Updated:
                logInfo(WM_CONTENTUPDATER,
                        "Content update for '%s' completed: %zu document(s), token '%s'.",
                        m_topicName.c_str(),
                        outcome.documentsDelivered,
                        outcome.token.c_str());
                break;

            case CycleStatus::Unchanged:
                logDebug1(WM_CONTENTUPDATER, "Content for '%s' is up to date.", m_topicName.c_str());
                break;

            case CycleStatus::FailedTransport:
            case CycleStatus::FailedSink:
            case CycleStatus::FailedConfig:
                logWarn(WM_CONTENTUPDATER,
                        "Content update for '%s' failed: %s. Retrying in %llds.",
                        m_topicName.c_str(),
                        outcome.detail.c_str(),
                        static_cast<long long>(outcome.retryAfter.count()));
                break;

            case CycleStatus::SkippedConsumerNotReady:
            case CycleStatus::SkippedPreconditionUnmet:
                logDebug1(WM_CONTENTUPDATER,
                          "Content update for '%s' deferred: %s. Retrying in %llds.",
                          m_topicName.c_str(),
                          outcome.detail.c_str(),
                          static_cast<long long>(outcome.retryAfter.count()));
                break;

            case CycleStatus::SkippedStopRequested:
            case CycleStatus::SkippedAlreadyRunning:
            default:
                logDebug2(WM_CONTENTUPDATER,
                          "Content update for '%s' did not run: %s",
                          m_topicName.c_str(),
                          outcome.detail.c_str());
                break;
        }
    }

    static constexpr std::chrono::seconds BASE_TRANSPORT_BACKOFF {30};
    static constexpr std::chrono::seconds MAX_TRANSPORT_BACKOFF {300};
    static constexpr std::size_t MAX_BACKOFF_DOUBLINGS {4};

    std::thread m_schedulerThread;
    /// Written under m_mutex so the scheduler thread cannot miss a stop between testing it and
    /// waiting; atomic so the thread body can also read it without one.
    std::atomic<bool> m_schedulerRunning {false};
    std::atomic<size_t> m_interval {0};
    std::mutex m_mutex;
    std::condition_variable m_cv;

    /// The topic's single run slot. A mutex rather than an atomic flag because teardown has to be
    /// able to *wait* for it, not only test it.
    std::mutex m_runStateMutex;
    std::condition_variable m_runStateCv;
    bool m_running {false};

    std::string m_topicName;
    nlohmann::json m_parameters;
    std::shared_ptr<ConditionSync> m_stopActionCondition;
    std::unique_ptr<ActionOrchestrator> m_orchestration;
    std::size_t m_consecutiveTransportFailures {0};
};

#endif // _ACTION_MODULE_HPP
