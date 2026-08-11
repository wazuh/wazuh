/*
 * Wazuh remoted module - VD Scan handler
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "scanVdHandler.hpp"
#include "common/vdClient.hpp"
#include "json.hpp"
#include "loggerHelper.h"
#include "proc.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <httplib.h>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace remoted::scanvd
{
    namespace
    {
        constexpr auto SCANVD_HANDLER_LOGTAG {"wazuh-manager-remoted:scanvd-handler"};

        const LogFn& logFn()
        {
            static const LogFn instance {SCANVD_HANDLER_LOGTAG};
            return instance;
        }

        constexpr auto QUEUE_PROCESS_INTERVAL_MS = 100;
        constexpr uint8_t MAX_RETRIES = 3;

        // A single worker would let one agent's worst-case wait (VD_SCAN_READ_TIMEOUT_SECONDS --
        // see below) head-of-line-block every other queued agent on this node. A
        // pool bounds that blast radius as 1/N of total capacity, without the complexity of a
        // fully dynamic sizing scheme. This is a client-side occupancy concern (how many of
        // *this* pool's workers can be stuck waiting on one slow HTTP response at once) --
        // unrelated to how many scans VD can actually execute in parallel, which is exactly one
        // regardless of N: ScanOrchestrator::runScanAfterFeedUpdate() takes an exclusive lock for
        // the whole scan, shared with every other scan trigger in that process. So sizing this
        // above 1 helps *this* side (fewer of our own workers wedged on one slow agent at a time)
        // even though it can't make VD process our requests any faster; if this exceeds VD's own
        // admission pool (scanThreadPoolSize() in vulnerabilityScanner.cpp), excess requests
        // simply queue on VD's side instead of something rejecting them outright.
        //
        // Tracks cpp_get_nproc() -- like resolveThreadCount() in this module's own
        // httpServerConfig.cpp/downstreamConfig.cpp -- rather than a fixed constant, mainly for
        // consistency with that convention and so a much larger box gets more blast-radius
        // headroom; it doesn't need to match VD's pool size exactly (see above for why).
        size_t scanWorkerPoolSize()
        {
            static const size_t value = cpp_get_nproc();
            return value;
        }

        // VD's POST /vulnerability-detector/scan handler runs synchronously and can legitimately
        // block for up to ~30s (ServerScanCoordinator::pauseAgent()'s drain wait for a
        // concurrently active VDFirst/VDSync session on the same agent -- see
        // serverScanCoordinator.hpp's pauseQuiesceTimeout, 30s by default in production) before it
        // even starts scanning. The read timeout here MUST exceed that window (plus margin for
        // the scan itself) -- otherwise a legitimate in-progress wait gets misread as a network
        // failure, triggering a retry here while the original attempt is still running in the VD
        // module.
        constexpr long VD_SCAN_READ_TIMEOUT_SECONDS = 60;
        constexpr long VD_SCAN_WRITE_TIMEOUT_SECONDS = 5;
    } // namespace

    // Per-agent scan lifecycle. There is at most one of these per agent at any time, and it holds
    // the freshest offset that agent has asked to be scanned at -- NOT a frozen snapshot from
    // whenever the request first arrived. This is what lets a newer feed-update request
    // "overwrite" an older one still sitting in the queue or backing off from a retry, instead of
    // the older one running (or being discarded) while the newer one is silently dropped.
    struct AgentScanState
    {
        uint64_t pendingOffset;
        uint8_t retryCount = 0;
        bool inBackoff = false; // true while waiting out exponential backoff; not in m_scanQueue then.
        std::chrono::steady_clock::time_point nextRetryTime {};
    };

    class ScanVdHandlerImpl::Impl
    {
    public:
        Impl(std::shared_ptr<remoted::common::VdClient> vdClient,
             ScanVdMetrics& metrics,
             std::string vdModulesdSocketPath,
             size_t maxTrackedAgents)
            : m_vdClient(std::move(vdClient))
            , m_metrics(metrics)
            , m_vdModulesdSocketPath(std::move(vdModulesdSocketPath))
            , m_maxTrackedAgents(maxTrackedAgents)
            , m_stopping(false)
        {
            startWorkerThread();
        }

        ~Impl()
        {
            stopWorkerThread();
        }

        void
        handleVdScan(uint32_t agentId, uint64_t requestedOffset, remoted::endpoints::scanvd::ScanVdCallback callback)
        {
            LOGFN_DEBUG1(logFn(), "VD scan request for agent %u with offset %llu", agentId, requestedOffset);
            incRequests(m_metrics);

            if (agentId == 0)
            {
                LOGFN_WARN(logFn(), "VD scan request rejected: invalid agent ID (0)");
                incInvalidAgent(m_metrics);
                remoted::endpoints::scanvd::ScanVdResponse response;
                response.outcome = remoted::endpoints::scanvd::ScanVdOutcome::InvalidAgent;
                response.currentOffset = m_vdClient->getOffset();
                callback(response);
                return;
            }

            const uint64_t currentOffset = m_vdClient->getOffset();

            if (requestedOffset != currentOffset)
            {
                LOGFN_DEBUG1(logFn(),
                             "VD scan offset mismatch for agent %u: requested=%llu, current=%llu",
                             agentId,
                             requestedOffset,
                             currentOffset);

                incVersionMismatch(m_metrics);
                remoted::endpoints::scanvd::ScanVdResponse response;
                response.outcome = remoted::endpoints::scanvd::ScanVdOutcome::VersionMismatch;
                response.currentOffset = currentOffset;
                callback(response);
                return;
            }

            bool notifyWorker = false;
            bool rejectedFull = false;

            {
                std::lock_guard<std::mutex> lock(m_queueMutex);

                auto it = m_agentStates.find(agentId);
                if (it != m_agentStates.end())
                {
                    // Already tracked (queued, backing off, or being executed right now): just
                    // refresh the target offset. Whichever attempt runs next -- the one already
                    // queued, or the next retry -- will read this fresh value instead of a stale
                    // one, and an in-flight attempt is re-checked against it when it completes
                    // (see finishAttempt()).
                    it->second.pendingOffset = requestedOffset;

                    if (it->second.inBackoff)
                    {
                        // A fresh, offset-matching request supersedes whatever we were backing
                        // off from -- retry immediately instead of waiting out the old timer.
                        it->second.inBackoff = false;
                        it->second.retryCount = 0;
                        m_scanQueue.push_back(agentId);
                        notifyWorker = true;
                    }

                    LOGFN_DEBUG1(logFn(),
                                 "VD scan already tracked for agent %u, refreshed target offset to %llu",
                                 agentId,
                                 requestedOffset);
                }
                else if (m_agentStates.size() >= m_maxTrackedAgents)
                {
                    rejectedFull = true;
                }
                else
                {
                    AgentScanState state;
                    state.pendingOffset = requestedOffset;
                    m_agentStates.emplace(agentId, state);
                    m_scanQueue.push_back(agentId);
                    notifyWorker = true;
                }
            }

            if (rejectedFull)
            {
                LOGFN_WARN(logFn(),
                           "Scan tracking table full (%zu agents), rejecting scan request for agent %u",
                           m_maxTrackedAgents,
                           agentId);
                incQueueFull(m_metrics);
                remoted::endpoints::scanvd::ScanVdResponse response;
                response.outcome = remoted::endpoints::scanvd::ScanVdOutcome::QueueFull;
                response.currentOffset = currentOffset;
                callback(response);
                return;
            }

            if (notifyWorker)
            {
                m_queueCV.notify_one();
            }

            LOGFN_DEBUG1(logFn(), "VD scan tracked for agent %u with offset %llu", agentId, requestedOffset);
            incAccepted(m_metrics);

            remoted::endpoints::scanvd::ScanVdResponse response;
            response.outcome = remoted::endpoints::scanvd::ScanVdOutcome::Accepted;
            response.currentOffset = currentOffset;
            callback(response);
        }

    private:
        void startWorkerThread()
        {
            const auto poolSize = scanWorkerPoolSize();
            m_workerThreads.reserve(poolSize);
            for (size_t i = 0; i < poolSize; ++i)
            {
                m_workerThreads.emplace_back([this]() { workerLoop(); });
            }
        }

        void stopWorkerThread()
        {
            {
                std::lock_guard<std::mutex> lock(m_queueMutex);
                m_stopping = true;
            }
            // notify_all: every pooled worker is blocked in its own wait_for() and must wake up
            // to observe m_stopping, not just whichever one would otherwise get a queued task.
            m_queueCV.notify_all();

            for (auto& worker : m_workerThreads)
            {
                if (worker.joinable())
                {
                    worker.join();
                }
            }
        }

        void workerLoop()
        {
            LOGFN_INFO(logFn(), "VD scan worker thread started");

            while (true)
            {
                uint32_t agentId = 0;
                bool hasTask = false;

                {
                    std::unique_lock<std::mutex> lock(m_queueMutex);
                    m_queueCV.wait_for(lock,
                                       std::chrono::milliseconds(QUEUE_PROCESS_INTERVAL_MS),
                                       [this]() { return m_stopping || !m_scanQueue.empty(); });

                    if (m_stopping)
                    {
                        LOGFN_INFO(logFn(), "VD scan worker thread stopping (queue size: %zu)", m_scanQueue.size());
                        break;
                    }

                    // Move any agent whose backoff has elapsed back into the ready queue. Doing
                    // this on every wake (every QUEUE_PROCESS_INTERVAL_MS, or sooner if new work
                    // arrives) means a backing-off agent never needs to be popped and re-pushed
                    // just to check "is it due yet" -- which is what previously caused the worker
                    // to busy-spin at full CPU while a retry's backoff elapsed.
                    promoteDueBackoffsLocked();

                    if (!m_scanQueue.empty())
                    {
                        agentId = m_scanQueue.front();
                        m_scanQueue.pop_front();
                        hasTask = true;
                    }
                }

                if (hasTask)
                {
                    processTask(agentId);
                }
            }

            LOGFN_INFO(logFn(), "VD scan worker thread stopped");
        }

        // Must be called while holding m_queueMutex.
        void promoteDueBackoffsLocked()
        {
            const auto now = std::chrono::steady_clock::now();
            for (auto& [agentId, state] : m_agentStates)
            {
                if (state.inBackoff && state.nextRetryTime <= now)
                {
                    state.inBackoff = false;
                    m_scanQueue.push_back(agentId);
                }
            }
        }

        void processTask(uint32_t agentId)
        {
            uint64_t targetOffset = 0;
            {
                std::lock_guard<std::mutex> lock(m_queueMutex);
                auto it = m_agentStates.find(agentId);
                if (it == m_agentStates.end())
                {
                    return; // Defensive: state must exist while an agent is queued/executing.
                }
                targetOffset = it->second.pendingOffset;
            }

            // Re-validate offset at execution time (as per design doc Phase 1.4): the offset may
            // have moved on since this agent was enqueued.
            const uint64_t currentOffset = m_vdClient->getOffset();

            if (targetOffset != currentOffset)
            {
                LOGFN_DEBUG1(logFn(),
                             "Skipping VD scan for agent %u: offset mismatch at execution time "
                             "(requested=%llu, current=%llu). Agent will re-request with new offset.",
                             agentId,
                             targetOffset,
                             currentOffset);
                finishAttempt(agentId, targetOffset, AttemptOutcome::Discard);
                return;
            }

            const auto [success, retryable] = triggerVdScan(agentId, targetOffset);

            if (success)
            {
                LOGFN_DEBUG1(
                    logFn(), "Successfully triggered VD scan for agent %u with offset %llu", agentId, targetOffset);
                finishAttempt(agentId, targetOffset, AttemptOutcome::Success);
                return;
            }

            finishAttempt(
                agentId, targetOffset, retryable ? AttemptOutcome::RetryableFailure : AttemptOutcome::PermanentFailure);
        }

        enum class AttemptOutcome
        {
            Success,
            Discard,
            RetryableFailure,
            PermanentFailure
        };

        // Finalizes one attempt made for `agentId` against `attemptedOffset`. If a newer,
        // offset-matching request arrived for this agent while the attempt was in flight (network
        // call to the VD module, or waiting out the earlier offset-mismatch/backoff window), that
        // request is re-queued immediately instead of being silently superseded by `outcome` --
        // this is the mechanism that guarantees every feed update eventually gets exactly one scan
        // per agent, even when requests race with an attempt that's already running.
        void finishAttempt(uint32_t agentId, uint64_t attemptedOffset, AttemptOutcome outcome)
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            auto it = m_agentStates.find(agentId);
            if (it == m_agentStates.end())
            {
                return;
            }

            if (it->second.pendingOffset != attemptedOffset)
            {
                LOGFN_DEBUG1(logFn(),
                             "Agent %u received a newer offset (%llu) while the scan attempt for offset %llu was "
                             "in flight; re-queueing immediately.",
                             agentId,
                             it->second.pendingOffset,
                             attemptedOffset);
                it->second.retryCount = 0;
                it->second.inBackoff = false;
                m_scanQueue.push_back(agentId);
                return;
            }

            switch (outcome)
            {
                case AttemptOutcome::Success:
                    incScanSucceeded(m_metrics);
                    m_agentStates.erase(it);
                    return;

                case AttemptOutcome::Discard:
                    incScanDiscarded(m_metrics);
                    m_agentStates.erase(it);
                    return;

                case AttemptOutcome::PermanentFailure:
                    LOGFN_WARN(
                        logFn(),
                        "VD scan for agent %u failed with permanent error - not retrying. Agent will retry later.",
                        agentId);
                    incScanPermanentFailure(m_metrics);
                    m_agentStates.erase(it);
                    return;

                case AttemptOutcome::RetryableFailure:
                {
                    if (it->second.retryCount < MAX_RETRIES)
                    {
                        it->second.retryCount++;
                        // Exponential backoff: 1s, 2s, 4s.
                        const auto backoffSeconds = 1 << (it->second.retryCount - 1);
                        it->second.nextRetryTime =
                            std::chrono::steady_clock::now() + std::chrono::seconds(backoffSeconds);
                        it->second.inBackoff = true;
                        incScanRetried(m_metrics);

                        LOGFN_DEBUG1(logFn(),
                                     "Re-queueing VD scan for agent %u (retry %u/%u, backoff: %ds)",
                                     agentId,
                                     it->second.retryCount,
                                     MAX_RETRIES,
                                     backoffSeconds);
                    }
                    else
                    {
                        LOGFN_WARN(
                            logFn(),
                            "VD scan for agent %u failed after %u retries. Agent will retry on next /control notify.",
                            agentId,
                            MAX_RETRIES);
                        incScanRetriesExhausted(m_metrics);
                        m_agentStates.erase(it);
                    }
                    return;
                }
            }
        }

        std::pair<bool, bool> triggerVdScan(uint32_t agentId, uint64_t offset)
        {
            try
            {
                // See vdClient.cpp: httplib::Client's single-string constructor only parses
                // "http(s)://host[:port]" URLs, so a raw socket path needs set_address_family
                // (AF_UNIX) to actually be treated as a Unix domain socket.
                httplib::Client client(m_vdModulesdSocketPath);
                client.set_address_family(AF_UNIX);
                client.set_read_timeout(VD_SCAN_READ_TIMEOUT_SECONDS, 0);
                client.set_write_timeout(VD_SCAN_WRITE_TIMEOUT_SECONDS, 0);

                nlohmann::json requestBody;
                requestBody["agent_id"] = std::to_string(agentId);

                const std::string body = requestBody.dump();

                auto res = client.Post("/vulnerability-detector/scan", body, "application/json");

                if (!res)
                {
                    LOGFN_DEBUG1(logFn(), "Failed to send VD scan request to modulesd for agent %u", agentId);
                    return {false, true}; // Network error - retryable
                }

                if (res->status == 200)
                {
                    return {true, false}; // Success
                }

                // Parse retryable flag from error response
                bool retryable = true; // Default: assume retryable for safety
                try
                {
                    auto errorJson = nlohmann::json::parse(res->body);
                    if (errorJson.contains("retryable") && errorJson["retryable"].is_boolean())
                    {
                        retryable = errorJson["retryable"].get<bool>();
                    }
                }
                catch (...)
                {
                    // Failed to parse JSON - assume retryable
                }

                LOGFN_DEBUG1(logFn(),
                             "VD module returned error for agent %u: status=%d, retryable=%s",
                             agentId,
                             res->status,
                             retryable ? "true" : "false");

                return {false, retryable};
            }
            catch (const std::exception& e)
            {
                LOGFN_DEBUG1(logFn(), "Exception while triggering VD scan for agent %u: %s", agentId, e.what());
                return {false, true}; // Exception - assume retryable
            }
        }

        std::shared_ptr<remoted::common::VdClient> m_vdClient;
        ScanVdMetrics& m_metrics;
        std::string m_vdModulesdSocketPath;
        size_t m_maxTrackedAgents;
        std::atomic<bool> m_stopping;
        std::vector<std::thread> m_workerThreads;
        std::mutex m_queueMutex;
        std::condition_variable m_queueCV;
        std::deque<uint32_t> m_scanQueue;                           // Ready-to-run agent IDs (FIFO).
        std::unordered_map<uint32_t, AgentScanState> m_agentStates; // Per-agent lifecycle + freshest target offset.
    };

    ScanVdHandlerImpl::ScanVdHandlerImpl(std::shared_ptr<remoted::common::VdClient> vdClient,
                                         ScanVdMetrics& metrics,
                                         std::string vdModulesdSocketPath,
                                         size_t maxTrackedAgents)
        : m_impl(
              std::make_unique<Impl>(std::move(vdClient), metrics, std::move(vdModulesdSocketPath), maxTrackedAgents))
    {
    }

    ScanVdHandlerImpl::~ScanVdHandlerImpl() = default;

    void ScanVdHandlerImpl::handleVdScan(uint32_t agentId,
                                         uint64_t requestedOffset,
                                         remoted::endpoints::scanvd::ScanVdCallback callback)
    {
        m_impl->handleVdScan(agentId, requestedOffset, std::move(callback));
    }

} // namespace remoted::scanvd
