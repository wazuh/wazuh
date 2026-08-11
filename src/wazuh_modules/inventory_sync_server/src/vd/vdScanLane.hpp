/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_VD_VD_SCAN_LANE_HPP
#define _INVSYNC_VD_VD_SCAN_LANE_HPP

#include "indexer/IIndexerConnectorSync.hpp"
#include "sync/sessionProcessor.hpp"
#include "sync/syncPipeline.hpp"
#include "vd/IVdScanner.hpp"
#include "vd/agentInFlightRegistry.hpp"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace invsync::vd
{

    struct VdScanLaneConfig
    {
        /// Scan workers. 1 until VD gains real scan parallelism (its global mutex serializes scans
        /// anyway -- REQ-VDQ-7); each worker owns one IndexerConnectorSync.
        std::size_t workers {1};
        /// Short admission queue; full => the strand answers 503 "scan capacity exhausted" (D22).
        /// 0 resolves to 2x workers.
        std::size_t queueSlots {0};
        /// Retry-After attached to the 503 a lane worker answers when the feed became unready
        /// between admission and dispatch (D17 re-check).
        int retryAfterSeconds {60};
    };

    /**
     * @brief The dedicated lane for vulnerability-detection sessions (D22).
     *
     * scan -> (ok or legitimate skip) -> index inventory + flush -> 200. A failed scan answers 500
     * with ZERO inventory documents indexed; the re-POST redoes scan and ingest together (the
     * whole point of the gating: the legacy module indexed even when the scan failed).
     *
     * Sessions ride the same Item shape as the pipeline; the lane keeps its own short bounded
     * queue (bytes already counted by the transport budget) and shares the AgentInFlightRegistry
     * with the pipeline so one agent never has two sessions being applied at once, whichever lane
     * they took.
     */
    class VdScanLane final
    {
    public:
        using Item = sync::SyncPipeline::Item;

        enum class Admission
        {
            Accepted,
            Full,    ///< queue at capacity -> 503 scan capacity
            Stopping ///< shutting down -> 503
        };

        /// @param metrics OPTIONAL registry for the D18 statistics; null falls back to a private
        ///                disconnected manager (branch-free instrumentation, tests unchanged).
        VdScanLane(VdScanLaneConfig config,
                   std::shared_ptr<IVdScanner> scanner,
                   std::vector<std::shared_ptr<indexer::IIndexerConnectorSync>> connectors,
                   std::shared_ptr<AgentInFlightRegistry> registry,
                   std::string managerClusterName,
                   std::shared_ptr<wazuh::metrics::IManager> metrics = nullptr);

        ~VdScanLane();

        VdScanLane(const VdScanLane&) = delete;
        VdScanLane& operator=(const VdScanLane&) = delete;

        /// @brief Admit one VD session. O(1), called from I/O strands.
        Admission tryEnqueue(Item item);

        /**
         * @brief Stop: answer 503 to everything queued and join the workers.
         *
         * A scan ALREADY RUNNING cannot be aborted; it is the caller's responsibility so
         * stop() waits for it (same exposure the legacy module had on its completion thread; the
         * risk window is one scan). Everything not yet dispatched answers 503 immediately.
         * Idempotent.
         */
        void stop();

        std::size_t workerCount() const noexcept
        {
            return m_connectors.size();
        }

    private:
        void workerLoop(std::size_t index);
        void respond(Item& item, int status, const std::string& body);
        void respondConnectorFailure(Item& item, indexer::IIndexerConnectorSync& connector);

        VdScanLaneConfig m_config;
        std::shared_ptr<IVdScanner> m_scanner;
        std::vector<std::shared_ptr<indexer::IIndexerConnectorSync>> m_connectors;
        std::shared_ptr<AgentInFlightRegistry> m_registry;
        /// Declared before m_processor: the processor resolves its counters from it. Never reset.
        std::shared_ptr<wazuh::metrics::IManager> m_metrics;
        sync::SessionProcessor m_processor;

        // D18 instruments, resolved once at construction (see common/metricNames.hpp).
        invsync::metrics::RequestCounters m_requestCounters;
        std::shared_ptr<wazuh::metrics::ICounter> m_capacity503;
        std::shared_ptr<wazuh::metrics::ICounter> m_retryAfterTotal;
        std::shared_ptr<wazuh::metrics::ICounter> m_scansOk;
        std::shared_ptr<wazuh::metrics::ICounter> m_scansFailed;
        std::shared_ptr<wazuh::metrics::ICounter> m_scansSkipped;
        std::shared_ptr<wazuh::metrics::ICounter> m_offsetMismatchTotal;
        std::shared_ptr<wazuh::metrics::IGaugeInt> m_laneDepth;
        std::shared_ptr<wazuh::metrics::IHistogram> m_laneTime;
        std::shared_ptr<wazuh::metrics::IHistogram> m_scanDuration;

        mutable std::mutex m_mutex;   ///< Guards the queue and the in-flight bookkeeping.
        std::condition_variable m_cv; ///< Wakes workers on enqueue/release/stop.
        std::deque<Item> m_queue;
        std::atomic<bool> m_stopping {false};
        std::mutex m_stopMutex;
        bool m_stopped {false};
        std::vector<std::thread> m_workers;
    };

} // namespace invsync::vd

#endif // _INVSYNC_VD_VD_SCAN_LANE_HPP
