/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 4, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_SYNC_SYNC_PIPELINE_HPP
#define _INVSYNC_SYNC_SYNC_PIPELINE_HPP

#include "common/metricNames.hpp"
#include "http_server/IUdsHttpServer.hpp"
#include "indexer/IIndexerConnectorSync.hpp"
#include "sync/fullSessionValidator.hpp"
#include "sync/sessionProcessor.hpp"
#include "vd/agentInFlightRegistry.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace invsync::sync
{

    struct SyncPipelineConfig
    {
        /// Early-rejection cap on payload bytes sitting in the pipeline's queues; enqueue() refuses
        /// over it (the endpoint answers 503). The memory itself is already bounded by the
        /// transport's in-flight budget -- this sheds earlier so other routes keep admitting.
        std::size_t maxQueueBytes {64U * 1024U * 1024U};
        /// Group-commit threshold: a worker flushes its open batch when the staged payload bytes
        /// reach this (mirrors the connector's own max_bulk_size) or when its queue drains.
        std::size_t bulkFlushBytes {10U * 1024U * 1024U};
    };

    /**
     * @brief The ingestion pipeline behind POST /stateful: workers sharded by agent id.
     *
     * One worker (and ONE IndexerConnectorSync, private to it) per shard; a session lands on
     * `hash(agentId) % workers`, which makes per-agent ordering a property of the topology instead
     * of a lock: two requests of the same agent -- a Cleans and the SyncData that re-populates it,
     * a delta and its checksum -- are applied in arrival order because they traverse the same
     * FIFO. The private connector is what retires the legacy module's shared-connector machinery
     * (global notify, stale flags, cross-thread scopeLock) from this path entirely.
     *
     * Workers GROUP-COMMIT (design doc 03 §7): bulk sessions stage and their responses wait; the
     * flush happens when the staged bytes reach `bulkFlushBytes` or the shard's queue drains, and
     * only then is the whole batch answered. Under low load the queue is empty after every session
     * (flush-per-request latency); under a burst of small sessions the bulks grow on their own and
     * the indexer sees a few large requests instead of a thousand tiny ones.
     */
    class SyncPipeline final
    {
    public:
        /// One queued request. Holding the HttpRequest keeps the FlatBuffer the ValidatedSession
        /// points into alive -- and with it the transport's in-flight byte reservation.
        struct Item
        {
            /// What this item asks the worker to do. DeleteAgent (DELETE /agents) rides the same
            /// shard queue as the agent's sessions ON PURPOSE: the deletion orders FIFO against any
            /// in-flight session of that agent instead of racing it (design doc 04 §1) -- the
            /// legacy module's delete competed for a lock with no ordering at all.
            enum class Kind
            {
                Session,
                DeleteAgent
            };

            std::shared_ptr<const http::HttpRequest> request;
            std::shared_ptr<http::IHttpResponder> responder;
            /// For DeleteAgent only `session.agentId` is meaningful (sharding, registry, deletion
            /// scope); the FlatBuffer pointer stays null.
            ValidatedSession session;
            Kind kind {Kind::Session};
            /// Stamped by the endpoint at enqueue; respond() observes the elapsed time into the
            /// session-duration histograms (D18). Epoch (default) means "not stamped": no sample.
            std::chrono::steady_clock::time_point enqueuedAt {};
        };

        /**
         * @param config     Tunables (queue cap, flush threshold).
         * @param connectors One connector PER WORKER; the vector's size is the worker count.
         *                   All share one IndexerSession; each is owned (and staged into) by
         *                   exactly one worker thread.
         * @param managerClusterName Cluster scope for queries and document ids.
         * @param registry   OPTIONAL cross-lane per-agent exclusion (D22): when set, a worker
         *                   skips (leaves queued) items of an agent the VD scan lane is applying,
         *                   holding each dispatched item's agent until its response. Null keeps
         *                   the standalone behavior. The registry must OUTLIVE this pipeline (the
         *                   facade resets it last).
         * @param metrics    OPTIONAL registry for the D18 statistics. Null falls back to a private
         *                   disconnected manager, so the instrumentation stays branch-free and the
         *                   existing tests need no change.
         */
        SyncPipeline(SyncPipelineConfig config,
                     std::vector<std::shared_ptr<indexer::IIndexerConnectorSync>> connectors,
                     std::string managerClusterName,
                     std::shared_ptr<vd::AgentInFlightRegistry> registry = nullptr,
                     std::shared_ptr<wazuh::metrics::IManager> metrics = nullptr);

        ~SyncPipeline();

        SyncPipeline(const SyncPipeline&) = delete;
        SyncPipeline& operator=(const SyncPipeline&) = delete;

        /**
         * @brief Queue a validated session for its agent's shard. Called from I/O strands; O(1).
         *
         * @return false when the pipeline is stopping or the queue byte cap is exceeded -- the
         *         caller answers 503 (the item is NOT consumed).
         */
        bool enqueue(Item item);

        /**
         * @brief Stop the workers and answer 503 to everything still queued.
         *
         * Called between the transport's stopAccepting() (so responders still deliver) and the
         * connector teardown (so no worker touches a dead connector). A worker finishes the
         * session it is on; an OPEN batch is answered 503 WITHOUT flushing -- shutdown must not
         * wait on indexer I/O, and the agents re-POST on their next cycle (the same restart
         * semantics RF-13 already prescribes). Idempotent.
         */
        void stop();

        std::size_t workerCount() const noexcept
        {
            return m_shards.size();
        }

    private:
        struct Shard
        {
            std::mutex mutex;
            std::condition_variable cv;
            std::deque<Item> queue;
        };

        void workerLoop(std::size_t index);
        /// Sends the response AND releases the item's agent from the registry (a release of a
        /// never-acquired agent is a harmless no-op, so the stop() drain path may share this).
        void respond(Item& item, int status, const std::string& body);
        /// Pops the first queued item whose agent the registry lets this lane take (front, when
        /// no registry). Returns false when nothing is dispatchable RIGHT NOW.
        bool popDispatchable(Shard& shard, Item& item);
        /// 503 when the worker's connector reports unavailable (retriable), 500 otherwise.
        void respondConnectorFailure(std::vector<Item>& items, indexer::IIndexerConnectorSync& connector);
        void
        flushAndRespond(std::vector<Item>& batch, std::size_t& batchBytes, indexer::IIndexerConnectorSync& connector);

        SyncPipelineConfig m_config;
        /// Declared before m_processor: the processor resolves its counters from it. Never reset.
        std::shared_ptr<wazuh::metrics::IManager> m_metrics;
        SessionProcessor m_processor;
        std::shared_ptr<vd::AgentInFlightRegistry> m_registry;
        std::vector<std::shared_ptr<indexer::IIndexerConnectorSync>> m_connectors;
        std::vector<std::unique_ptr<Shard>> m_shards;
        std::vector<std::thread> m_workers;

        // D18 instruments, resolved once at construction (see common/metricNames.hpp).
        invsync::metrics::RequestCounters m_requestCounters;
        std::shared_ptr<wazuh::metrics::ICounter> m_shedTotal;
        std::shared_ptr<wazuh::metrics::ICounter> m_bulkFlushes;
        std::shared_ptr<wazuh::metrics::ICounter> m_bulkBytesTotal;
        std::shared_ptr<wazuh::metrics::ICounter> m_bulkSessionsTotal;
        std::shared_ptr<wazuh::metrics::IHistogram> m_durationBulk;
        std::shared_ptr<wazuh::metrics::IHistogram> m_durationImmediate;
        /// One pair per shard. GAUGES the workers update, not pull metrics: a pull would capture
        /// a `this` that dies in stop() while the manager persists (there is no remove()).
        std::vector<std::shared_ptr<wazuh::metrics::IGaugeInt>> m_shardDepth;
        std::vector<std::shared_ptr<wazuh::metrics::IGaugeInt>> m_shardBytes;
        std::atomic<std::size_t> m_queuedBytes {0};
        std::atomic<bool> m_stopping {false};
        std::mutex m_stopMutex; ///< Serializes stop() against itself (facade + destructor).
        bool m_stopped {false};
    };

} // namespace invsync::sync

#endif // _INVSYNC_SYNC_SYNC_PIPELINE_HPP
