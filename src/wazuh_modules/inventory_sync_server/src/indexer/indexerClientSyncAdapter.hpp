/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_INDEXER_CLIENT_SYNC_ADAPTER_HPP
#define _INVSYNC_INDEXER_CLIENT_SYNC_ADAPTER_HPP

#include "IIndexerConnectorSync.hpp"
#include "inventory_sync_server.h"

#include "indexer_client/chunking.hpp"
#include "indexer_client/client.hpp"
#include "indexer_client/runtime.hpp"
#include "indexer_client/types.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace invsync::indexer
{

    /// The consumer name invsync registers with the process runtime, and its two buckets (I148).
    constexpr auto INDEXER_CLIENT_CONSUMER {"inventory_sync_server"};
    constexpr auto INVENTORY_BUCKET {"inventory"};
    constexpr auto AGENT_STATE_BUCKET {"agent-state"};

    /// Bytes the library charges per operation besides its payload (`IC/src/write/bucket.hpp` RESULT_RESERVE).
    constexpr std::size_t RESULT_RESERVE_BYTES {2048};

    /**
     * @brief `retry_on_conflict` of a versioned sync value's scripted `update` (5.0.0 #41191).
     *
     * The update writes with the seq_no it read the document at, so a concurrent `_update_by_query` of the same
     * agent (a group or metadata session applied by another manager node) makes the item answer 409 and drop its
     * data. With it the indexer re-reads the document and re-runs the script; a 409 that still comes back is retried
     * on the bucket's retry lane and, once that budget runs out, fails the session (`RetryExhausted`), so the agent
     * sends it again instead of getting a 200 for data the index does not hold. Only the versioned upsert carries it:
     * `index` and `delete` keep the bucket's `Success` policy for a 409.
     */
    constexpr std::uint32_t UPDATE_RETRY_ON_CONFLICT {5};

    /**
     * @brief Time budgets of the adapter's calls (I145, I145b).
     *
     * `stateful` bounds a `/stateful` batch (from its first add) and each query of an Immediate
     * session: it stays under remoted's 20 s response window. `deletion` bounds the by-query of a
     * whole-agent deletion, whose caller waits up to 600 s.
     */
    struct Budgets
    {
        std::chrono::milliseconds stateful {18000};
        std::chrono::milliseconds deletion {70000};
        std::chrono::milliseconds statefulRetry {15000}; ///< `maxDuration` of writes and Immediate queries.
        std::chrono::milliseconds deletionRetry {15000}; ///< `maxDuration` of the deletion's by-query.
    };

    /**
     * @brief Budgets from the module's retry options (I145, I145b).
     *
     * With d = `indexer_sync_max_retry_duration_seconds` (0 = no bound, < 0 = default 15 s):
     * stateful = clamp(d + 3 s, 5 s, 18 s) (18 s when d = 0); deletion = min(3·d + 25 s, 540 s)
     * (70 s when d = 0); each retry duration = min(d or 15 s, its budget − 3 s).
     */
    Budgets budgets(const inventory_sync_server_config_t& config);

    /**
     * @brief The `inventory` bucket (I138, I137b, I142b, I145b).
     *
     * quotaBytes = clamp(max(64 MiB, bulk.maxBytes + RESULT_RESERVE_BYTES + 1 MiB), <= quotaBudget); when even
     * the budget cannot hold one bulk, bulk.maxBytes is clipped to fit and `warning` says so. bulk.maxBytes =
     * `indexer_sync_connector_max_bulk_size` (<= 0 -> 10 MiB, the v1 default); retry.maxAttempts =
     * `indexer_sync_max_retry_attempts` (0 -> unlimited, < 0 -> 5); retry.maxDuration = Budgets::statefulRetry;
     * retry.cap = `indexer_sync_max_retry_delay_seconds` (<= 0 -> 15 s); overflow Block with `blockTimeout`; 409
     * Success; ambiguous 5xx Retry (I105); not ordered.
     *
     * @param config Module configuration.
     * @param quotaBudget What the runtime's `global_quota_bytes` leaves once `agent-state` took its quota (I149c):
     *                    `snapshot().globalQuotaBytes − agentStateBucketSpec(...).quotaBytes`.
     * @param blockTimeout How long an add may wait for quota (2 s in production).
     * @param warning Set when bulk.maxBytes had to be clipped; may be null.
     */
    indexer_client::BucketSpec inventoryBucketSpec(const inventory_sync_server_config_t& config,
                                                   std::uint64_t quotaBudget,
                                                   std::chrono::milliseconds blockTimeout,
                                                   std::string* warning = nullptr);

    /**
     * @brief The `agent-state` bucket of POST /stats, POST /config and the deletion's by-id deletes (I148, I149,
     *        I149b, I149c).
     *
     * ordered; overflow Reject (503 to the agent); ambiguous 5xx Retry; 409 Success; retry without an attempt or a
     * duration bound (the v1 async queue buffered through outages too; the quota bounds it), cap =
     * `indexer_async_max_retry_delay_seconds` (<= 0 -> 15 s). bulk.maxBytes = `indexer_async_bulk_max_bytes`
     * (<= 0 -> 4 MiB). quotaBytes = min(max(requested, bulk + 6 KiB, 16 KiB), top) with requested =
     * `indexer_async_max_queue_bytes` (0 -> global / 4) and top = max(global / 4, min(16 KiB, global / 2)): the
     * floor lets the two deletes of a deletion share one Group; the top leaves `inventory` the rest. When the bulk
     * does not fit it is clipped to quota − 6 KiB (or quota / 2) and `warning` says so; a capped request warns too.
     * Valid for every option value with a global quota of 8 KiB or more.
     */
    indexer_client::BucketSpec agentStateBucketSpec(const inventory_sync_server_config_t& config,
                                                    std::uint64_t globalQuotaBytes,
                                                    std::string* warning = nullptr);

    /// Per-worker chunk cap: 0.8 · quota / (2 · lanes), lanes = pipeline + scan-lane workers (I137b, I145); shared
    /// with VD in indexer_client/chunking.hpp (D88).
    using indexer_client::chunkCap;

    /// The seam's class of a library cause (I135); every indexer_client::Cause maps to exactly one.
    ConnectorError::Cause translateCause(indexer_client::Cause cause);

    struct AdapterOptions
    {
        std::size_t capBytes {0};                       ///< chunkCap(); > 0.
        std::chrono::milliseconds blockSlice {250};     ///< Granularity of every wait (closing, deadline).
        Budgets budgets;                                ///< Deadlines and query retry durations.
        indexer_client::RetryPolicy queryRetry;         ///< Base query policy; maxDuration set per call.
        std::chrono::milliseconds pageDeadline {30000}; ///< QueryOptions::pageDeadline of each query.
        /// The process runtime: settleAbandoned() takes its bound from snapshot().requestTimeout and gives up
        /// once shutdownDeadline() is set. An invalid reference (tests) means the default request timeout.
        indexer_client::RuntimeRef runtime;
    };

    /**
     * @brief IIndexerConnectorSync over indexer_client (E7b): one adapter per pipeline or scan-lane worker,
     *        all sharing one Client and its `inventory` bucket.
     *
     * Staging adds to an open Group; a chunk is committed before the add that would pass `capBytes`; at most one
     * committed-or-abandoned chunk is unresolved per adapter besides the open one, and its results are harvested
     * (ticket and Group dropped) before the next commit (I137b, I145). Two operations with the same (index, _id) are
     * never unresolved at once (I139). An add refused by the library marks its session failed without throwing
     * (I142). A batch's deadline starts at its first add; past it, or with `closing` set, the unresolved chunk is
     * cancelled by tag without waiting and its sessions fail Unavailable (I142b, I145, I145b). By-query, update and
     * search calls first wait for every pending write (D49). isAvailable() = health().anyUsable() (I52-e).
     *
     * Not thread-safe: each instance is driven by its one worker thread.
     */
    class IndexerClientSyncAdapter final : public IIndexerConnectorSync
    {
    public:
        /**
         * @param client The consumer's Client; writer(INVENTORY_BUCKET) and query() are taken here, once (I141b).
         * @param options Cap, slices, budgets.
         * @param closing Set by the module's stop() before requestClose(); every wait returns when it flips.
         * @param tag This worker's cancellation tag (`w<i>` / `vd<i>`).
         * @throws std::runtime_error if the client hands out no writer or no query (closed, or no such bucket).
         */
        IndexerClientSyncAdapter(std::shared_ptr<indexer_client::IClient> client,
                                 AdapterOptions options,
                                 std::shared_ptr<const std::atomic<bool>> closing,
                                 std::string tag);
        ~IndexerClientSyncAdapter() override;

        bool isAvailable() const override;
        void bulkIndex(std::string_view id, std::string_view index, std::string_view data) override;
        void bulkIndex(std::string_view id,
                       std::string_view index,
                       std::string_view data,
                       std::string_view version) override;
        void bulkDelete(std::string_view id, std::string_view index) override;
        void
        deleteByQuery(const std::string& index, const std::string& agentId, const std::string& clusterName) override;
        void deleteAgentByQuery(const std::string& index,
                                const std::string& agentId,
                                const std::string& clusterName) override;
        void executeUpdateByQuery(const std::vector<std::string>& indices, const nlohmann::json& updateQuery) override;
        nlohmann::json executeSearchQuery(const std::string& index, const nlohmann::json& searchQuery) override;
        void flush() override;
        void endSession() override;
        std::vector<SessionOutcome> flushSessions(std::size_t sessions) override;
        void discard() override;
        /// Waits for the abandoned chunk, if any, up to the runtime's request timeout + 5 s (one request at most:
        /// a cancelled op is never sent again), watching `closing` and the runtime's shutdown every blockSlice.
        /// Still unresolved past that, the chunk stays pending (its keys keep their barrier).
        AbandonedWrite settleAbandoned() override;
        /// True while an abandoned chunk's ticket is not ready and `closing` is unset.
        bool holdsAbandonedWrite() override;

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_CLIENT_SYNC_ADAPTER_HPP
