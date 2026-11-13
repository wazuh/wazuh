/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_METRICS_HPP
#define _INDEXER_CLIENT_METRICS_HPP

// Metrics of the indexer client. NORMATIVE.
//
// SCOPE. Client::metrics() returns the buckets of that consumer (ClientMetrics); RuntimeRef::snapshot() returns
// the runtime, the nodes, the queries and the PITs (MetricsSnapshot) and no bucket. Neither blocks the hot path: they
// read under the leaf mutexes the counters already live under, with no I/O. Lifetimes: buckets and nodes belong to the
// runtime; QueryMetrics, PitMetrics and usageErrors are process-wide and never reset (one runtime per process in
// production).
//
// CLOSED SETS. Every per-cause array below is indexed by its enum; forEachMetric emits every member, zeros included.
//   RejectCause  queue_full, client_closed, shutdown, submit_timeout, reentrancy, payload_too_large, group_too_large,
//                invalid_argument (Submit refusals and group adds).
//   DropCause    queue_full (DropNewest + DropOldest), client_closed, shutdown, cancelled.
//   FailCause    item_permanent, retry_exhausted, client_4xx, server_5xx, unavailable, invalid_state, ambiguous (a
//                bulk answered 500/502/504, or whose response went over max_response_bytes, in a bucket with
//                onAmbiguous5xx = Fail).
//   RetryCause   item_retryable, version_conflict, server_5xx, transport, other (ops requeued with a counted attempt,
//                counted per op in Bucket::requeue from the op's last error).
//
// LATENCY. LatencyHistogram keeps per-bucket counts: counts[i] counts samples with ms <= LATENCY_BOUNDS_MS[i]
// and > the previous bound (counts[0]: ms <= 1); counts[16] counts the rest (inf). forEachMetric publishes them
// CUMULATIVE: <prefix>.latency.le_1 … le_32768, le_inf, sum_micros, count. A sample is the HttpResult timings.total of
// a bulk response with an HTTP answer.
//
// LATE RESULTS. lateResults counts the ops of a completion WITH an HTTP answer (Items / FailBatch verdicts) whose
// resolution lost first-wins (WritePath::resolve returned false) or came back closed from Bucket::requeue. Ignore
// verdicts (Cancelled, Shutdown) never count.
//
// QUERIES. responseBytesInFlight = Σ body bytes of query HttpResults delivered to the query engine and not yet
// returned to the consumer (classification + DOM); peakResponseBytesInFlight is its process-wide maximum. There is no
// global charge for them: the gauge makes the memory that reads hold observable.
//
// CATALOG. forEachMetric(m, visitor) calls visitor(name, kind, value) once per metric. Names are lowercase,
// dotted, without labels (.claude/docs/metrics.md):
//   indexer_client.bucket.<consumer>.<bucket>.<field>   (BucketMetrics of ClientMetrics)
//   indexer_client.client.<consumer>.<field>            (ClientMetrics)
//   indexer_client.node.<i>.<field>                     (<i> = position of the node in <indexer><hosts>)
//   indexer_client.runtime.<field>, indexer_client.query.<field>, indexer_client.pit.<field>
// <consumer> and <bucket> are sanitized: lowercase, every character outside [a-z0-9_] becomes '_', and a result that is
// empty or only '_' (e.g. "---") becomes "_". RuntimeRef::client() refuses (InvalidArgument, naming the field) a
// consumer whose sanitized name equals another live consumer's, or two buckets of one client with the same sanitized
// name. The set of names is dense (every member of every closed set, zeros included) and fixed for the life of the
// runtime (buckets from RuntimeRef::client(), nodes from start()): adapters register their pull metrics once. Values
// are doubles (byte counters cast from uint64). NodeMetrics::state is published as 0 = Available, 1 = Throttled,
// 2 = Down.
//
// BULK. bulkRequests counts every bulk completion of the bucket, whatever its outcome; bulkBytes adds the body bytes of
// each of those requests, i.e. the bytes handed to the sender: an operation sent again (a retry, a failover, or each
// half of a 413 Split) counts again, so bulkBytes is not the payload accepted.

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "types.hpp"

namespace indexer_client
{
    enum class RejectCause : std::uint8_t
    {
        QueueFull,
        ClientClosed,
        Shutdown,
        SubmitTimeout,
        Reentrancy,
        PayloadTooLarge,
        GroupTooLarge,
        InvalidArgument,
        Count
    };

    enum class DropCause : std::uint8_t
    {
        QueueFull,
        ClientClosed,
        Shutdown,
        Cancelled,
        Count
    };

    enum class FailCause : std::uint8_t
    {
        ItemPermanent,
        RetryExhausted,
        Client4xx,
        Server5xx,
        Unavailable,
        InvalidState,
        Ambiguous,
        Count
    };

    enum class RetryCause : std::uint8_t
    {
        ItemRetryable,
        VersionConflict,
        Server5xx,
        Transport,
        Other,
        Count
    };

    INDEXER_CLIENT_API const char* toString(RejectCause cause) noexcept;
    INDEXER_CLIENT_API const char* toString(DropCause cause) noexcept;
    INDEXER_CLIENT_API const char* toString(FailCause cause) noexcept;
    INDEXER_CLIENT_API const char* toString(RetryCause cause) noexcept;

    /// Upper bounds of the latency buckets, in milliseconds (the 17th bucket is inf).
    inline constexpr std::array<std::uint32_t, 16> LATENCY_BOUNDS_MS {
        1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768};

    struct INDEXER_CLIENT_API LatencyHistogram final
    {
        std::array<std::uint64_t, 17> counts {}; ///< Per bucket (not cumulative); [16] = inf.
        std::uint64_t sumMicros {0};
        std::uint64_t count {0};

        /// Adds one sample (the bucket whose bound is the first >= the sample in ms, rounded up).
        void observe(std::uint64_t micros) noexcept;
    };

    struct BucketMetrics final
    {
        std::string consumer;
        std::string bucket;
        std::uint64_t accepted {0};
        std::array<std::uint64_t, static_cast<std::size_t>(RejectCause::Count)> rejected {};
        std::array<std::uint64_t, static_cast<std::size_t>(DropCause::Count)> dropped {};
        std::uint64_t ok {0};
        std::array<std::uint64_t, static_cast<std::size_t>(FailCause::Count)> failed {};
        std::array<std::uint64_t, static_cast<std::size_t>(RetryCause::Count)> retries {};
        std::uint64_t lateResults {0};
        std::uint64_t retainedBytes {0}; ///< Payload charged: pending + retry lane + delivered (consumers' queue size).
        std::uint64_t charge {0};        ///< Everything charged: payload + result reserves + building groups.
        std::uint64_t quotaBytes {0};
        std::uint64_t bulkRequests {0};
        std::uint64_t bulkBytes {0}; ///< Bytes handed to the sender (resends and Split halves count again; BULK).
        LatencyHistogram latency;
    };

    struct ClientMetrics final
    {
        std::string consumer;
        std::vector<BucketMetrics> buckets;
        std::uint64_t callbacksSkipped {0};
        std::uint64_t callbackOverruns {0};
        std::uint64_t callbackMaxDurationMs {0};
    };

    struct NodeMetrics final
    {
        std::string host;
        HealthView::NodeState state {HealthView::NodeState::Down};
        std::uint64_t transitions {0};
        double window {0};
        std::uint64_t bulkTarget {0};
        std::uint64_t paceMs {0};
        std::uint64_t requests {0};
        std::uint64_t throttled {0};
        std::uint64_t server5xx {0};
        std::uint64_t failures {0};
        std::uint64_t decreases429 {0};
        std::uint64_t decreasesThrottled {0};
        std::uint64_t decreasesLatency {0};
        LatencyHistogram latency;
    };

    struct QueryMetrics final
    {
        std::uint64_t requests {0}; ///< Attempts sent (queryStats()).
        std::uint64_t failovers {0};
        std::uint64_t throttles {0};
        std::uint64_t unavailable {0};
        std::uint64_t tooLarge {0};
        std::uint64_t conflictRetries {0};
        std::uint64_t responseBytesInFlight {0};
        std::uint64_t peakResponseBytesInFlight {0};
    };

    struct PitMetrics final
    {
        std::uint64_t open {0};
        std::uint64_t reserved {0};
        std::uint64_t deletesPending {0};
        std::uint64_t created {0};
        std::uint64_t deletesConfirmed {0};
        std::uint64_t deletesExpired {0};
        std::uint64_t deleteRetries {0};
        std::uint64_t expired {0};
        std::uint64_t stale {0};
        std::uint64_t refusedFull {0};
    };

    /// Snapshot of the runtime. The first three fields are the runtime's thread and client counts.
    struct MetricsSnapshot final
    {
        std::uint32_t networkThreads {0};
        std::uint32_t cpuThreads {0};
        std::uint32_t clients {0};
        std::uint64_t globalCharge {0};
        std::uint64_t globalQuotaBytes {0};
        std::uint64_t retainedBytes {0};
        QueryMetrics queries;
        PitMetrics pit;
        std::vector<NodeMetrics> nodes;
        std::uint64_t usageErrors {0};
        /// The runtime's `request_timeout_ms`, echoed so a consumer can size waits that must outlast one request.
        Duration requestTimeout {0};
    };

    enum class MetricKind : std::uint8_t
    {
        Counter,
        Gauge
    };

    using MetricVisitor = std::function<void(std::string_view name, MetricKind kind, double value)>;

    /// The catalog: every metric of a client's buckets and its callback counters.
    INDEXER_CLIENT_API void forEachMetric(const ClientMetrics& metrics, const MetricVisitor& visitor);
    /// The catalog: the runtime, its nodes, the queries and the PITs.
    INDEXER_CLIENT_API void forEachMetric(const MetricsSnapshot& snapshot, const MetricVisitor& visitor);
    /// The sanitized form of a consumer or bucket name in the catalog.
    INDEXER_CLIENT_API std::string sanitizeMetricName(std::string_view name);
} // namespace indexer_client

#endif // _INDEXER_CLIENT_METRICS_HPP
