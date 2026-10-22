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

// The metrics catalog (stage E5c, plan 18 I100-I104; contract: include/indexer_client/metrics.hpp).

#include "indexer_client/metrics.hpp"

#include <algorithm>
#include <string>
#include <utility>

namespace indexer_client
{
    const char* toString(RejectCause cause) noexcept
    {
        switch (cause)
        {
            case RejectCause::QueueFull: return "queue_full";
            case RejectCause::ClientClosed: return "client_closed";
            case RejectCause::Shutdown: return "shutdown";
            case RejectCause::SubmitTimeout: return "submit_timeout";
            case RejectCause::Reentrancy: return "reentrancy";
            case RejectCause::PayloadTooLarge: return "payload_too_large";
            case RejectCause::GroupTooLarge: return "group_too_large";
            case RejectCause::InvalidArgument: return "invalid_argument";
            default: return "unknown";
        }
    }

    const char* toString(DropCause cause) noexcept
    {
        switch (cause)
        {
            case DropCause::QueueFull: return "queue_full";
            case DropCause::ClientClosed: return "client_closed";
            case DropCause::Shutdown: return "shutdown";
            case DropCause::Cancelled: return "cancelled";
            default: return "unknown";
        }
    }

    const char* toString(FailCause cause) noexcept
    {
        switch (cause)
        {
            case FailCause::ItemPermanent: return "item_permanent";
            case FailCause::RetryExhausted: return "retry_exhausted";
            case FailCause::Client4xx: return "client_4xx";
            case FailCause::Server5xx: return "server_5xx";
            case FailCause::Unavailable: return "unavailable";
            case FailCause::InvalidState: return "invalid_state";
            case FailCause::Ambiguous: return "ambiguous";
            default: return "unknown";
        }
    }

    const char* toString(RetryCause cause) noexcept
    {
        switch (cause)
        {
            case RetryCause::ItemRetryable: return "item_retryable";
            case RetryCause::VersionConflict: return "version_conflict";
            case RetryCause::Server5xx: return "server_5xx";
            case RetryCause::Transport: return "transport";
            case RetryCause::Other: return "other";
            default: return "unknown";
        }
    }

    void LatencyHistogram::observe(std::uint64_t micros) noexcept
    {
        const auto ms = (micros + 999) / 1000; // Rounded up: a sample is in the first bucket whose bound covers it.
        const auto it = std::lower_bound(LATENCY_BOUNDS_MS.begin(), LATENCY_BOUNDS_MS.end(), ms);
        ++counts[static_cast<std::size_t>(it - LATENCY_BOUNDS_MS.begin())];
        sumMicros += micros;
        ++count;
    }

    std::string sanitizeMetricName(std::string_view name)
    {
        std::string out;
        out.reserve(name.size());
        for (const char c : name)
        {
            const auto lower = static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
            const bool keep = (lower >= 'a' && lower <= 'z') || (lower >= '0' && lower <= '9') || lower == '_';
            out.push_back(keep ? lower : '_');
        }
        // Empty, or only separators (e.g. "---"): a single "_".
        return out.find_first_not_of('_') == std::string::npos ? std::string("_") : out;
    }

    namespace
    {
        constexpr auto COUNTER = MetricKind::Counter;
        constexpr auto GAUGE = MetricKind::Gauge;

        /// Emits `<prefix><field>`; the prefix buffer is restored afterwards.
        class Emitter final
        {
        public:
            Emitter(std::string prefix, const MetricVisitor& visitor)
                : m_name(std::move(prefix))
                , m_base(m_name.size())
                , m_visitor(visitor)
            {
            }

            void operator()(std::string_view field, MetricKind kind, double value)
            {
                m_name.resize(m_base);
                m_name.append(field);
                m_visitor(m_name, kind, value);
            }

            void operator()(std::string_view group, std::string_view field, MetricKind kind, double value)
            {
                m_name.resize(m_base);
                m_name.append(group).append(".").append(field);
                m_visitor(m_name, kind, value);
            }

        private:
            std::string m_name;
            std::size_t m_base;
            const MetricVisitor& m_visitor;
        };

        double num(std::uint64_t value) noexcept
        {
            return static_cast<double>(value);
        }

        /// One closed set (metrics.hpp CLOSED SETS): every member, zeros included.
        template<class E, std::size_t N>
        void emitSet(Emitter& emit, std::string_view group, const std::array<std::uint64_t, N>& values)
        {
            static_assert(N == static_cast<std::size_t>(E::Count), "one slot per member");
            for (std::size_t i = 0; i < N; ++i)
            {
                emit(group, toString(static_cast<E>(i)), COUNTER, num(values[i]));
            }
        }

        /// The cumulative histogram (metrics.hpp LATENCY): latency.le_<ms> … le_inf, sum_micros, count.
        void emitLatency(Emitter& emit, const LatencyHistogram& histogram)
        {
            std::uint64_t cumulative = 0;
            std::string field;
            for (std::size_t i = 0; i < LATENCY_BOUNDS_MS.size(); ++i)
            {
                cumulative += histogram.counts[i];
                field = "le_" + std::to_string(LATENCY_BOUNDS_MS[i]);
                emit("latency", field, COUNTER, num(cumulative));
            }
            cumulative += histogram.counts[LATENCY_BOUNDS_MS.size()];
            emit("latency", "le_inf", COUNTER, num(cumulative));
            emit("latency", "sum_micros", COUNTER, num(histogram.sumMicros));
            emit("latency", "count", COUNTER, num(histogram.count));
        }

        double nodeState(HealthView::NodeState state) noexcept
        {
            switch (state)
            {
                case HealthView::NodeState::Available: return 0;
                case HealthView::NodeState::Throttled: return 1;
                case HealthView::NodeState::Down:
                default: return 2;
            }
        }
    } // namespace

    void forEachMetric(const ClientMetrics& metrics, const MetricVisitor& visitor)
    {
        if (!visitor || metrics.consumer.empty())
        {
            return; // An empty or moved-from client (N27) has no names.
        }
        const auto consumer = sanitizeMetricName(metrics.consumer);
        for (const auto& bucket : metrics.buckets)
        {
            Emitter emit("indexer_client.bucket." + consumer + "." + sanitizeMetricName(bucket.bucket) + ".", visitor);
            emit("accepted", COUNTER, num(bucket.accepted));
            emitSet<RejectCause>(emit, "rejected", bucket.rejected);
            emitSet<DropCause>(emit, "dropped", bucket.dropped);
            emit("ok", COUNTER, num(bucket.ok));
            emitSet<FailCause>(emit, "failed", bucket.failed);
            emitSet<RetryCause>(emit, "retries", bucket.retries);
            emit("late_results", COUNTER, num(bucket.lateResults));
            emit("retained_bytes", GAUGE, num(bucket.retainedBytes));
            emit("charge_bytes", GAUGE, num(bucket.charge));
            emit("quota_bytes", GAUGE, num(bucket.quotaBytes));
            emit("bulk_requests", COUNTER, num(bucket.bulkRequests));
            emit("bulk_bytes", COUNTER, num(bucket.bulkBytes));
            emitLatency(emit, bucket.latency);
        }
        Emitter emit("indexer_client.client." + consumer + ".", visitor);
        emit("callbacks_skipped", COUNTER, num(metrics.callbacksSkipped));
        emit("callback_overruns", COUNTER, num(metrics.callbackOverruns));
        emit("callback_max_duration_ms", GAUGE, num(metrics.callbackMaxDurationMs));
    }

    void forEachMetric(const MetricsSnapshot& snapshot, const MetricVisitor& visitor)
    {
        if (!visitor)
        {
            return;
        }
        {
            Emitter emit("indexer_client.runtime.", visitor);
            emit("network_threads", GAUGE, num(snapshot.networkThreads));
            emit("cpu_threads", GAUGE, num(snapshot.cpuThreads));
            emit("clients", GAUGE, num(snapshot.clients));
            emit("global_charge_bytes", GAUGE, num(snapshot.globalCharge));
            emit("global_quota_bytes", GAUGE, num(snapshot.globalQuotaBytes));
            emit("retained_bytes", GAUGE, num(snapshot.retainedBytes));
            emit("usage_errors", COUNTER, num(snapshot.usageErrors));
        }
        {
            const auto& q = snapshot.queries;
            Emitter emit("indexer_client.query.", visitor);
            emit("requests", COUNTER, num(q.requests));
            emit("failovers", COUNTER, num(q.failovers));
            emit("throttles", COUNTER, num(q.throttles));
            emit("unavailable", COUNTER, num(q.unavailable));
            emit("too_large", COUNTER, num(q.tooLarge));
            emit("conflict_retries", COUNTER, num(q.conflictRetries));
            emit("response_bytes_in_flight", GAUGE, num(q.responseBytesInFlight));
            emit("peak_response_bytes_in_flight", GAUGE, num(q.peakResponseBytesInFlight));
        }
        {
            const auto& p = snapshot.pit;
            Emitter emit("indexer_client.pit.", visitor);
            emit("open", GAUGE, num(p.open));
            emit("reserved", GAUGE, num(p.reserved));
            emit("deletes_pending", GAUGE, num(p.deletesPending));
            emit("created", COUNTER, num(p.created));
            emit("deletes_confirmed", COUNTER, num(p.deletesConfirmed));
            emit("deletes_expired", COUNTER, num(p.deletesExpired));
            emit("delete_retries", COUNTER, num(p.deleteRetries));
            emit("expired", COUNTER, num(p.expired));
            emit("stale", COUNTER, num(p.stale));
            emit("refused_full", COUNTER, num(p.refusedFull));
        }
        for (std::size_t i = 0; i < snapshot.nodes.size(); ++i)
        {
            const auto& n = snapshot.nodes[i];
            Emitter emit("indexer_client.node." + std::to_string(i) + ".", visitor);
            emit("state", GAUGE, nodeState(n.state));
            emit("transitions", COUNTER, num(n.transitions));
            emit("window", GAUGE, n.window);
            emit("bulk_target_bytes", GAUGE, num(n.bulkTarget));
            emit("pace_ms", GAUGE, num(n.paceMs));
            emit("requests", COUNTER, num(n.requests));
            emit("throttled", COUNTER, num(n.throttled));
            emit("server_5xx", COUNTER, num(n.server5xx));
            emit("failures", COUNTER, num(n.failures));
            emit("decreases", "429", COUNTER, num(n.decreases429));
            emit("decreases", "throttled", COUNTER, num(n.decreasesThrottled));
            emit("decreases", "latency", COUNTER, num(n.decreasesLatency));
            emitLatency(emit, n.latency);
        }
    }
} // namespace indexer_client
