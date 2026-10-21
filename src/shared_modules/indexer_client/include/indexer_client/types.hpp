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

#ifndef _INDEXER_CLIENT_TYPES_HPP
#define _INDEXER_CLIENT_TYPES_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "json.hpp"

#if defined(__GNUC__) || defined(__clang__)
#define INDEXER_CLIENT_API __attribute__((visibility("default")))
#else
#define INDEXER_CLIENT_API
#endif

namespace indexer_client
{
    using Duration = std::chrono::milliseconds;
    using TimePoint = std::chrono::steady_clock::time_point;
    /// Absolute point in time after which a wait gives up.
    using Deadline = TimePoint;

    /// Empty value for operations that only report success or failure.
    struct Unit final
    {
    };

    /// Process that owns the runtime; selects the internal-options family (`<process>.indexer_client_*`).
    enum class ProcessId
    {
        Analysisd,
        Modulesd,
        Standalone
    };

    /// Final status of an operation (RF-6).
    enum class Status
    {
        Ok,
        Failed,
        Dropped
    };

    /// Single classification of every failure (RF-9) and of every API-level refusal.
    enum class Cause
    {
        None,
        TransportTimeout,
        TransportConnect,
        TransportTls,
        Throttled,
        PayloadTooLarge,
        Server5xx,
        Client4xx,
        ItemRetryable,
        ItemPermanent,
        VersionConflict,
        Unavailable,
        QueueFull,
        SubmitTimeout,
        WaitTimeout,
        GroupTooLarge,
        RetryExhausted,
        Shutdown,
        ClientClosed,
        Cancelled,
        Reentrancy,
        PitExpired,
        PitStaleGeneration,
        NotFound,
        InvalidConfig,
        InvalidArgument,
        InvalidState,
        UsageError
    };

    /// Stable, lowercase name of a cause (logs, metrics labels and test diagnostics).
    INDEXER_CLIENT_API const char* toString(Cause cause) noexcept;

    /// Per-item outcome of a write (RF-28).
    enum class ItemOutcome
    {
        None,
        Created,
        Updated,
        Noop,
        Deleted,
        NotFound
    };

    /// Value or failure. `ok()` is true only when `cause == Cause::None`.
    template<class T>
    struct Outcome final
    {
        T value {};
        Cause cause {Cause::None};
        int httpStatus {0};
        std::string reason;

        bool ok() const noexcept
        {
            return cause == Cause::None;
        }

        static Outcome success(T v)
        {
            Outcome o;
            o.value = std::move(v);
            return o;
        }

        static Outcome failure(Cause c, std::string why, int status = 0)
        {
            Outcome o;
            o.cause = c;
            o.reason = std::move(why);
            o.httpStatus = status;
            return o;
        }
    };

    /// Final result of one write. Strings are bounded (§4.15): itemErrorType <= 64 B, reason <= 512 B (truncated).
    struct OpResult final
    {
        static constexpr std::size_t MAX_ITEM_ERROR_TYPE = 64;
        static constexpr std::size_t MAX_REASON = 512;

        Status status {Status::Ok};
        Cause cause {Cause::None};
        ItemOutcome outcome {ItemOutcome::None};
        int httpStatus {0};
        std::string itemErrorType;
        std::string reason;
    };

    /// Retry policy of a bucket or of a query. `std::nullopt` means unlimited.
    struct RetryPolicy final
    {
        std::optional<std::uint32_t> maxAttempts {5};
        std::optional<Duration> maxDuration {Duration {15000}};
        Duration base {Duration {1000}};
        Duration cap {Duration {15000}};
        double jitter {0.5};
    };

    /// What a bucket does when its quota (or the global cap) is full (RF-11).
    struct Overflow final
    {
        enum class Kind
        {
            Reject,
            Block,
            DropNewest,
            DropOldest
        };
        Kind kind {Kind::Reject};
        Duration blockTimeout {Duration {0}}; ///< Only for Kind::Block; must be > 0 there.
    };

    /// When a bucket's pending data becomes a bulk.
    struct BulkThresholds final
    {
        std::size_t maxBytes {4 * 1024 * 1024};
        std::size_t maxDocs {10000};
        Duration maxAge {Duration {5000}};
    };

    /// Treatment of HTTP 409 on `update` actions (I27).
    struct ConflictPolicy final
    {
        enum class Kind
        {
            Success,
            Retry
        };
        Kind kind {Kind::Success};
        std::uint32_t retryOnConflict {3};
    };

    /// How a write replaces the stored document (RF-28, I28).
    struct WriteMode final
    {
        enum class Kind
        {
            Replace,
            ReplacePreserving
        };
        Kind kind {Kind::Replace};
        std::vector<std::string> preservedPaths;
    };

    /// One write (RF-4).
    struct Op final
    {
        enum class Kind
        {
            Index,
            IndexAutoId,
            IndexDataStream,
            Delete,
            IndexVersionedScript
        };
        Kind kind {Kind::Index};
        std::string index;
        std::string id;
        std::string body; ///< Compact JSON without '\n'.
        std::string version;
        /// Cancellation key, e.g. the agent id (RF-26); never sent to the indexer. At most 256 bytes, with no byte
        /// below 0x20 nor 0x7f (otherwise the op is refused as an invalid argument); empty = no tag.
        /// IWriter::cancel(tag) drops the ops of its bucket with that tag; cancel("") is refused (InvalidArgument). See
        /// README § Cancellation.
        std::string tag;
        WriteMode mode;
        std::optional<ConflictPolicy> onConflict; ///< Overrides the bucket's policy.
    };

    using Callback = std::function<void(const OpResult&)>; ///< Runs on the CPU pool; must be short and never block.

    /// A queue with its own policies, declared by a consumer (RF-2, I8).
    struct BucketSpec final
    {
        std::string name;
        std::uint32_t weight {1};
        std::size_t quotaBytes {64 * 1024 * 1024};
        RetryPolicy retry;
        Overflow overflow;
        BulkThresholds bulk;
        ConflictPolicy onConflict;
        /// Send order per key (index, _id): an op is never sent before an earlier op of its key has a final outcome,
        /// the bucket keeps at most one bulk in flight, and an ambiguous failure (the node may have applied the bulk)
        /// pins the retry to that node for ambiguous_retry_window_ms. See README § Ordered buckets.
        bool ordered {false};
    };

    struct Slice final
    {
        std::uint32_t id {0};
        std::uint32_t max {1};
    };

    struct CursorQuery final
    {
        nlohmann::json query = nlohmann::json::object();
        nlohmann::json sort = nlohmann::json::array();
        nlohmann::json source; ///< `_source` filter; null means "all".
        std::uint32_t pageSize {1000};
    };

    struct PitOptions final
    {
        Duration keepAlive {Duration {300000}};
        bool expandWildcardsAll {false};
    };

    struct DbqOptions final
    {
        bool proceedOnConflicts {true};
    };

    struct QueryOptions final
    {
        RetryPolicy retry;
        Duration pageDeadline {Duration {30000}};
        bool expandWildcardsAll {false};
    };

    struct PitPage final
    {
        std::uint64_t generation {0};
        nlohmann::json hits = nlohmann::json::array();
        bool last {false};
    };

    /// Indexer credentials (I42, I55): read by each process from its keystore and handed over through
    /// IConfigSource::credentials(). Deliberately without operator<<: never streamed, logged or put in a reason.
    struct Credentials final
    {
        std::string user;
        std::string password;
    };

    struct HealthView final
    {
        enum class NodeState
        {
            Available,
            Throttled,
            Down
        };
        struct Node final
        {
            std::string url;
            NodeState state {NodeState::Down};
            std::string reason; ///< Why the node is Down (status, cause, curl code); empty otherwise.
        };
        std::vector<Node> nodes;
        bool clusterRed {false};
        /// Set while the last complete probe round failed for a local reason (TLS material curl refused, a local
        /// curl error, a response over the cap): the runtime, not the nodes, is at fault (D36).
        std::optional<std::string> localFault;

        /// At least one node Available: the strict aggregate (vulnerability scanner admission, I52-e).
        bool anyAvailable() const
        {
            for (const auto& node : nodes)
            {
                if (node.state == NodeState::Available)
                {
                    return true;
                }
            }
            return false;
        }

        /// At least one node not Down (Available or Throttled): the lenient aggregate (inventory sync, I52-e).
        bool anyUsable() const
        {
            for (const auto& node : nodes)
            {
                if (node.state != NodeState::Down)
                {
                    return true;
                }
            }
            return false;
        }
    };

    struct CloseReport final
    {
        std::size_t callbacksInFlight {0};
        std::size_t droppedClientClosed {0};
        std::size_t droppedShutdown {0};
    };

    /// Snapshot of the runtime counters (I20). Grows stage by stage; E1 only reports the thread layout.
    struct MetricsSnapshot final
    {
        std::uint32_t networkThreads {0};
        std::uint32_t cpuThreads {0};
        std::uint32_t clients {0};
    };
} // namespace indexer_client

#endif // _INDEXER_CLIENT_TYPES_HPP
