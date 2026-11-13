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

    /// Final status of an operation.
    enum class Status
    {
        Ok,
        Failed,
        Dropped
    };

    /// Single classification of every failure and of every API-level refusal.
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
        UsageError,
        /// A bulk answered 500/502/504 by the indexer, or whose response went over max_response_bytes, failed without
        /// resending (BucketSpec::onAmbiguous5xx = Fail).
        Ambiguous
    };

    /// Stable, lowercase name of a cause (logs, metrics labels and test diagnostics).
    INDEXER_CLIENT_API const char* toString(Cause cause) noexcept;

    /// Per-item outcome of a write.
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
        /// Queries only: the failure (always Cause::ItemPermanent, never retried by the library) is a response over
        /// the query's size cap (maxResponseBytes / QUERY_DOM_FACTOR, or maxResponseBytes on the wire). The same
        /// request asking for fewer hits may fit; the caller decides (the content manager's paginator halves its page).
        bool responseTooLarge {false};

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

    /// What a bucket does when its quota (or the global cap) is full.
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

    /// Treatment of HTTP 409 on `update` actions.
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

    /// How a write replaces the stored document.
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

    /// One write.
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
        /// Cancellation key, e.g. the agent id; never sent to the indexer. At most 256 bytes, with no byte
        /// below 0x20 nor 0x7f (otherwise the op is refused as an invalid argument); empty = no tag.
        /// IWriter::cancel(tag) drops the ops of its bucket with that tag; cancel("") is refused (InvalidArgument). See
        /// README § Cancellation.
        std::string tag;
        WriteMode mode;
        std::optional<ConflictPolicy> onConflict; ///< Overrides the bucket's policy.
    };

    using Callback = std::function<void(const OpResult&)>; ///< Runs on the CPU pool; must be short and never block.

    /// What a bucket does with a `_bulk` answered 500, 502 or 504, or whose response went over max_response_bytes
    /// (BucketSpec::onAmbiguous5xx).
    enum class AmbiguousPolicy
    {
        Retry, ///< Requeue the batch with a counted attempt, as any other 5xx; split an oversized answer like a 413.
        Fail   ///< Resolve every op Failed(Ambiguous) without resending it.
    };

    /// What every queued operation reserves against the quota for its result, besides its payload (the charge). A
    /// bucket is valid only if `bulk.maxBytes + RESULT_RESERVE_BYTES <= quotaBytes`.
    constexpr std::uint64_t RESULT_RESERVE_BYTES = 2048;

    /// A queue with its own policies, declared by a consumer.
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
        /// A `_bulk` answered 500, 502 or 504 may have been applied by the indexer: Retry resends it (a duplicate in an
        /// index without `_id`), Fail resolves its ops Failed(Ambiguous) without resending them. A response over
        /// max_response_bytes is ambiguous too (the node answered, the client did not read it): Retry splits the batch
        /// and resends the halves, Fail resolves it like a 500. A 503 is always retried. A transport timeout after the
        /// request left stays Retry under both (known asymmetry: it may still duplicate in buckets without `_id`).
        AmbiguousPolicy onAmbiguous5xx {AmbiguousPolicy::Retry};
        /// The producer guarantees every body is compact JSON with no raw '\n': submit, post and Group::add skip the
        /// per-op search for it (an empty body is still InvalidArgument). Risk: a stray '\n' is not caught locally;
        /// it splits the NDJSON line. If what follows is not a valid action line, the indexer answers 400 to that whole
        /// bulk (every op in it fails). If it is one, the indexer runs the injected operation and answers 2xx with one
        /// item more than ops: the whole batch is requeued, so every retry runs the injected operation again and
        /// duplicates each IndexAutoId/IndexDataStream of the batch, until RetryExhausted. Only for producers that
        /// guarantee compact JSON (the engine escapes every '\n').
        bool trustedBodies {false};
    };

    struct Slice final
    {
        std::uint32_t id {0};
        std::uint32_t max {1};
    };

    struct CursorQuery final
    {
        nlohmann::json query = {{"match_all", nlohmann::json::object()}}; ///< `{}` is a 400 in OpenSearch 3.6.
        nlohmann::json sort = nlohmann::json::array();
        nlohmann::json source; ///< `_source` filter; null means "all".
        std::uint32_t pageSize {1000};
    };

    struct PitOptions final
    {
        Duration keepAlive {Duration {300000}};
        bool expandWildcardsAll {false};
        /// The pages of this PIT (Pit::search, PitSession::next) are capped by maxResponseBytes itself instead of
        /// maxResponseBytes / QUERY_DOM_FACTOR (8 MiB with the default 64 MiB), so one page may parse into a DOM
        /// several times maxResponseBytes. For content downloads (the content manager), whose single documents can
        /// exceed the query cap; every other query keeps it.
        bool wholeResponseCap {false};
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
        /// deleteByQuery / updateByQuery: how many requests a by-query whose answers report version conflicts may take
        /// (the first included) before it ends Failed(VersionConflict); must be > 0. 1 never resends it on a conflict.
        std::uint32_t conflictAttempts {3};
    };

    struct PitPage final
    {
        std::uint64_t generation {0};
        nlohmann::json hits = nlohmann::json::array();
        bool last {false};
        /// hits.total.value of the cursor's first page (track_total_hits); empty on the following pages.
        std::optional<std::uint64_t> total;
    };

    /// Indexer credentials: read by each process from its keystore and handed over through
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
        /// curl error, a response over the cap): the runtime, not the nodes, is at fault.
        std::optional<std::string> localFault;

        /// At least one node Available: the strict aggregate (vulnerability scanner admission).
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

        /// At least one node not Down (Available or Throttled): the lenient aggregate (inventory sync).
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

        /// Why a call should not wait for a node: every node already went through a probe round (Down
        /// with a reason) and none is usable. Then "url: reason" of each node in order, joined by "; ". Nullopt with no
        /// node, with a usable one, or before the first probe round (a node is born Down with an empty reason).
        std::optional<std::string> noUsableAfterProbes() const
        {
            if (nodes.empty() || anyUsable())
            {
                return std::nullopt;
            }
            std::string reasons;
            for (const auto& node : nodes)
            {
                if (node.reason.empty())
                {
                    return std::nullopt;
                }
                if (!reasons.empty())
                {
                    reasons += "; ";
                }
                reasons += node.url;
                reasons += ": ";
                reasons += node.reason;
            }
            return reasons;
        }
    };

    struct CloseReport final
    {
        std::size_t callbacksInFlight {0}; ///< Callbacks started and not finished when awaitClosed returned.
        std::size_t droppedClientClosed {0};
        std::size_t droppedShutdown {0};
        std::size_t callbacksSkipped {0}; ///< Completions past the cutoff: ticket completed, callback not called.
        std::size_t callbackOverruns {0}; ///< Callbacks that took longer than callbackBudget.
        /// Ops resolved after requestClose() that are not Dropped(ClientClosed) or Dropped(Shutdown): the
        /// drain's own results (Ok, Failed, any other Dropped). Sweeps and refusals are only in the two counters above.
        std::size_t drained {0};
    };
} // namespace indexer_client

#endif // _INDEXER_CLIENT_TYPES_HPP
