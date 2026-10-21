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

#ifndef _INDEXER_CLIENT_RUNTIME_INTERNAL_HPP
#define _INDEXER_CLIENT_RUNTIME_INTERNAL_HPP

// Internal glue between the runtime (runtime.cpp), the client handles (client.cpp) and the tickets (tickets.cpp).
// asio stays inside runtime.cpp: nothing here names an asio type.

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "indexer_client/client.hpp"
#include "indexer_client/types.hpp"

namespace indexer_client::detail::write
{
    class Bucket;
    class WritePath;
    struct OpState;
} // namespace indexer_client::detail::write

namespace indexer_client::detail
{
    struct RuntimeState;
    struct ClientState;

    /// Releases a consumer name so that a later client may reuse it. No-op if the runtime is gone or restarted.
    void releaseClientName(const std::weak_ptr<RuntimeState>& runtime, std::uint64_t epoch, const std::string& name);

    /// The runtime's shutdown deadline, if beginShutdown() fixed one and the runtime is still the same epoch.
    std::optional<TimePoint> runtimeShutdownDeadline(const std::weak_ptr<RuntimeState>& runtime, std::uint64_t epoch);

    /// Counts one usage error (I37) in the process-wide counter read by detail::testing::usageErrors().
    void countUsageError();

    /// Runs `action` under the lock that serializes RuntimeOwner::start() and shutdown() when no runtime exists (no
    /// runtime thread can be running); false, without running it, otherwise (setLogFunction, I56).
    bool withNoRuntime(const std::function<void()>& action);

    class NodeSet;
    /// The NodeSet of a client's runtime (Client::health()): null once that runtime is gone or another epoch runs.
    std::shared_ptr<NodeSet> runtimeNodeSet(const std::weak_ptr<RuntimeState>& runtime, std::uint64_t epoch);

    /// One-shot completion shared by every ticket kind: set once, waited on by consumer threads only.
    template<class T>
    struct Completion
    {
        mutable std::mutex mutex;
        mutable std::condition_variable cv;
        std::optional<Outcome<T>> result;

        void complete(Outcome<T> outcome)
        {
            {
                std::lock_guard<std::mutex> lock(mutex);
                if (result)
                {
                    return;
                }
                result = std::move(outcome);
            }
            cv.notify_all();
        }

        bool isReady() const
        {
            std::lock_guard<std::mutex> lock(mutex);
            return result.has_value();
        }

        /// The caller has already rejected runtime threads (Reentrancy).
        Outcome<T> waitUntil(Deadline deadline) const
        {
            std::unique_lock<std::mutex> lock(mutex);
            if (!cv.wait_until(lock, deadline, [this] { return result.has_value(); }))
            {
                return Outcome<T>::failure(Cause::WaitTimeout, "wait deadline expired before the result");
            }
            return *result;
        }
    };

    struct TicketState final : Completion<OpResult>
    {
        /// E3a (I62): the op's RESULT_RESERVE when it has no callback; its destructor returns the reserve to the
        /// bucket, so the reserve lives as long as the last Ticket. Never dropped while holding a bucket mutex.
        std::shared_ptr<void> resultReserve;
        /// The submitting client, for the completion accounting of WritePath::resolve (outstandingCompletions and
        /// the CloseReport counters). Weak: a ticket never keeps its client alive.
        std::weak_ptr<ClientState> client;
    };

    struct CancelState final : Completion<Unit>
    {
    };

    /// A confirmable group (E3c-1, I74). NORMATIVE contract: write/group.hpp.
    struct GroupState final : Completion<std::vector<OpResult>>
    {
        enum class Phase
        {
            Building,
            Committed,
            Done,
            Abandoned
        };

        GroupState() = default;
        GroupState(const GroupState&) = delete;
        GroupState& operator=(const GroupState&) = delete;
        ~GroupState(); ///< Returns reservesHeld x RESULT_RESERVE (group.cpp).

        std::atomic<bool> committed {false}; ///< commit() runs once.
        std::weak_ptr<ClientState> client;
        std::weak_ptr<write::Bucket> bucket;
        std::weak_ptr<write::WritePath> path;

        std::mutex groupMutex; ///< A leaf (group.hpp); guards the members below.
        Phase phase {Phase::Building};
        std::vector<std::shared_ptr<write::OpState>> ops; ///< Building only.
        std::uint64_t reservedBytes {0};                  ///< Payload + reserves of the Building ops.
        std::uint32_t reservesHeld {0};                   ///< RESULT_RESERVEs this group still owes back.
        std::vector<OpResult> results;                    ///< One slot per op, in add order (Committed).
        std::size_t remaining {0};
        std::string lastAddReason; ///< Why the last add() was refused (D42); empty after an accepted one.
    };

    struct PitState final
    {
        std::uint64_t generation {0};
    };

    struct CursorState final
    {
        std::atomic<bool> exhausted {false};
    };

    /// Per-consumer state. The runtime is referenced weakly: a client never keeps the runtime alive (I37).
    struct ClientState final
    {
        std::weak_ptr<RuntimeState> runtime;
        std::uint64_t epoch {0};
        std::string consumer;
        std::vector<BucketSpec> buckets;
        /// E3a: the client's buckets, in the order of `buckets` (created by WritePath::registerClient).
        std::vector<std::shared_ptr<write::Bucket>> bucketStates;
        /// E3a (I63): completions posted to the pool and not yet finished (callback run, reserve released);
        /// awaitClosed waits on it and reports the rest as CloseReport.callbacksInFlight.
        std::mutex completionsMutex;
        std::condition_variable completionsDone;
        std::uint64_t outstandingCompletions {0};
        /// E3a: ops of this client resolved Dropped(ClientClosed) / Dropped(Shutdown) (CloseReport).
        std::atomic<std::uint64_t> droppedClientClosed {0};
        std::atomic<std::uint64_t> droppedShutdown {0};
        /// E3a: the runtime's write path (set by RuntimeRef::client); weak, like `runtime`.
        std::weak_ptr<write::WritePath> writePath;
        Duration drain {Duration {10000}};
        std::atomic<bool> closeRequested {false};
        std::atomic<bool> nameReleased {false};

        void releaseName()
        {
            if (!nameReleased.exchange(true))
            {
                releaseClientName(runtime, epoch, consumer);
            }
        }

        ~ClientState()
        {
            releaseName();
        }
    };

    /// The CPU pool's queue (E3a, NoDropWithoutCounter): tasks posted and not yet taken by a worker, and the peak
    /// since the runtime started. Zeros when no runtime runs. Internal access (component suite).
    struct PoolStats final
    {
        std::uint64_t postsPending {0};
        std::uint64_t peakPostsPending {0};
    };
    PoolStats runtimePoolStats();

    /// E1 stubs: every data-path operation is Cause::Unavailable until E3b/E4 replace them.
    std::shared_ptr<IWriter> makeStubWriter(std::shared_ptr<ClientState> client, std::string bucket);
    std::shared_ptr<IQuery> makeStubQuery(std::shared_ptr<ClientState> client);
} // namespace indexer_client::detail

#endif // _INDEXER_CLIENT_RUNTIME_INTERNAL_HPP
