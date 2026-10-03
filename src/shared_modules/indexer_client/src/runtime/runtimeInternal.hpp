/*
 * Wazuh indexer client
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_CLIENT_RUNTIME_INTERNAL_HPP
#define _INDEXER_CLIENT_RUNTIME_INTERNAL_HPP

// Internal glue between the runtime (runtime.cpp), the client handles (client.cpp) and the tickets (tickets.cpp).
// asio stays inside runtime.cpp: nothing here names an asio type.

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "indexer_client/client.hpp"
#include "indexer_client/types.hpp"

namespace indexer_client::detail
{
    struct RuntimeState;

    /// Releases a consumer name so that a later client may reuse it. No-op if the runtime is gone or restarted.
    void releaseClientName(const std::weak_ptr<RuntimeState>& runtime, std::uint64_t epoch, const std::string& name);

    /// The runtime's shutdown deadline, if beginShutdown() fixed one and the runtime is still the same epoch.
    std::optional<TimePoint> runtimeShutdownDeadline(const std::weak_ptr<RuntimeState>& runtime, std::uint64_t epoch);

    /// Counts one usage error (I37) in the process-wide counter read by detail::testing::usageErrors().
    void countUsageError();

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
    };

    struct CancelState final : Completion<Unit>
    {
    };

    struct GroupState final : Completion<std::vector<OpResult>>
    {
        std::atomic<bool> committed {false};
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

    /// E1 stubs: every data-path operation is Cause::Unavailable until E3b/E4 replace them.
    std::shared_ptr<IWriter> makeStubWriter(std::shared_ptr<ClientState> client, std::string bucket);
    std::shared_ptr<IQuery> makeStubQuery(std::shared_ptr<ClientState> client);
} // namespace indexer_client::detail

#endif // _INDEXER_CLIENT_RUNTIME_INTERNAL_HPP
