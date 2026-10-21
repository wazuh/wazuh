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

#ifndef _INDEXER_CLIENT_WRITE_WRITER_HPP
#define _INDEXER_CLIENT_WRITE_WRITER_HPP

// The write path of a runtime (stage E3a, plan 18 I62/I63): admission through the writer, the buckets of every client,
// the global cap, the scheduler, the sink and the single resolution path. Normative contract:
// anexos/e2a-1/contrato-transport.md § Escritura.

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

#include "indexer_client/client.hpp"
#include "indexer_client/runtimeConfig.hpp"
#include "write/bucket.hpp"
#include "write/budget.hpp"
#include "write/scheduler.hpp"
#include "write/sink.hpp"

namespace indexer_client::detail
{
    struct ClientState;
    class NodeSet;
    class Transport;
} // namespace indexer_client::detail

namespace indexer_client::detail::write
{
    struct WriteStats final
    {
        std::uint64_t globalCharge {0};
        std::uint64_t globalCap {0};
        std::vector<BucketStats> buckets;
    };

    class WritePath final : public std::enable_shared_from_this<WritePath>
    {
    public:
        /// `postToPool` runs a task on the CPU pool (false once the pool stopped accepting).
        WritePath(std::uint64_t globalCap, std::function<bool(std::function<void()>)> postToPool);

        /// Created after the runtime threads exist (needs loop 0); installs and starts the production sink, the bulk
        /// sender (E3b-2), whose start() registers the NodeSet hook: the runtime calls this before prober->start().
        /// Without a NodeSet or a transport the sink is makeUnavailableSink (defensive; the runtime always has both).
        void start(asio::io_context& loop0,
                   const RuntimeConfig& config,
                   std::shared_ptr<NodeSet> nodes,
                   std::shared_ptr<Transport> transport);

        /// Creates the client's buckets (owned by its ClientState) and registers them weakly for the scheduler.
        void registerClient(ClientState& client);

        GlobalBudget& budget() noexcept;
        std::shared_ptr<Scheduler> scheduler() const;
        std::shared_ptr<BatchSink> sink() const;
        /// Tests (component suite) install a programmable sink; production never calls it after start().
        void setSink(std::shared_ptr<BatchSink> sink);
        /// The sink has capacity again: the scheduler runs a pass.
        void sinkReady();
        /// Runs `task` on the CPU pool (the bulk sender's assembly and submit, E3b-2). False, without running it, once
        /// stop() finished or the pool refused it.
        bool postToPool(std::function<void()> task);

        /// The single resolution path, first-wins on OpState::claimed: releases the payload once, counts the status and
        /// posts the completion to the pool (ticket completed, then the callback under a guard that releases the
        /// result reserve even if it throws; without a callback the reserve dies with the last Ticket), counted in the
        /// client's outstandingCompletions. An op of a group (OpState::group, I74) has neither: it goes to
        /// resolveInGroup (group.hpp) instead, no pool task, and then drops its GroupState reference. Returns false
        /// when the op was already resolved.
        bool resolve(const std::shared_ptr<OpState>& op, OpResult result);

        /// requestClose(): closes the client's buckets (ClientClosed; blocked producers wake) and resolves their
        /// pending ops Dropped(ClientClosed). Ops already delivered to the sink keep their course.
        void closeClient(ClientState& client);

        /// Shutdown, in stopAndJoin before the prober: close every bucket (Shutdown; blocked producers wake) → stop the
        /// scheduler → sink.stop() → resolve every unresolved op (pending and delivered) Dropped(Shutdown) while the
        /// pool still accepts. Idempotent.
        void stop();

        WriteStats stats() const;

    private:
        void forEachBucket(const std::function<void(const std::shared_ptr<Bucket>&)>& fn) const;
        /// Closes `bucket` with `cause` (idempotent) and resolves what is still pending Dropped(cause).
        void sweepClosed(Bucket& bucket, Cause cause);

        GlobalBudget m_budget;
        std::function<bool(std::function<void()>)> m_postToPool;
        mutable std::mutex m_mutex; ///< Guards the members below (never held while calling into a bucket or the sink).
        std::vector<std::weak_ptr<Bucket>> m_buckets;
        std::shared_ptr<Scheduler> m_scheduler;
        std::shared_ptr<BatchSink> m_sink;
        bool m_stopped {false};
        /// Set at the end of stop(): later completions run inline (the pool may be gone with its runtime).
        std::atomic<bool> m_poolDetached {false};
    };

    /// The writer bound to one bucket of one client (Client::writer). submit: effective conflict policy + encode
    /// (InvalidArgument, Submit::reason) → reserve → enqueue (+ Scheduler::notify) or the drop/refusal;
    /// seams::afterAdmission() sits between reserve and enqueue. group(): a Building group of this bucket (group.hpp,
    /// E3c-1). cancel(tag): Bucket::cancel and the resolution of what it removes (E3c-2 I80, bucket.hpp).
    std::shared_ptr<IWriter>
    makeWriter(std::shared_ptr<ClientState> client, std::shared_ptr<Bucket> bucket, std::shared_ptr<WritePath> path);

    /// The running runtime's write path, or null (internal users and the component suite).
    std::shared_ptr<WritePath> runtimeWritePath();
    /// Snapshot of the running runtime's write counters (empty when no runtime).
    WriteStats writeStats();
} // namespace indexer_client::detail::write

#endif // _INDEXER_CLIENT_WRITE_WRITER_HPP
