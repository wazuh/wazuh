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

#include "write/writer.hpp"

#include <algorithm>
#include <chrono>
#include <string>
#include <utility>

#include "runtime/runtimeInternal.hpp"
#include "transport/seams.hpp"
#include "write/encoding.hpp"
#include "write/sender.hpp"

// The write path of a runtime (plan 18 I62/I63). Lock discipline: WritePath::m_mutex only guards its own members and
// is never held while calling into a bucket, the scheduler or the sink; a bucket's mutex is a leaf (bucket.hpp);
// tickets and callbacks are completed with no lock held.

namespace indexer_client::detail::write
{
    namespace
    {
        constexpr const char* E3C_UNAVAILABLE = "groups and cancel(tag) arrive in E3c";

        OpResult dropped(Cause cause)
        {
            OpResult result;
            result.status = Status::Dropped;
            result.cause = cause;
            switch (cause)
            {
                case Cause::QueueFull: result.reason = "dropped by the bucket's overflow policy"; break;
                case Cause::ClientClosed: result.reason = "dropped: the client was closed"; break;
                case Cause::Shutdown: result.reason = "dropped: the runtime is shutting down"; break;
                default: result.reason = std::string("dropped: ") + toString(cause); break;
            }
            return result;
        }

        /// The RESULT_RESERVE of an op without callback (TicketState::resultReserve): returned to the bucket when the
        /// last holder of the TicketState lets it go. Both references are weak: the reserve never keeps the runtime
        /// alive, and once the write path is gone (its budget with it) there is nothing to return.
        struct ReserveHandle final
        {
            std::weak_ptr<WritePath> path;
            std::weak_ptr<Bucket> bucket;

            ReserveHandle(std::weak_ptr<WritePath> writePath, std::weak_ptr<Bucket> owner)
                : path(std::move(writePath))
                , bucket(std::move(owner))
            {
            }

            ReserveHandle(const ReserveHandle&) = delete;
            ReserveHandle& operator=(const ReserveHandle&) = delete;

            ~ReserveHandle()
            {
                auto alive = path.lock(); // Keeps the budget alive while the bucket returns the reserve.
                if (!alive)
                {
                    return;
                }
                if (auto owner = bucket.lock())
                {
                    owner->releaseReserve();
                }
                else
                {
                    // The bucket died first (its Client and writers are gone, a Ticket outlived them): its own charge
                    // no longer matters, but the runtime-wide cap must get the reserve back (G-diff E3a obj. 1).
                    alive->budget().release(RESULT_RESERVE);
                }
            }
        };

        /// One completion with a callback, run on the CPU pool (or inline once the pool is gone).
        struct CallbackCompletion final
        {
            std::shared_ptr<WritePath> path; ///< Keeps the global budget alive until the reserve is returned.
            std::shared_ptr<Bucket> bucket;
            std::shared_ptr<TicketState> ticket;
            std::shared_ptr<ClientState> client;
            Callback callback;
            OpResult result;
            bool releaseReserve {false};

            void run()
            {
                // Runs on every exit, a throwing callback included: the reserve is returned, then the completion is
                // no longer outstanding (awaitClosed waits for exactly that).
                struct Finish final
                {
                    CallbackCompletion& self;
                    ~Finish()
                    {
                        if (self.releaseReserve && self.bucket)
                        {
                            self.bucket->releaseReserve();
                        }
                        if (self.client)
                        {
                            {
                                std::lock_guard<std::mutex> lock(self.client->completionsMutex);
                                --self.client->outstandingCompletions;
                            }
                            self.client->completionsDone.notify_all();
                        }
                    }
                } finish {*this};

                if (ticket)
                {
                    ticket->complete(Outcome<OpResult>::success(result));
                }
                try
                {
                    callback(result);
                }
                catch (...)
                {
                    // A consumer callback must never take a pool thread down (nor skip the accounting above).
                }
            }
        };
    } // namespace

    namespace
    {
        /// The writer bound to one bucket of one client.
        class WriterImpl final : public IWriter
        {
        public:
            WriterImpl(std::shared_ptr<ClientState> client,
                       std::shared_ptr<Bucket> bucket,
                       std::shared_ptr<WritePath> path)
                : m_client(std::move(client))
                , m_bucket(std::move(bucket))
                , m_path(std::move(path))
            {
            }

            Submit submit(Op request, Callback cb) override
            {
                Submit submit;
                if (request.onConflict)
                {
                    // The per-operation ConflictPolicy is E3c: refused rather than silently served with the bucket's.
                    m_bucket->countInvalidArgument();
                    submit.cause = Cause::InvalidArgument;
                    return submit;
                }
                auto encoded = encode(std::move(request));
                if (!encoded.ok())
                {
                    m_bucket->countInvalidArgument();
                    submit.cause = encoded.cause;
                    return submit;
                }
                const bool withCallback = static_cast<bool>(cb);
                const auto now = std::chrono::steady_clock::now();
                const auto& overflow = m_bucket->spec().overflow;
                const auto blockUntil = overflow.kind == Overflow::Kind::Block ? now + overflow.blockTimeout : now;

                auto reservation = m_bucket->reserve(encoded.value.size(), withCallback, blockUntil);
                // DropOldest: the evicted ops are resolved outside the bucket's mutex, whatever this submit's outcome.
                for (const auto& evicted : reservation.evicted)
                {
                    m_path->resolve(evicted, dropped(Cause::QueueFull));
                }
                if (reservation.cause != Cause::None)
                {
                    submit.cause = reservation.cause;
                    return submit;
                }

                auto ticket = std::make_shared<TicketState>();
                ticket->client = m_client;
                submit.accepted = true;
                submit.ticket = Ticket(ticket);

                if (reservation.dropNewest)
                {
                    if (!withCallback)
                    {
                        // Nothing charged and no pool task: the ticket is completed here (I62).
                        m_bucket->countResolved(Status::Dropped);
                        ticket->complete(Outcome<OpResult>::success(dropped(Cause::QueueFull)));
                        return submit;
                    }
                    // Only RESULT_RESERVE was charged; it is returned after the callback, through the single path.
                    auto op = std::make_shared<OpState>();
                    op->reserveCharged = true;
                    op->ticket = std::move(ticket);
                    op->callback = std::move(cb);
                    op->firstSubmit = now;
                    op->bucket = m_bucket;
                    m_path->resolve(op, dropped(Cause::QueueFull));
                    return submit;
                }

                auto op = std::make_shared<OpState>();
                op->payload = encoded.value.size();
                op->lines = std::move(encoded.value);
                op->reserveCharged = true;
                if (!withCallback)
                {
                    ticket->resultReserve = std::make_shared<ReserveHandle>(m_path, m_bucket);
                }
                op->ticket = std::move(ticket);
                op->callback = std::move(cb);
                op->firstSubmit = now;
                op->bucket = m_bucket;

                seams::afterAdmission();

                std::optional<Cause> closedAtEnqueue;
                const bool notify = m_bucket->enqueue(op, &closedAtEnqueue);
                // A close or a shutdown that swept this bucket between the reservation and the enqueue did not see this
                // op; the bucket took it anyway (bucket.hpp), so it is taken back and resolved here (SubmitRacesClose).
                // Both sides order on the bucket's mutex: either the sweep returned it or closedCause() is set now.
                if (const auto& closed = closedAtEnqueue; closed)
                {
                    for (const auto& pending : m_bucket->close(*closed))
                    {
                        m_path->resolve(pending, dropped(*closed));
                    }
                    return submit;
                }
                if (notify)
                {
                    if (auto scheduler = m_path->scheduler())
                    {
                        scheduler->notify(m_bucket);
                    }
                }
                return submit;
            }

            Group group() override
            {
                return Group(std::make_shared<GroupState>());
            }

            CancelTicket cancel(std::string_view /*tag*/) override
            {
                auto state = std::make_shared<CancelState>();
                state->complete(Outcome<Unit>::failure(Cause::Unavailable, E3C_UNAVAILABLE));
                return CancelTicket(std::move(state));
            }

        private:
            std::shared_ptr<ClientState> m_client;
            std::shared_ptr<Bucket> m_bucket;
            std::shared_ptr<WritePath> m_path;
        };
    } // namespace

    WritePath::WritePath(std::uint64_t globalCap, std::function<bool(std::function<void()>)> postToPool)
        : m_budget(globalCap)
        , m_postToPool(std::move(postToPool))
    {
    }

    void WritePath::start(asio::io_context& loop0,
                          const RuntimeConfig& config,
                          std::shared_ptr<NodeSet> nodes,
                          std::shared_ptr<Transport> transport)
    {
        auto scheduler = Scheduler::create(weak_from_this(), loop0, config.drrQuantumBytes);
        std::shared_ptr<BulkSink> bulk;
        std::shared_ptr<BatchSink> sink;
        if (nodes && transport)
        {
            bulk = BulkSink::create(weak_from_this(), std::move(nodes), std::move(transport), loop0, config);
            sink = bulk;
        }
        else
        {
            sink = makeUnavailableSink(weak_from_this());
        }
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_scheduler = std::move(scheduler);
            m_sink = std::move(sink);
        }
        if (bulk)
        {
            bulk->start(); // The NodeSet hook, before the runtime starts the prober.
        }
    }

    void WritePath::registerClient(ClientState& client)
    {
        std::vector<std::shared_ptr<Bucket>> created;
        created.reserve(client.buckets.size());
        for (const auto& spec : client.buckets)
        {
            created.push_back(std::make_shared<Bucket>(client.consumer, spec, m_budget));
        }
        bool stopped = false;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_buckets.erase(std::remove_if(m_buckets.begin(),
                                           m_buckets.end(),
                                           [](const std::weak_ptr<Bucket>& bucket) { return bucket.expired(); }),
                            m_buckets.end());
            for (const auto& bucket : created)
            {
                m_buckets.push_back(bucket);
            }
            stopped = m_stopped;
        }
        client.writePath = weak_from_this();
        client.bucketStates = std::move(created);
        if (stopped)
        {
            for (const auto& bucket : client.bucketStates)
            {
                bucket->close(Cause::Shutdown); // Never reached by the runtime (admission closes first): defensive.
            }
        }
    }

    GlobalBudget& WritePath::budget() noexcept
    {
        return m_budget;
    }

    std::shared_ptr<Scheduler> WritePath::scheduler() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_scheduler;
    }

    std::shared_ptr<BatchSink> WritePath::sink() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_sink;
    }

    void WritePath::setSink(std::shared_ptr<BatchSink> sink)
    {
        std::shared_ptr<BatchSink> replaced;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            replaced = std::exchange(m_sink, std::move(sink));
        }
        if (replaced)
        {
            replaced->stop(); // Outside the mutex: the production sender cancels its transfers and its timer (E3b-2).
        }
    }

    void WritePath::sinkReady()
    {
        if (auto current = scheduler())
        {
            current->notifyAll();
        }
    }

    bool WritePath::postToPool(std::function<void()> task)
    {
        return !m_poolDetached.load() && m_postToPool(std::move(task));
    }

    bool WritePath::resolve(const std::shared_ptr<OpState>& op, OpResult result)
    {
        if (!op || op->claimed.exchange(true))
        {
            return false;
        }
        // The winner owns the op's ticket and callback from here on; the sink or a sweep may still hold the OpState.
        auto bucket = op->bucket.lock();
        auto ticket = std::move(op->ticket);
        auto callback = std::move(op->callback);
        const bool reserveCharged = op->reserveCharged;
        auto client = ticket ? ticket->client.lock() : nullptr;

        if (result.reason.size() > OpResult::MAX_REASON)
        {
            result.reason.resize(OpResult::MAX_REASON);
        }
        if (result.itemErrorType.size() > OpResult::MAX_ITEM_ERROR_TYPE)
        {
            result.itemErrorType.resize(OpResult::MAX_ITEM_ERROR_TYPE);
        }
        if (bucket)
        {
            // Once per op (the bucket tracks it); wakes blocked producers; frees the op's last-error strings under the
            // mutex a concurrent Bucket::requeue writes them with (nothing reads them after the claim: an exhausted
            // op's error was copied out by that requeue).
            bucket->countResolved(result.status);
            bucket->releasePayload(*op);
        }
        else
        {
            std::string().swap(op->lastReason); // No bucket, so no requeue can write them.
            std::string().swap(op->lastItemErrorType);
        }
        if (client && result.status == Status::Dropped)
        {
            if (result.cause == Cause::ClientClosed)
            {
                client->droppedClientClosed.fetch_add(1);
            }
            else if (result.cause == Cause::Shutdown)
            {
                client->droppedShutdown.fetch_add(1);
            }
        }

        if (!callback)
        {
            // No pool task: the ticket is completed here; its reserve lives in TicketState::resultReserve and is
            // returned when the last Ticket (or this local reference) lets it go.
            if (ticket)
            {
                ticket->complete(Outcome<OpResult>::success(std::move(result)));
            }
            return true;
        }

        auto completion = std::make_shared<CallbackCompletion>();
        completion->path = shared_from_this();
        completion->bucket = std::move(bucket);
        completion->ticket = std::move(ticket);
        completion->client = client;
        completion->callback = std::move(callback);
        completion->result = std::move(result);
        completion->releaseReserve = reserveCharged;
        if (client)
        {
            std::lock_guard<std::mutex> lock(client->completionsMutex);
            ++client->outstandingCompletions;
        }
        if (m_poolDetached.load() || !m_postToPool([completion]() { completion->run(); }))
        {
            completion->run(); // The pool no longer accepts: complete inline (I63).
        }
        return true;
    }

    void WritePath::sweepClosed(Bucket& bucket, Cause cause)
    {
        for (const auto& op : bucket.close(cause))
        {
            resolve(op, dropped(cause));
        }
    }

    void WritePath::closeClient(ClientState& client)
    {
        for (const auto& bucket : client.bucketStates)
        {
            sweepClosed(*bucket, Cause::ClientClosed);
        }
    }

    void WritePath::stop()
    {
        std::shared_ptr<Scheduler> scheduler;
        std::shared_ptr<BatchSink> sink;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_stopped)
            {
                return;
            }
            m_stopped = true;
            scheduler = m_scheduler;
            sink = m_sink;
        }
        // 1. Admission: every bucket closes (blocked producers wake with Shutdown) and its pending ops are dropped.
        forEachBucket([this](const std::shared_ptr<Bucket>& bucket) { sweepClosed(*bucket, Cause::Shutdown); });
        // 2. No pass, no batch and no timer afterwards.
        if (scheduler)
        {
            scheduler->stop();
        }
        // 3. The sink accepts no more batches; what it still holds is swept below (resolution is first-wins).
        if (sink)
        {
            sink->stop();
        }
        // 4. Everything still unresolved, pending (a late enqueue) or delivered, while the pool still accepts.
        forEachBucket(
            [this](const std::shared_ptr<Bucket>& bucket)
            {
                sweepClosed(*bucket, Cause::Shutdown);
                for (const auto& op : bucket->delivered())
                {
                    resolve(op, dropped(Cause::Shutdown));
                }
            });
        m_poolDetached.store(true);
    }

    WriteStats WritePath::stats() const
    {
        WriteStats stats;
        stats.globalCharge = m_budget.charge();
        stats.globalCap = m_budget.cap();
        forEachBucket([&stats](const std::shared_ptr<Bucket>& bucket) { stats.buckets.push_back(bucket->stats()); });
        return stats;
    }

    void WritePath::forEachBucket(const std::function<void(const std::shared_ptr<Bucket>&)>& fn) const
    {
        std::vector<std::shared_ptr<Bucket>> alive;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            alive.reserve(m_buckets.size());
            for (const auto& weak : m_buckets)
            {
                if (auto bucket = weak.lock())
                {
                    alive.push_back(std::move(bucket));
                }
            }
        }
        for (const auto& bucket : alive)
        {
            fn(bucket);
        }
    }

    std::shared_ptr<IWriter>
    makeWriter(std::shared_ptr<ClientState> client, std::shared_ptr<Bucket> bucket, std::shared_ptr<WritePath> path)
    {
        if (!client || !bucket || !path)
        {
            return nullptr;
        }
        return std::make_shared<WriterImpl>(std::move(client), std::move(bucket), std::move(path));
    }

    WriteStats writeStats()
    {
        auto path = runtimeWritePath();
        return path ? path->stats() : WriteStats {};
    }
} // namespace indexer_client::detail::write
