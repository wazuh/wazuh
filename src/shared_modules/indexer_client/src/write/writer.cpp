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
#include <string_view>
#include <utility>

#include "runtime/runtimeInternal.hpp"
#include "transport/seams.hpp"
#include "write/encoding.hpp"
#include "write/group.hpp"
#include "write/sender.hpp"

// The write path of a runtime (plan 18 I62/I63). Lock discipline: WritePath::m_mutex only guards its own members and
// is never held while calling into a bucket, the scheduler or the sink; a bucket's mutex is a leaf (bucket.hpp);
// tickets and callbacks are completed with no lock held.

namespace indexer_client::detail::write
{
    namespace
    {
        /// The fixed reason of a refused submit (D42): never a consumer string (group.cpp has the add() twin).
        const char* refusalReason(Cause cause)
        {
            switch (cause)
            {
                case Cause::QueueFull: return "the bucket has no room for the operation";
                case Cause::SubmitTimeout: return "blocked until overflow.blockTimeout without room";
                case Cause::Reentrancy: return "a blocking submit from a runtime thread";
                case Cause::PayloadTooLarge:
                    return "the operation can never fit bulk.maxBytes, the bucket's quota or the global cap";
                case Cause::ClientClosed: return "the client is closed";
                case Cause::Shutdown: return "the runtime is shutting down";
                default: return toString(cause);
            }
        }

        /// The cancel(tag) refusal (field first), or null for a tag submit accepts (encoding.hpp, MAX_TAG_SIZE).
        const char* invalidCancelTag(std::string_view tag)
        {
            if (tag.empty())
            {
                return "tag: empty";
            }
            if (tag.size() > MAX_TAG_SIZE)
            {
                static_assert(MAX_TAG_SIZE == 256, "the reason below names the bound");
                return "tag: longer than 256 bytes";
            }
            for (const char c : tag)
            {
                const auto byte = static_cast<unsigned char>(c);
                if (byte < 0x20 || byte == 0x7f)
                {
                    return "tag: contains a control character";
                }
            }
            return nullptr;
        }

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
                case Cause::Cancelled: result.reason = "dropped: cancelled by cancel(tag)"; break;
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
                // I99, the callback cutoff (writer.hpp «Close»): decided under completionsMutex, so once awaitClosed
                // moved the cutoff under the same mutex no callback starts and callbacksRunning is exact.
                bool started = true;
                const auto runtimeCutoff = path ? path->callbackCutoff() : TimePoint::max();
                if (client)
                {
                    std::lock_guard<std::mutex> lock(client->completionsMutex);
                    const bool past =
                        std::chrono::steady_clock::now() >= std::min(client->callbackCutoff, runtimeCutoff);
                    seams::inCallbackGate(); // Between the comparison and the mark (CutoffGateHoldsAwaitClosed).
                    if (past)
                    {
                        started = false;
                        client->callbacksSkipped.fetch_add(1);
                    }
                    else
                    {
                        ++client->callbacksRunning;
                    }
                }
                else
                {
                    started = std::chrono::steady_clock::now() < runtimeCutoff;
                }

                // Runs on every exit, a throwing callback included: the reserve is returned, then the completion is
                // no longer outstanding (awaitClosed waits for exactly that).
                struct Finish final
                {
                    CallbackCompletion& self;
                    bool started;
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
                                if (started)
                                {
                                    --self.client->callbacksRunning;
                                }
                            }
                            self.client->completionsDone.notify_all();
                        }
                    }
                } finish {*this, started};

                if (ticket)
                {
                    ticket->complete(Outcome<OpResult>::success(result)); // Past the cutoff too (RF-6).
                }
                if (!started)
                {
                    return;
                }
                const auto begin = std::chrono::steady_clock::now();
                try
                {
                    callback(result);
                }
                catch (...)
                {
                    // A consumer callback must never take a pool thread down (nor skip the accounting above).
                }
                if (client)
                {
                    // k4-1: every callback is timed (E5c publishes the overruns and the maximum).
                    const auto took = std::chrono::steady_clock::now() - begin;
                    const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(took).count();
                    if (took > client->callbackBudget)
                    {
                        client->callbackOverruns.fetch_add(1);
                    }
                    auto seen = client->callbackMaxDurationMicros.load();
                    while (micros > seen && !client->callbackMaxDurationMicros.compare_exchange_weak(seen, micros))
                    {
                    }
                    // E5c: the maximum of the current log summary interval (exchanged with 0 by the summary).
                    seen = client->callbackIntervalMaxMicros.load();
                    while (micros > seen && !client->callbackIntervalMaxMicros.compare_exchange_weak(seen, micros))
                    {
                    }
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
                // The effective conflict policy (I73): the op's when set, else the bucket's.
                const ConflictPolicy effective = request.onConflict ? *request.onConflict : m_bucket->spec().onConflict;
                auto encoded = encode(std::move(request), effective);
                if (!encoded.ok())
                {
                    m_bucket->countInvalidArgument();
                    submit.cause = encoded.cause;
                    submit.reason = std::move(encoded.reason); // The field first (D42).
                    return submit;
                }
                // encode() only moved the body out: the tag and the key fields are still the request's (I79, I80).
                std::string tag = std::move(request.tag);
                const bool hasKey = m_bucket->spec().ordered && !request.id.empty(); // `_id` iff the kind has one.
                const std::uint64_t keyHash = hasKey ? orderedKeyHash(request.index, request.id) : 0;
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
                    submit.reason = refusalReason(reservation.cause);
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
                        m_bucket->countResolved(Status::Dropped, Cause::QueueFull);
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
                op->conflictRetry = effective.kind == ConflictPolicy::Kind::Retry;
                op->tag = std::move(tag);
                op->hasKey = hasKey;
                op->keyHash = keyHash;

                seams::afterAdmission();

                std::optional<Cause> closedAtEnqueue;
                const bool notify = m_bucket->enqueue(op, &closedAtEnqueue);
                // A close or a shutdown between the reservation and the enqueue (SubmitRacesClose): the bucket refused
                // the op and took custody of its payload without queuing it (I99, N2), so only this op is resolved
                // here; the rest of the bucket keeps draining. Both sides order on the bucket's mutex.
                if (const auto& closed = closedAtEnqueue; closed)
                {
                    m_path->resolve(op, dropped(*closed)); // Not part of CloseReport::drained (a refusal).
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
                return Group(makeGroup(m_client, m_bucket, m_path));
            }

            /// I80 (bucket.hpp): the bucket removes the pending and lane ops of the tag and marks the delivered ones;
            /// the removed ones resolve Dropped(Cancelled) here, outside its mutex. With nothing delivered the ticket
            /// completes at once; otherwise the bucket completes it at the last resolution of a marked op. Never
            /// blocks.
            CancelTicket cancel(std::string_view tag) override
            {
                auto state = std::make_shared<CancelState>();
                // An empty tag is "no tag" (OpState::tag): it would cancel every untagged op. A tag that submit refuses
                // can match nothing. Both are refused with the field first, never echoing the tag (D42).
                if (const char* why = invalidCancelTag(tag); why != nullptr)
                {
                    state->complete(Outcome<Unit>::failure(Cause::InvalidArgument, why));
                    return CancelTicket(std::move(state));
                }
                auto result = m_bucket->cancel(std::string(tag), state);
                for (const auto& op : result.removed)
                {
                    m_path->resolve(op, dropped(Cause::Cancelled));
                }
                if (!result.removed.empty())
                {
                    // Removing lane ops may lift an ordered bucket's pin gate or unblock keys: its timer may still be
                    // armed at a far nextDue (the pin's end, the lane head), so the scheduler looks again now.
                    if (auto scheduler = m_path->scheduler())
                    {
                        scheduler->notify(m_bucket);
                    }
                }
                if (!result.waiting)
                {
                    state->complete(Outcome<Unit>::success(Unit {}));
                }
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
            created.push_back(std::make_shared<Bucket>(client.consumer, spec, m_budget, weak_from_this()));
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
        std::shared_ptr<ClientState> client;
        if (ticket)
        {
            client = ticket->client.lock();
        }
        else if (op->group)
        {
            client = op->group->client.lock(); // A group op counts in the CloseReport like a submitted one.
        }

        if (result.reason.size() > OpResult::MAX_REASON)
        {
            result.reason.resize(OpResult::MAX_REASON);
        }
        if (result.itemErrorType.size() > OpResult::MAX_ITEM_ERROR_TYPE)
        {
            result.itemErrorType.resize(OpResult::MAX_ITEM_ERROR_TYPE);
        }
        // I99 (writer.hpp «Close»): the client's accounting goes before the payload is released. Σ retained of the
        // client reaches 0 only once every resolution of the drain is counted and its completion is outstanding, so
        // awaitClosed's second wait (outstandingCompletions == 0) covers the callback of the last drained op.
        const bool withCompletion = client && callback && !op->group;
        if (withCompletion)
        {
            std::lock_guard<std::mutex> lock(client->completionsMutex);
            ++client->outstandingCompletions;
        }
        bool closing = false;
        if (client)
        {
            const bool sweptOrRefused = result.status == Status::Dropped &&
                                        (result.cause == Cause::ClientClosed || result.cause == Cause::Shutdown);
            if (result.status == Status::Dropped)
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
            closing = client->closeRequested.load();
            if (closing && !sweptOrRefused)
            {
                // CloseReport::drained: resolved after requestClose() by the drain itself. A Dropped(ClientClosed)
                // or Dropped(Shutdown) comes only from a sweep, a refusal or a requeue into a closed bucket.
                client->drained.fetch_add(1);
            }
        }
        if (bucket)
        {
            // Once per op (the bucket tracks it); wakes blocked producers; frees the op's last-error strings under the
            // mutex a concurrent Bucket::requeue writes them with (nothing reads them after the claim: an exhausted
            // op's error was copied out by that requeue).
            bucket->countResolved(result.status, result.cause, result.itemErrorType, result.reason);
            if (result.status == Status::Dropped && result.cause == Cause::Cancelled)
            {
                bucket->countCancelled(1); // I80: also under resolvedDropped.
            }
            bucket->releasePayload(*op);
            seams::afterPayloadReleased(); // ResolutionOutstandingBeforeReleased.
        }
        else
        {
            // No bucket, so no requeue writes the last-error strings and no cancel reads the tag (RESULT_RESERVE).
            std::string().swap(op->lastReason);
            std::string().swap(op->lastItemErrorType);
            std::string().swap(op->tag);
        }
        if (closing)
        {
            // After the release: awaitClosed's drain re-checks its predicate (Σ retained) under completionsMutex.
            {
                std::lock_guard<std::mutex> lock(client->completionsMutex);
            }
            client->drainDone.notify_all();
        }

        if (op->group)
        {
            // A group op (I74): no ticket, no callback, no pool task. Its slot is filled (the last one completes the
            // GroupTicket) and the op lets its GroupState go, with no lock held: it may be the last holder, whose
            // destructor returns the group's reserves; the OpState itself may still live on in a batch.
            resolveInGroup(*op, std::move(result));
            op->group.reset();
            return true;
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
        completion->releaseReserve = reserveCharged; // Already outstanding for its client (above).
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

    void WritePath::closeClient(ClientState& client, bool sweep)
    {
        auto current = scheduler();
        for (const auto& bucket : client.bucketStates)
        {
            if (sweep)
            {
                // A Client destroyed on a runtime thread: the old close, pending and lane resolved now; what is
                // delivered keeps its course (a later requeue finds the bucket closed).
                sweepClosed(*bucket, Cause::ClientClosed);
                continue;
            }
            bucket->closeAdmission(Cause::ClientClosed);
            if (current)
            {
                current->notify(bucket); // Everything pending is eligible now (flushSeq): the drain starts at once.
            }
        }
    }

    std::uint64_t WritePath::sweepClient(ClientState& client, bool cancelTransfers)
    {
        std::uint64_t won = 0;
        auto current = cancelTransfers ? sink() : nullptr;
        for (const auto& bucket : client.bucketStates)
        {
            for (const auto& op : bucket->close(Cause::ClientClosed))
            {
                won += resolve(op, dropped(Cause::ClientClosed)) ? 1 : 0;
            }
            bool any = false;
            for (const auto& op : bucket->delivered())
            {
                any = true;
                won += resolve(op, dropped(Cause::Shutdown)) ? 1 : 0;
            }
            if (any && current)
            {
                current->cancelBucket(*bucket); // After the resolutions: the sender's assembly skips claimed ops.
            }
        }
        return won;
    }

    void WritePath::stop(std::optional<TimePoint> callbackCutoff)
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
        if (callbackCutoff)
        {
            // First: the completions this stop() posts, and those already queued, start no callback past it.
            m_callbackCutoff.store(callbackCutoff->time_since_epoch().count());
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

    std::uint64_t WritePath::retainedBytes() const
    {
        std::uint64_t bytes = 0;
        forEachBucket([&bytes](const std::shared_ptr<Bucket>& bucket) { bytes += bucket->retainedBytes(); });
        return bytes;
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
