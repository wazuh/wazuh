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

// Confirmable groups (stage E3c-1, plan 18 I74): the contract is group.hpp. groupMutex is a leaf: every call into a
// bucket, the scheduler, WritePath or the budget happens after it is dropped.

#include "write/group.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "runtime/runtimeInternal.hpp"
#include "write/bucket.hpp"
#include "write/encoding.hpp"
#include "write/writer.hpp"

namespace indexer_client::detail
{
    GroupState::~GroupState()
    {
        // The RESULT_RESERVEs of the committed ops, through the weak pair exactly like the writer's ReserveHandle. The
        // last holder (Group, GroupTicket or an OpState let go by WritePath::resolve) holds no mutex here.
        if (reservesHeld == 0)
        {
            return;
        }
        auto alive = path.lock(); // Keeps the budget alive while the bucket returns the reserves.
        if (!alive)
        {
            return;
        }
        if (auto owner = bucket.lock())
        {
            owner->releaseReserve(reservesHeld);
        }
        else
        {
            alive->budget().release(static_cast<std::uint64_t>(reservesHeld) * write::RESULT_RESERVE);
        }
    }
} // namespace indexer_client::detail

namespace indexer_client::detail::write
{
    namespace
    {
        /// The fixed reason of a refused add (D42): never a consumer string.
        const char* refusalReason(Cause cause)
        {
            switch (cause)
            {
                case Cause::QueueFull: return "the bucket has no room for the operation";
                case Cause::SubmitTimeout: return "blocked until overflow.blockTimeout without room";
                case Cause::Reentrancy: return "a blocking add from a runtime thread";
                case Cause::PayloadTooLarge:
                    return "the operation can never fit bulk.maxBytes, the bucket's quota or the global cap";
                case Cause::GroupTooLarge: return "the group would exceed the bucket's quota or the global cap";
                case Cause::ClientClosed: return "the client is closed";
                case Cause::Shutdown: return "the runtime is shutting down";
                case Cause::InvalidState: return "the group is no longer building";
                case Cause::Unavailable: return "the client is gone";
                default: return toString(cause);
            }
        }

        /// As writer.cpp's dropped(): the result of an op dropped by a close or a shutdown.
        OpResult dropped(Cause cause)
        {
            OpResult result;
            result.status = Status::Dropped;
            result.cause = cause;
            switch (cause)
            {
                case Cause::ClientClosed: result.reason = "dropped: the client was closed"; break;
                case Cause::Shutdown: result.reason = "dropped: the runtime is shutting down"; break;
                default: result.reason = std::string("dropped: ") + toString(cause); break;
            }
            return result;
        }

        Cause refuse(GroupState& group, Cause cause, std::string reason)
        {
            std::lock_guard<std::mutex> lock(group.groupMutex);
            group.lastAddReason = std::move(reason);
            return cause;
        }

        GroupTicket readyFailure(Cause cause, const char* reason)
        {
            auto state = std::make_shared<GroupState>();
            state->committed = true;
            state->phase = GroupState::Phase::Done;
            state->complete(Outcome<std::vector<OpResult>>::failure(cause, reason));
            return GroupTicket(std::move(state));
        }

        /// Resolves an op of a group whose write path is gone (no claim contender is left: nothing queued it).
        void resolveWithoutPath(const std::shared_ptr<OpState>& op, OpResult result)
        {
            if (op->claimed.exchange(true))
            {
                return;
            }
            resolveInGroup(*op, std::move(result));
            op->group.reset();
        }
    } // namespace

    std::shared_ptr<GroupState>
    makeGroup(std::shared_ptr<ClientState> client, std::shared_ptr<Bucket> bucket, std::shared_ptr<WritePath> path)
    {
        auto group = std::make_shared<GroupState>();
        group->client = client;
        group->bucket = bucket;
        group->path = path;
        return group;
    }

    Cause addToGroup(const std::shared_ptr<GroupState>& group, Op op)
    {
        std::uint64_t groupReserved = 0;
        {
            std::lock_guard<std::mutex> lock(group->groupMutex);
            if (group->phase != GroupState::Phase::Building)
            {
                group->lastAddReason = refusalReason(Cause::InvalidState);
                return Cause::InvalidState;
            }
            groupReserved = group->reservedBytes;
        }
        // No bucket call without a live write path (group.hpp): the bucket references the budget the path owns. Kept
        // for the whole add, a Block wait included. Gone means the runtime was shut down.
        auto path = group->path.lock();
        if (!path)
        {
            return refuse(*group, Cause::Shutdown, refusalReason(Cause::Shutdown));
        }
        auto bucket = group->bucket.lock();
        if (!bucket)
        {
            return refuse(*group, Cause::Unavailable, refusalReason(Cause::Unavailable));
        }

        // The effective conflict policy (I73), exactly as submit.
        const ConflictPolicy effective = op.onConflict ? *op.onConflict : bucket->spec().onConflict;
        auto encoded = encode(std::move(op), effective);
        if (!encoded.ok())
        {
            bucket->countInvalidArgument();
            return refuse(*group, encoded.cause, std::move(encoded.reason));
        }
        // As submit (writer.cpp): encode() only moved the body out, so the tag and the key fields are still `op`'s.
        std::string tag = std::move(op.tag);
        const bool hasKey = bucket->spec().ordered && !op.id.empty(); // `_id` iff the kind has one.
        const std::uint64_t keyHash = hasKey ? orderedKeyHash(op.index, op.id) : 0;

        const auto& overflow = bucket->spec().overflow;
        const auto now = std::chrono::steady_clock::now();
        const auto blockUntil = overflow.kind == Overflow::Kind::Block ? now + overflow.blockTimeout : now;
        const std::uint64_t payload = encoded.value.size();
        const auto reservation = bucket->reserveForGroup(payload, groupReserved, blockUntil);
        if (reservation.cause != Cause::None)
        {
            return refuse(*group, reservation.cause, refusalReason(reservation.cause));
        }

        // No ticket, no callback and no firstSubmit: enqueueGroup sets it (the age counts from the commit).
        auto state = std::make_shared<OpState>();
        state->payload = payload;
        state->lines = std::move(encoded.value);
        state->reserveCharged = true;
        state->conflictRetry = effective.kind == ConflictPolicy::Kind::Retry;
        state->tag = std::move(tag);
        state->hasKey = hasKey;
        state->keyHash = keyHash;
        state->bucket = bucket;
        state->group = group;

        std::lock_guard<std::mutex> lock(group->groupMutex);
        state->groupIndex = static_cast<std::uint32_t>(group->ops.size());
        group->ops.push_back(std::move(state));
        group->reservedBytes += payload + RESULT_RESERVE;
        ++group->reservesHeld;
        group->lastAddReason.clear();
        return Cause::None;
    }

    GroupTicket commitGroup(const std::shared_ptr<GroupState>& group)
    {
        if (!group)
        {
            return readyFailure(Cause::InvalidState, "empty group handle"); // A moved-from or default Group.
        }
        if (group->committed.exchange(true))
        {
            // An already committed group yields a ready ticket that reports the misuse.
            return readyFailure(Cause::InvalidState, "group already committed");
        }

        std::vector<std::shared_ptr<OpState>> ops;
        std::uint64_t reserved = 0;
        {
            std::lock_guard<std::mutex> lock(group->groupMutex);
            if (group->phase != GroupState::Phase::Building)
            {
                return readyFailure(Cause::InvalidState, "group no longer building");
            }
            if (group->ops.empty())
            {
                group->phase = GroupState::Phase::Done;
            }
            else
            {
                group->phase = GroupState::Phase::Committed;
                group->results.resize(group->ops.size());
                group->remaining = group->ops.size();
                ops = std::move(group->ops);
                group->ops.clear();
                reserved = group->reservedBytes;
                group->reservedBytes = 0;
            }
        }
        if (ops.empty())
        {
            group->complete(Outcome<std::vector<OpResult>>::success({}));
            return GroupTicket(group);
        }

        // No bucket or budget call without a live write path (group.hpp): the runtime is gone, and with it the budget
        // the ops were charged against, so there is nothing to return (as the writer's ReserveHandle); every op drops.
        auto path = group->path.lock();
        if (!path)
        {
            for (const auto& op : ops)
            {
                resolveWithoutPath(op, dropped(Cause::Shutdown));
            }
            return GroupTicket(group);
        }
        auto bucket = group->bucket.lock();
        if (!bucket)
        {
            // The bucket died with the ops charged against it (its client and writers are gone): the runtime-wide
            // `building` and payload go back here, the reserves when the GroupState dies; every op is dropped.
            const std::uint64_t reserves = static_cast<std::uint64_t>(ops.size()) * RESULT_RESERVE;
            path->budget().removeBuilding(reserved);
            path->budget().release(reserved - reserves);
            for (const auto& op : ops)
            {
                path->resolve(op, dropped(Cause::ClientClosed));
            }
            return GroupTicket(group);
        }

        std::optional<Cause> closedAtEnqueue;
        const bool notify = bucket->enqueueGroup(std::move(ops), reserved, &closedAtEnqueue);
        if (const auto& closed = closedAtEnqueue; closed)
        {
            // As submit's closedAtEnqueue: the bucket took the ops anyway; take them back and resolve them.
            for (const auto& pending : bucket->close(*closed))
            {
                path->resolve(pending, dropped(*closed));
            }
            return GroupTicket(group);
        }
        if (notify)
        {
            if (auto scheduler = path->scheduler())
            {
                scheduler->notify(bucket);
            }
        }
        return GroupTicket(group);
    }

    void abandonGroup(GroupState& group)
    {
        std::vector<std::shared_ptr<OpState>> ops; // Dropped after the mutex (each holds the GroupState).
        std::uint64_t reserved = 0;
        {
            std::lock_guard<std::mutex> lock(group.groupMutex);
            if (group.phase != GroupState::Phase::Building)
            {
                return;
            }
            group.phase = GroupState::Phase::Abandoned;
            ops = std::move(group.ops);
            group.ops.clear();
            reserved = group.reservedBytes;
            group.reservedBytes = 0;
            group.reservesHeld = 0; // Returned below with the payload: the destructor returns nothing more.
        }
        if (ops.empty())
        {
            return;
        }
        // No bucket call without a live write path (group.hpp): with the runtime gone the budget is gone too and there
        // is nothing to return; the ops and the counters above are cleared all the same.
        auto path = group.path.lock();
        if (!path)
        {
            return;
        }
        if (auto bucket = group.bucket.lock())
        {
            bucket->cancelGroupReservation(reserved, static_cast<std::uint32_t>(ops.size()));
        }
        else
        {
            path->budget().removeBuilding(reserved);
            path->budget().release(reserved);
        }
    }

    void resolveInGroup(OpState& op, OpResult result)
    {
        auto group = op.group;
        if (!group)
        {
            return;
        }
        std::optional<std::vector<OpResult>> done;
        {
            std::lock_guard<std::mutex> lock(group->groupMutex);
            if (op.groupIndex < group->results.size())
            {
                group->results[op.groupIndex] = std::move(result);
            }
            if (group->remaining > 0 && --group->remaining == 0)
            {
                group->phase = GroupState::Phase::Done;
                done = std::move(group->results);
                group->results.clear();
            }
        }
        if (done)
        {
            group->complete(Outcome<std::vector<OpResult>>::success(std::move(*done)));
        }
    }
} // namespace indexer_client::detail::write
