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

#ifndef _INDEXER_CLIENT_WRITE_GROUP_HPP
#define _INDEXER_CLIENT_WRITE_GROUP_HPP

// Confirmable groups. NORMATIVE.
//
// States (GroupState::phase, under GroupState::groupMutex): Building → Committed → Done, or Building → Abandoned.
// A Group is single-owner (not thread-safe); two groups may be built concurrently from different threads.
//
// Lifetime rule: no call into the bucket or the budget without a live WritePath (GroupState::path locked first and
// held across the call): the bucket references its budget, which the WritePath owns, and a Group may outlive
// RuntimeOwner::shutdown() while its Client lives. Without a path: add ⇒ Shutdown; commit ⇒ every op resolves
// Dropped(Shutdown) without touching the bucket; abandonment ⇒ the ops and counters are cleared, nothing is returned
// (as ~GroupState and a TicketState's armed reserve). With a live path the bucket may still be gone: see each step
// below.
//
// add(op), Building only (else InvalidState); no path ⇒ Shutdown; no bucket (its client is gone) ⇒ Unavailable; then
// the effective conflict policy and encode() exactly as submit (failure ⇒ InvalidArgument, reason kept for
// Group::lastAddReason()); then Bucket::reserveForGroup(payload, wire, reservedBytes, blockUntil) (bucket.hpp). On
// success a new OpState (no ticket, no callback, `group` = this GroupState (strong), `groupIndex` = its position,
// `conflictRetry`, `reserveCharged`) is appended to GroupState::ops; reservedBytes += payload + RESULT_RESERVE;
// reservesHeld += 1. The op stays charged and outside the bucket's queue until commit. GroupState holds the ops ONLY
// while Building (commit moves them out): an OpState → GroupState reference never cycles.
//
// commit(): the first call only (else a ready ticket with InvalidState, as before). No op ⇒ Done at once, success with
// an empty vector. Otherwise Committed: results.resize(n), remaining = n, then Bucket::enqueueGroup(ops, reservedBytes)
// (one lock: out of `building`, a sequence number per op, flushSeq = the last, and a scheduler notification asked for
// whatever the thresholds — the group leaves now) and Scheduler::notify when it says so. A bucket closed by
// then hands the ops back (the only reservation→append window left) and they resolve Dropped(cause) through
// WritePath::resolve. With the bucket gone (path alive) the global `building` and payload go back to the budget and
// every op resolves Dropped(ClientClosed) through WritePath::resolve. The returned GroupTicket shares this GroupState.
// A null state (a moved-from or default Group) yields a ready ticket with InvalidState ("empty group handle").
//
// Resolution: WritePath::resolve, after winning the op's claim and releasing its payload (bucket mutex, then dropped),
// calls resolveInGroup: results[groupIndex] = result and --remaining under groupMutex; the resolution that takes
// remaining to 0 sets Done and completes the GroupTicket (success, results in add order) with no lock held and no
// pool task (there is no callback). A requeued op (retry lane, split) is not resolved: the ticket waits for it.
// Committed ops are ordinary pending ops (DropOldest may evict them; shutdown and close sweep them). Never resolve a
// Building op through WritePath::resolve (its results vector is empty until commit: the result would be lost and the
// ticket never complete); cancel(tag) must go through the abandon path or refuse Building groups.
//
// Reserves: payload is released per op by its resolution, as for submit. The reservesHeld × RESULT_RESERVE return
// when the GroupState dies (last of Group, GroupTicket and the OpStates), through the weak path/bucket pair exactly
// like a TicketState's armed reserve (bucket gone ⇒ the global budget gets them back; path gone ⇒ nothing to return).
//
// Abandonment: ~Group() (or move-assignment over it) of a Building group ⇒ abandonGroup: Abandoned, then one
// Bucket::cancelGroupReservation(reservedBytes, ops.size()) (charge, `building` bucket and global, the global cap,
// wake-ups; stats groupAbandoned and resolvedDropped), ops cleared, reservedBytes = 0 and reservesHeld = 0 (so the
// destructor returns nothing more). Without a bucket (gone) the global part is returned through the budget; without a
// path nothing is returned (lifetime rule).
//
// Lock order: groupMutex is a leaf: never held while calling a bucket, the scheduler, WritePath or the budget, and
// never taken under a bucket mutex. Re-entrancy: a Block add from a runtime thread is Reentrancy
// (reserveForGroup); GroupTicket::wait from one is Reentrancy (tickets.cpp).

#include <memory>

#include "indexer_client/client.hpp"
#include "indexer_client/types.hpp"

namespace indexer_client::detail
{
    struct ClientState;
    struct GroupState;
} // namespace indexer_client::detail

namespace indexer_client::detail::write
{
    class Bucket;
    class WritePath;
    struct OpState;

    /// A new Building group of `bucket` (Writer::group()).
    std::shared_ptr<GroupState>
    makeGroup(std::shared_ptr<ClientState> client, std::shared_ptr<Bucket> bucket, std::shared_ptr<WritePath> path);
    /// Takes the shared GroupState: the new OpState holds it strongly (OpState::group).
    Cause addToGroup(const std::shared_ptr<GroupState>& group, Op op);
    GroupTicket commitGroup(const std::shared_ptr<GroupState>& group);
    void abandonGroup(GroupState& group);
    /// From WritePath::resolve for an op with OpState::group set (after the claim and the payload release).
    void resolveInGroup(OpState& op, OpResult result);
} // namespace indexer_client::detail::write

#endif // _INDEXER_CLIENT_WRITE_GROUP_HPP
