/*
 * Wazuh Syscheckd — turning a staged batch into a reconcile action
 * (#37532 / #37396).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * This file exists to make one rule impossible to break by accident:
 *
 *   **A path batch may never authorise delete detection.**
 *
 * That is D15 (12-blocking-decisions.md), and it is a rule rather than a
 * judgement call because the three reasons a staged path can fail to resolve
 * inside a container are indistinguishable at the moment of the read:
 *
 *   1. The file really was deleted            -> a DELETE is correct.
 *   2. It was a C22 host-form path artifact   -> a DELETE is a false positive
 *                                                on a file that is fine.
 *   3. The container restarted, or its PID is momentarily unresolvable
 *                                             -> a MASS false positive, which
 *                                                is C15 all over again.
 *
 * Two of the three are wrong, and both wrong ones fail in the damaging
 * direction: telling an operator a file vanished when it did not. So a path
 * reconcile upserts what it can read and leaves everything else alone. Real
 * deletions are found by a walk, which sees whole directories and can tell
 * absence from unreadability.
 *
 * The cost is honest and belongs in the record: a file deleted inside a
 * container is not reported until the next walk of that container. That is a
 * real detection gap. It is also the gap the module already has today, and it
 * is strictly better than emitting deletions that are wrong.
 *
 * `may_detect_deletions` is NECESSARY, NOT SUFFICIENT. A walk that sets it
 * still has to complete: container_baseline_fim.cpp's ScopedContainerTxn only
 * calls fim_db_transaction_deleted_rows() for a scan reported complete, and
 * closes plainly otherwise, so a partial walk cannot delete either. This flag
 * decides whether delete detection is on the table at all.
 */

#ifndef _CONTAINER_RECONCILE_PLAN_HPP
#define _CONTAINER_RECONCILE_PLAN_HPP

#include "container_event_staging.hpp"

#include <string>
#include <vector>

namespace fim_container_events
{

enum class ReconcileMode
{
    /* Nothing is known about what changed — unattributable kernel loss, or
     * cgroups the map had no room to queue. Re-baseline every container. */
    rebaselineAll,

    /* One container changed in ways that cannot be enumerated: reported loss,
     * a rename (C21), a staging budget overflow, or events that arrived before
     * the container was identified. Walk it. */
    rewalkContainer,

    /* A known, complete set of paths changed in a known container. Re-read
     * exactly those. */
    rereadPaths,

    /* The kernel reported these paths UNLINKED in a known container. Delete
     * exactly those rows.
     *
     * This is NOT the inference D15 forbids, and the distinction is the whole
     * point: D15 refuses to read a FAILED READ as a removal, because a failed
     * read has three causes and two of them are wrong. RT_EV_FILE_UNLINK is the
     * kernel stating the removal, so there is nothing to infer. Discarding it
     * and then re-deriving "deleted" from a read that finds nothing — which is
     * what the spike branch did — is exactly backwards. */
    deletePaths,

    /* container_instances states this container no longer exists. Delete every
     * row it still holds, and then the context describing it — in that order,
     * because the DELETE events are built from that context.
     *
     * Not the inference D15 forbids, and it rests on the same ground as
     * deletePaths above: the connector is STATING the removal, after its own
     * removal grace has expired. Nothing is derived from a read that found
     * nothing. `may_detect_deletions` stays false, because that flag governs
     * whether a WALK may treat absent rows as deletions and there is no walk
     * here. */
    containerGone,

    /* The periodic reconciliation floor. Obtain the whole-node container list
     * and, only if the connector answered, sweep rows and contexts for
     * containers absent from it, then prune contexts an interrupted sweep left
     * behind.
     *
     * Carries no container_id: the list is the input. Needed in addition to
     * containerGone because a resync carries no removal events, and because no
     * notification can report a container the module never learned about. */
    sweepAbsent,
};

struct ReconcileRequest
{
    ReconcileMode mode{ReconcileMode::rereadPaths};

    /* Empty for rebaselineAll. */
    std::string container_id;

    /* Populated for rereadPaths (paths to re-read) and for deletePaths (rows to
     * remove). One list, because the mode already says which it is. */
    std::vector<std::string> paths;

    /* Whether this action may use delete detection AT ALL. False for every
     * path reconcile, without exception — see this file's header. */
    bool may_detect_deletions{false};

    /* Nothing to do. A path batch that carries no paths is a no-op, and
     * deliberately NOT promoted to a walk: promoting it would turn "I have
     * nothing to reconcile" into "delete whatever I cannot find", which is the
     * exact inference D15 forbids. */
    bool empty() const
    {
        return (mode == ReconcileMode::rereadPaths || mode == ReconcileMode::deletePaths) && paths.empty();
    }
};

inline ReconcileRequest PlanFor(const Batch& batch)
{
    ReconcileRequest request;

    /* Reconciliation before collection. A removal supersedes anything else
     * staged for that container (the staging buffer drops it on the way in),
     * and neither of these may ever authorise a WALK to derive deletions:
     * `may_detect_deletions` stays false for both, which is what keeps
     * "only a walk may authorise deletion" true. The deletions these perform
     * are stated by the connector, not inferred from a read. */
    if (batch.lifecycle == Batch::Lifecycle::containerGone)
    {
        request.mode = ReconcileMode::containerGone;
        request.container_id = batch.container_id;
        return request;
    }

    if (batch.lifecycle == Batch::Lifecycle::sweepAbsent)
    {
        request.mode = ReconcileMode::sweepAbsent;
        return request;
    }

    if (batch.suspect)
    {
        /* A walk sees whole directories, so it can tell a deleted file from an
         * unreadable one. This is the only place deletions may come from. */
        request.may_detect_deletions = true;
        request.container_id = batch.container_id;
        request.mode =
            batch.container_id.empty() ? ReconcileMode::rebaselineAll : ReconcileMode::rewalkContainer;
        return request;
    }

    request.container_id = batch.container_id;

    /* may_detect_deletions stays FALSE for both of these. It governs whether a
     * walk may derive deletions from ABSENT rows, which neither of them does:
     * a re-read never deletes, and an unlink deletes one named row because an
     * event named it. */
    request.may_detect_deletions = false;

    if (!batch.unlinked.empty())
    {
        request.mode = ReconcileMode::deletePaths;
        request.paths = batch.unlinked;
        return request;
    }

    request.mode = ReconcileMode::rereadPaths;
    request.paths = batch.paths;
    return request;
}

} // namespace fim_container_events

#endif /* _CONTAINER_RECONCILE_PLAN_HPP */
