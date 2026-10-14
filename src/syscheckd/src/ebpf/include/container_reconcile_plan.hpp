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
 *
 * Three things may authorise removing a row, and they are different in kind:
 *
 *   a walk              completed, so absence inside it means absence.
 *   RT_EV_FILE_UNLINK   the kernel STATED that one path is gone.
 *   a lifecycle event   container_instances STATED that one container is gone.
 *
 * None of them is "a read found nothing", which is the one D15 forbids. The
 * third arrives from outside the event stream entirely, which is why it does
 * not travel through may_detect_deletions: see purgeContainer below.
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

    /* This container no longer exists: delete every row it still holds.
     *
     * The same distinction as deletePaths, one level up. D15 forbids inferring
     * a removal from a read that found nothing; container_instances STATING
     * that a container has gone is not an inference, and it is not a read at
     * all. It fires only at erase — for a running container that is removal-
     * grace expiry, not the moment it dropped out of a snapshot — so a merely
     * STOPPED container never reaches here, and its rows are left alone to be
     * diffed against when it starts again.
     *
     * container_id is mandatory. An empty one is the HOST's scope, not "no
     * container": see empty() below. */
    purgeContainer,

    /* Reconcile the whole stored set against what container_instances still
     * knows, and delete the rows of anything absent from it. No walk.
     *
     * The floor under purgeContainer, for the removals no notification can
     * report: one that happened while the agent was down, one swallowed by a
     * cursor resync, or a producer that never noticed. Unlike purgeContainer
     * this DOES act on absence, which is why it is the one deletion path gated
     * on the connector having actually answered — an unreachable connector must
     * not present as "no containers exist". Carries no container_id. */
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
        /* A purge names its scope by container_id, so an empty one is not a
         * harmless no-op that falls through: the host's own FIM rows are stored
         * with container_id = '' — that string IS the scope value of the host
         * transaction — so a purge with no id would delete every file the agent
         * monitors on the host. Second of four guards; the others are in
         * ContainerEventStaging::onContainerRemoved(), ReconcileBatch() and
         * PurgeContainerRows(). */
        if (mode == ReconcileMode::purgeContainer)
        {
            return container_id.empty();
        }

        return (mode == ReconcileMode::rereadPaths || mode == ReconcileMode::deletePaths) && paths.empty();
    }
};

inline ReconcileRequest PlanFor(const Batch& batch)
{
    ReconcileRequest request;

    /* Before `suspect`, so a container that is BOTH gone and suspect is purged
     * rather than walked. Walking it cannot succeed — the walker keeps the rows
     * of a container it cannot reach — so the stronger, and the only correct,
     * action wins. */
    if (batch.removed)
    {
        /* True because the purge does exactly what this flag announces: it
         * removes rows it did not refresh. Nothing reads it on this path —
         * ReconcileBatch() dispatches on the mode — but leaving it false would
         * state the opposite of what happens. */
        request.may_detect_deletions = true;
        request.container_id = batch.container_id;
        request.mode = ReconcileMode::purgeContainer;
        return request;
    }

    if (batch.sweep_absent)
    {
        request.may_detect_deletions = true;
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
