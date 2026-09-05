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
};

struct ReconcileRequest
{
    ReconcileMode mode{ReconcileMode::rereadPaths};

    /* Empty for rebaselineAll. */
    std::string container_id;

    /* Only populated for rereadPaths. */
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
        return mode == ReconcileMode::rereadPaths && paths.empty();
    }
};

inline ReconcileRequest PlanFor(const Batch& batch)
{
    ReconcileRequest request;

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

    request.mode = ReconcileMode::rereadPaths;
    request.container_id = batch.container_id;
    request.paths = batch.paths;
    request.may_detect_deletions = false;
    return request;
}

} // namespace fim_container_events

#endif /* _CONTAINER_RECONCILE_PLAN_HPP */
