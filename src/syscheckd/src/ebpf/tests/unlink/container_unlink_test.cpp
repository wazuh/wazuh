/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * D17's unlink half (#37532, WP3 of 14-spike-integration-plan).
 *
 * RT_EV_FILE_UNLINK names the file the kernel removed. Staging it as an
 * ordinary changed path made the re-read find nothing and — correctly, under
 * D15 — do nothing, so an in-container `rm` was not reported until something
 * else forced a walk of that container. Acting on the event is not the
 * inference D15 forbids: D15 refuses to read a FAILED READ as a removal,
 * because a failed read has three causes and two of them are wrong. There is
 * nothing to infer from an event that states the removal.
 *
 * Eight properties, each of which a plausible refactor would break:
 *
 *   1. An unlink plans a deletePaths action, and never authorises delete
 *      DETECTION (deriving removals from absent rows) on the way.
 *   2. An unlink supersedes a pending re-read of the same path: re-reading a
 *      file that has just been removed can only find nothing.
 *   3. A write AFTER an unlink supersedes it. The file exists again, so the
 *      pending delete is wrong. The newer event wins in both directions.
 *   4. Unlinks are not held by the settle. Waiting for a removed file to
 *      settle and then failing to read it is precisely the shape D15 rejects.
 *   5. A re-walk supersedes pending unlinks — a walk finds those deletions on
 *      its own, so the list is redundant and the memory is better freed.
 *   6. Unlinks are served before staged paths.
 *   7. Overflowing the unlink budget escalates to a re-walk rather than
 *      dropping paths, the same rule staged paths follow.
 *   8. An empty batch stays empty rather than being promoted to a walk.
 *
 * Standalone, like tests/txn/, tests/alert/ and tests/settle/: `make check`.
 * ContainerEventStaging and ContainerReconcilePlan are header-only, so this
 * needs nothing built.
 */

#include "container_reconcile_plan.hpp"

#include <chrono>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

using fim_container_events::Batch;
using fim_container_events::ContainerEventStaging;
using fim_container_events::PlanFor;
using fim_container_events::ReconcileMode;
using Clock = std::chrono::steady_clock;

namespace {

int g_failures = 0;

void Check(bool condition, const char* what)
{
    std::printf("  %-70s %s\n", what, condition ? "OK" : "FAIL");
    if (!condition) ++g_failures;
}

/// Every pid is alive, so nothing here can be released by the settle's early
/// path — only by a deadline, or by not being subject to the settle at all.
fim_container_events::PidAliveFn AlwaysAlive()
{
    return [](unsigned int) { return true; };
}

bool Contains(const std::vector<std::string>& haystack, const char* needle)
{
    for (const auto& item : haystack)
    {
        if (item == needle) return true;
    }
    return false;
}

// --------------------------------------------------------------------- cases --

void CaseUnlinkPlansADelete()
{
    std::printf("case 1: an unlink plans a delete of exactly that path\n");

    ContainerEventStaging staging(1024, 128, 0, AlwaysAlive());
    staging.release();
    staging.onUnlink("c1", "/etc/issue");

    Batch batch;
    Check(staging.nextBatch(batch, 0), "served");
    Check(batch.unlinked.size() == 1 && batch.unlinked[0] == "/etc/issue", "as an unlinked path");
    Check(batch.paths.empty(), "and not as a re-read");
    Check(!batch.suspect, "and not as a re-walk");

    const auto plan = PlanFor(batch);
    Check(plan.mode == ReconcileMode::deletePaths, "planned as deletePaths");
    Check(plan.container_id == "c1", "for the right container");
    Check(plan.paths.size() == 1 && plan.paths[0] == "/etc/issue", "carrying the path");
    Check(!plan.may_detect_deletions, "without authorising delete DETECTION");
    Check(!plan.empty(), "and it is not a no-op");

    Check(staging.stats().unlinked == 1, "counted as an unlink");
}

void CaseUnlinkSupersedesAPendingReRead()
{
    std::printf("case 2: an unlink supersedes a pending re-read of the same path\n");

    ContainerEventStaging staging(1024, 128, 0, AlwaysAlive());
    staging.release();

    staging.onEvent("c1", "/etc/issue", 7);
    staging.onUnlink("c1", "/etc/issue");

    Batch batch;
    Check(staging.nextBatch(batch, 0), "served");
    Check(batch.unlinked.size() == 1 && batch.unlinked[0] == "/etc/issue", "as an unlink");

    // Nothing must be left behind as a re-read of a file that is gone.
    Check(!staging.nextBatch(batch, 0), "and the re-read is gone with it");
    Check(staging.pendingContainers() == 0, "no container left pending");
}

void CaseWriteAfterUnlinkSupersedesIt()
{
    std::printf("case 3: a write after an unlink supersedes the delete\n");

    ContainerEventStaging staging(1024, 128, 0, AlwaysAlive());
    staging.release();

    staging.onUnlink("c1", "/etc/issue");
    staging.onEvent("c1", "/etc/issue", 7); // re-created

    Batch batch;
    Check(staging.nextBatch(batch, 0), "served");
    Check(batch.paths.size() == 1 && batch.paths[0] == "/etc/issue", "as a re-read");
    Check(batch.unlinked.empty(), "with no pending delete");
    Check(!staging.nextBatch(batch, 0), "and nothing is left");
}

void CaseUnlinksAreNotSettled()
{
    std::printf("case 4: unlinks are not held by the settle\n");

    // A 5s settle and a pid that never exits: a staged path would be stuck.
    ContainerEventStaging staging(1024, 128, 5000, AlwaysAlive());
    staging.release();

    staging.onEvent("c1", "/etc/held", 7);
    staging.onUnlink("c1", "/etc/removed");

    const auto start = Clock::now();
    Batch batch;
    Check(staging.nextBatch(batch, 500), "served well inside the settle delay");
    Check(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count() < 300,
          "and promptly");
    Check(batch.unlinked.size() == 1 && batch.unlinked[0] == "/etc/removed", "the unlinked path");
    Check(batch.paths.empty(), "without dragging the settling path out with it");
}

void CaseReWalkSupersedesUnlinks()
{
    std::printf("case 5: a re-walk supersedes pending unlinks\n");

    ContainerEventStaging staging(1024, 128, 0, AlwaysAlive());
    staging.release();

    staging.onUnlink("c1", "/etc/a");
    staging.onUnlink("c1", "/etc/b");
    staging.onDrops("c1"); // reported loss: the container must be re-walked

    // Absorbed: while c1 is marked suspect, a further unlink adds nothing,
    // because the pending re-walk already finds that deletion.
    staging.onUnlink("c1", "/etc/c");

    Batch batch;
    Check(staging.nextBatch(batch, 0), "served");
    Check(batch.suspect, "as a re-walk");
    Check(batch.unlinked.empty(), "with the unlink list dropped");
    Check(staging.pendingContainers() == 0, "and nothing left pending");
    Check(!staging.nextBatch(batch, 0), "not even the unlink that arrived after the escalation");
}

void CaseUnlinksAreServedFirst()
{
    std::printf("case 6: unlinks are served before staged paths\n");

    ContainerEventStaging staging(1024, 128, 0, AlwaysAlive());
    staging.release();

    // Different containers, so neither supersedes the other; "a" sorts first,
    // so a plain map order would serve the re-read first.
    staging.onEvent("a", "/etc/changed", 7);
    staging.onUnlink("b", "/etc/removed");

    Batch batch;
    Check(staging.nextBatch(batch, 0), "first batch served");
    Check(!batch.unlinked.empty(), "and it is the unlink");
    Check(batch.container_id == "b", "for container b");

    Check(staging.nextBatch(batch, 0), "second batch served");
    Check(!batch.paths.empty(), "and it is the re-read");
    Check(batch.container_id == "a", "for container a");
}

void CaseUnlinkBudgetEscalates()
{
    std::printf("case 7: exceeding the unlink budget escalates to a re-walk\n");

    ContainerEventStaging staging(4 /* tiny budget */, 128, 0, AlwaysAlive());
    staging.release();

    for (int i = 0; i < 40; ++i)
    {
        staging.onUnlink("c1", "/etc/f" + std::to_string(i));
    }

    Batch batch;
    Check(staging.nextBatch(batch, 0), "served");
    Check(batch.suspect, "as a re-walk, not as a truncated unlink list");
    Check(batch.unlinked.empty(), "with no partial list handed over");
    Check(staging.stats().path_overflows == 1, "counted as one overflow");

    // A re-walk finds every one of those deletions, so nothing is lost.
    const auto plan = PlanFor(batch);
    Check(plan.mode == ReconcileMode::rewalkContainer, "planned as a container re-walk");
    Check(plan.may_detect_deletions, "which is the only action allowed to detect deletions");
}

void CaseEmptyBatchStaysEmpty()
{
    std::printf("case 8: an empty batch is a no-op, not a walk\n");

    Batch batch;
    batch.container_id = "c1";

    const auto plan = PlanFor(batch);
    Check(plan.empty(), "planned as empty");
    Check(plan.mode == ReconcileMode::rereadPaths, "and not promoted to a re-walk");
    Check(!plan.may_detect_deletions, "so it can never delete anything");
}

} // namespace

int main()
{
    CaseUnlinkPlansADelete();
    CaseUnlinkSupersedesAPendingReRead();
    CaseWriteAfterUnlinkSupersedesIt();
    CaseUnlinksAreNotSettled();
    CaseReWalkSupersedesUnlinks();
    CaseUnlinksAreServedFirst();
    CaseUnlinkBudgetEscalates();
    CaseEmptyBatchStaysEmpty();

    std::printf("\n%s\n", g_failures == 0 ? "ALL OK" : "FAILURES");
    return g_failures == 0 ? 0 : 1;
}
