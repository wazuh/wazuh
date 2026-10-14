/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * D5's FIM half (#40329): a container that container_instances reports GONE has
 * every row it still holds deleted, promptly.
 *
 * Before this, the only thing that swept those rows was the whole-node baseline
 * — which runs once, at startup. Measured on a real node: 50 containers removed
 * at 18:38 still held 91,416 of the 100,000 rows in `file_entry` two hours
 * later, and a full `file_entry` refuses EVERY insert, host rows included. The
 * sweep itself took under 40 seconds when forced, so the constraint was never
 * cost; it was cadence.
 *
 * Nine properties, each of which a plausible refactor would break:
 *
 *   1. A removal plans a purge of exactly that container, and is not a no-op.
 *   2. A purge with NO container id is refused at every layer. The host's own
 *      rows are stored with container_id = '', so an empty id does not mean
 *      "no container" — it means every file the agent monitors on the host.
 *   3. A removal supersedes that container's staged paths, pending unlinks and
 *      suspect mark. A walk of a container that is gone cannot succeed, and the
 *      walker KEEPS the rows of a container it cannot reach, so a walk left
 *      queued behind a removal is what reinstates the leak.
 *   4. ...and supersedes nothing belonging to any other container.
 *   5. Nothing can be staged for a container while its removal is queued.
 *   6. A removal is served before every other kind of work, including a
 *      whole-node re-baseline: at a full table the re-baseline's own inserts
 *      are all refused, which marks every container partial and suppresses
 *      delete detection for all of them, and it only reaches its sweep at the
 *      very end — after the refusals the purge would have prevented.
 *   7. A removal is served exactly once, and the id stages normally afterwards.
 *   8. The `removed` discriminator does not leak into the next batch through
 *      the Batch the consumer reuses.
 *   9. A removal is never inferred: only onContainerRemoved() produces one, and
 *      the reconciliation floor is a different action with no container id.
 *
 * Standalone, like tests/unlink/, tests/txn/, tests/alert/ and tests/settle/:
 * `make check`. ContainerEventStaging and ContainerReconcilePlan are
 * header-only, so this needs nothing built.
 */

#include "container_reconcile_plan.hpp"

#include <cstdio>
#include <string>
#include <vector>

using fim_container_events::Batch;
using fim_container_events::ContainerEventStaging;
using fim_container_events::PlanFor;
using fim_container_events::ReconcileMode;

namespace {

int g_failures = 0;

void Check(bool condition, const char* what)
{
    std::printf("  %-70s %s\n", what, condition ? "OK" : "FAIL");
    if (!condition) ++g_failures;
}

/// Every pid is alive, so nothing here is released by the settle's early path.
fim_container_events::PidAliveFn AlwaysAlive()
{
    return [](unsigned int) { return true; };
}

// --------------------------------------------------------------------- cases --

void CaseRemovalPlansAPurge()
{
    std::printf("case 1: a removal plans a purge of exactly that container\n");

    ContainerEventStaging staging(1024, 128, 0, AlwaysAlive());
    staging.release();
    staging.onContainerRemoved("c1");

    Batch batch;
    Check(staging.nextBatch(batch, 0), "served");
    Check(batch.removed, "as a removal");
    Check(batch.container_id == "c1", "for the right container");
    Check(batch.paths.empty() && batch.unlinked.empty(), "carrying no paths");
    Check(!batch.suspect, "and not as a re-walk");

    const auto plan = PlanFor(batch);
    Check(plan.mode == ReconcileMode::purgeContainer, "planned as purgeContainer");
    Check(plan.container_id == "c1", "naming the container to purge");
    Check(plan.paths.empty(), "with no path list");
    Check(!plan.empty(), "and it is not a no-op");

    Check(staging.stats().containers_removed == 1, "counted as a removal");
}

void CaseAPurgeWithNoContainerIdIsRefused()
{
    std::printf("case 2: a purge with no container id is refused at every layer\n");

    ContainerEventStaging staging(1024, 128, 0, AlwaysAlive());
    staging.release();

    // Guard 1 — staging.
    staging.onContainerRemoved("");

    Batch batch;
    Check(!staging.nextBatch(batch, 0), "an empty id stages nothing at all");
    Check(staging.stats().containers_removed == 0, "and is not counted as a removal");
    Check(staging.pendingContainers() == 0, "and leaves nothing pending");

    // Guard 2 — the plan. Reached if a future caller builds the batch directly.
    Batch forged;
    forged.removed = true;
    forged.container_id.clear();

    const auto plan = PlanFor(forged);
    Check(plan.mode == ReconcileMode::purgeContainer, "a forged empty-id batch still plans a purge");
    Check(plan.empty(), "but the plan reports itself EMPTY, so the consumer drops it");
    Check(plan.container_id.empty(), "and it names no container, which is the whole point");
}

void CaseRemovalSupersedesThatContainersWork()
{
    std::printf("case 3: a removal supersedes that container's staged work\n");

    ContainerEventStaging staging(1024, 128, 0, AlwaysAlive());
    staging.release();

    staging.onEvent("c1", "/etc/issue", 7);
    staging.onUnlink("c1", "/etc/hosts");
    staging.onDrops("c1");
    staging.onContainerRemoved("c1");

    Batch batch;
    Check(staging.nextBatch(batch, 0), "served");
    Check(batch.removed, "as a removal");
    Check(batch.container_id == "c1", "for the right container");
    Check(batch.paths.empty(), "with no re-read left over");
    Check(batch.unlinked.empty(), "with no unlink left over");
    Check(!batch.suspect, "and NOT as a re-walk, which could not reach it anyway");

    Check(!staging.nextBatch(batch, 0), "and nothing is left behind it");
    Check(staging.pendingContainers() == 0, "no container left pending");
}

void CaseRemovalLeavesOtherContainersAlone()
{
    std::printf("case 4: a removal supersedes nothing belonging to another container\n");

    ContainerEventStaging staging(1024, 128, 0, AlwaysAlive());
    staging.release();

    staging.onEvent("c2", "/etc/issue", 7);
    staging.onContainerRemoved("c1");

    Batch batch;
    Check(staging.nextBatch(batch, 0), "first batch served");
    Check(batch.removed && batch.container_id == "c1", "and it is the removal");

    Check(staging.nextBatch(batch, 0), "second batch served");
    Check(!batch.removed, "and it is not a removal");
    Check(batch.container_id == "c2", "for the untouched container");
    Check(batch.paths.size() == 1 && batch.paths[0] == "/etc/issue", "with its path intact");
}

void CaseNothingStagesWhileARemovalIsQueued()
{
    std::printf("case 5: nothing stages for a container while its removal is queued\n");

    ContainerEventStaging staging(1024, 128, 0, AlwaysAlive());
    staging.release();

    staging.onContainerRemoved("c1");

    const auto before = staging.stats();

    staging.onEvent("c1", "/etc/issue", 7);
    staging.onUnlink("c1", "/etc/hosts");
    staging.onDrops("c1");

    const auto after = staging.stats();

    Check(after.staged == before.staged, "a write stages nothing");
    Check(after.unlinked == before.unlinked, "an unlink stages nothing");
    Check(after.drop_escalations == before.drop_escalations, "a drop report escalates nothing");
    Check(after.deduplicated == before.deduplicated + 3, "all three are counted as deduplicated");

    Batch batch;
    Check(staging.nextBatch(batch, 0), "served");
    Check(batch.removed && batch.container_id == "c1", "as the removal");
    Check(!staging.nextBatch(batch, 0), "and nothing else at all");
}

void CaseRemovalsAreServedFirst()
{
    std::printf("case 6: a removal is served before every other kind of work\n");

    ContainerEventStaging staging(1024, 128, 0, AlwaysAlive());
    staging.release();

    staging.onEvent("c2", "/etc/issue", 7);  // a staged path
    staging.onUnlink("c3", "/etc/hosts");    // an unlink
    staging.onDrops("c4");                   // a container re-walk
    staging.onUnattributedDrops();           // a WHOLE-NODE re-baseline
    staging.onContainerRemoved("c1");        // and the removal, staged last

    Batch batch;
    Check(staging.nextBatch(batch, 0), "first batch served");
    Check(batch.removed, "and it is the removal");
    Check(batch.container_id == "c1", "for the removed container");

    Check(staging.nextBatch(batch, 0), "second batch served");
    Check(batch.suspect && batch.container_id.empty(), "and only THEN the whole-node re-baseline");
}

void CaseRemovalsAreNotChargedToTheContainerBudget()
{
    std::printf("case 7: a removal is not refused when the container budget is full\n");

    // max_containers = 2, both consumed by staged paths.
    ContainerEventStaging staging(1024, 2, 0, AlwaysAlive());
    staging.release();

    staging.onEvent("c2", "/etc/issue", 7);
    staging.onEvent("c3", "/etc/issue", 7);

    const auto before = staging.stats();
    Check(before.unknown_overflows == 0, "the budget is full but nothing has overflowed yet");

    staging.onContainerRemoved("c1");

    const auto after = staging.stats();
    Check(after.containers_removed == 1, "the removal is accepted anyway");
    Check(after.unknown_overflows == before.unknown_overflows,
          "and does NOT escalate the node to a re-baseline");

    Batch batch;
    Check(staging.nextBatch(batch, 0), "served");
    Check(batch.removed && batch.container_id == "c1", "as the removal, first");
}

void CaseRemovalIsServedOnceThenNormal()
{
    std::printf("case 8: a removal is served exactly once, then the id behaves normally\n");

    ContainerEventStaging staging(1024, 128, 0, AlwaysAlive());
    staging.release();

    staging.onContainerRemoved("c1");

    Batch batch;
    Check(staging.nextBatch(batch, 0), "served once");
    Check(batch.removed, "as a removal");
    Check(!staging.nextBatch(batch, 0), "and not a second time");

    // A container id is unique, so this is defensive rather than expected: what
    // matters is that the buffer holds no tombstone that would silently swallow
    // later work.
    staging.onEvent("c1", "/etc/issue", 7);
    Check(staging.nextBatch(batch, 0), "a later event for the same id is served");
    Check(!batch.removed, "and is not a removal");
    Check(batch.paths.size() == 1, "but an ordinary re-read");
}

void CaseTheDiscriminatorDoesNotLeak()
{
    std::printf("case 9: the removal flag does not leak into the next batch\n");

    ContainerEventStaging staging(1024, 128, 0, AlwaysAlive());
    staging.release();

    staging.onContainerRemoved("c1");
    staging.onEvent("c2", "/etc/issue", 7);

    // ONE Batch, reused — exactly what the consumer loop does.
    Batch batch;

    Check(staging.nextBatch(batch, 0), "first batch served");
    Check(batch.removed, "as the removal");

    Check(staging.nextBatch(batch, 0), "second batch served through the SAME Batch");
    Check(!batch.removed, "and the removal flag is cleared");
    Check(batch.container_id == "c2", "for the live container");

    const auto plan = PlanFor(batch);
    Check(plan.mode == ReconcileMode::rereadPaths, "so the live container is re-read");
    Check(plan.mode != ReconcileMode::purgeContainer, "and NOT purged");
}

void CaseTheFloorIsADifferentAction()
{
    std::printf("case 10: the reconciliation floor is a separate, container-less action\n");

    ContainerEventStaging staging(1024, 128, 0, AlwaysAlive());
    staging.release();

    staging.onReconcileFloorDue();

    Batch batch;
    Check(staging.nextBatch(batch, 0), "served");
    Check(batch.sweep_absent, "as a sweep");
    Check(!batch.removed, "and not as a removal of some container");
    Check(batch.container_id.empty(), "naming no container");

    const auto plan = PlanFor(batch);
    Check(plan.mode == ReconcileMode::sweepAbsent, "planned as sweepAbsent");
    Check(!plan.empty(), "and it is not a no-op despite having no container id");

    Check(!staging.nextBatch(batch, 0), "served once per time it falls due");

    // Idempotent: asking twice before it is served is one pass, not two.
    staging.onReconcileFloorDue();
    staging.onReconcileFloorDue();
    Check(staging.nextBatch(batch, 0), "two requests are served");
    Check(!staging.nextBatch(batch, 0), "as ONE sweep");
}

} // namespace

int main()
{
    CaseRemovalPlansAPurge();
    CaseAPurgeWithNoContainerIdIsRefused();
    CaseRemovalSupersedesThatContainersWork();
    CaseRemovalLeavesOtherContainersAlone();
    CaseNothingStagesWhileARemovalIsQueued();
    CaseRemovalsAreServedFirst();
    CaseRemovalsAreNotChargedToTheContainerBudget();
    CaseRemovalIsServedOnceThenNormal();
    CaseTheDiscriminatorDoesNotLeak();
    CaseTheFloorIsADifferentAction();

    std::printf("\n%s\n", g_failures == 0 ? "ALL OK" : "FAILURES");
    return g_failures == 0 ? 0 : 1;
}
