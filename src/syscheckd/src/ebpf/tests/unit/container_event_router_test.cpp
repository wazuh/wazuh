/*
 * Wazuh Syscheckd — unit tests for the eBPF drain's routing policy
 * (#37532 / #37396).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The load-bearing test in here is HostCgroupDropStormNeverEscalatesGlobally.
 * Every other property is a straightforward mapping; that one encodes the
 * failure mode that would make the whole consumer unusable in production, and
 * it is not visible from any single-event test.
 */

#include "container_event_router.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

using namespace fim_container_events;

namespace
{

constexpr std::size_t kMaxPaths = 64;
constexpr std::size_t kMaxContainers = 32;

/* Everything the consumer would see, in the order it would see it. */
std::vector<Batch> DrainBatches(ContainerEventStaging& staging)
{
    std::vector<Batch> out;
    Batch batch;

    while (staging.nextBatch(batch, 0))
    {
        out.push_back(batch);
    }

    return out;
}

const Batch* FindBatch(const std::vector<Batch>& batches, const std::string& container_id)
{
    const auto it = std::find_if(batches.begin(),
                                 batches.end(),
                                 [&container_id](const Batch& b) { return b.container_id == container_id; });
    return it == batches.end() ? nullptr : &*it;
}

struct Fixture
{
    CgroupContainerMap map;
    ContainerEventStaging staging{kMaxPaths, kMaxContainers};
    ContainerEventRouter router{map, staging};
};

} // namespace

TEST(ContainerEventRouterTest, AKnownContainersEventIsStagedForReconcile)
{
    Fixture f;
    f.router.applyContainerList({{10, "container-a"}});

    EXPECT_TRUE(f.router.onEvent(10, "/etc/passwd"));

    f.staging.release();
    const auto batches = DrainBatches(f.staging);

    ASSERT_EQ(1u, batches.size());
    EXPECT_EQ("container-a", batches[0].container_id);
    EXPECT_FALSE(batches[0].suspect);
    ASSERT_EQ(1u, batches[0].paths.size());
    EXPECT_EQ("/etc/passwd", batches[0].paths[0]);
    EXPECT_EQ(1u, f.router.stats().routed);
}

TEST(ContainerEventRouterTest, AHostCgroupsEventIsDiscarded)
{
    Fixture f;
    f.router.applyNotContainer(20);

    EXPECT_FALSE(f.router.onEvent(20, "/var/log/syslog"));

    f.staging.release();
    EXPECT_TRUE(DrainBatches(f.staging).empty());
    EXPECT_EQ(1u, f.router.stats().host_events);
}

TEST(ContainerEventRouterTest, AnUnidentifiedCgroupsEventQueuesTheCgroupAndStagesNothing)
{
    Fixture f;

    EXPECT_FALSE(f.router.onEvent(30, "/opt/app/config"));

    f.staging.release();
    EXPECT_TRUE(DrainBatches(f.staging).empty());
    EXPECT_EQ(1u, f.router.stats().unattributed);
    EXPECT_EQ(1u, f.map.unresolvedCount());
}

TEST(ContainerEventRouterTest, ACgroupIdentifiedAfterItsEventsIsReWalkedNotReconciled)
{
    Fixture f;

    f.router.onEvent(40, "/etc/shadow");
    f.router.onEvent(40, "/etc/hosts");

    // Those two paths were discarded unattributed and cannot be replayed, so the
    // container is escalated rather than handed an incomplete path set.
    f.router.applyContainerResolution(40, "container-late");

    f.staging.release();
    const auto batches = DrainBatches(f.staging);

    ASSERT_EQ(1u, batches.size());
    EXPECT_EQ("container-late", batches[0].container_id);
    EXPECT_TRUE(batches[0].suspect);
    EXPECT_TRUE(batches[0].paths.empty());
    EXPECT_EQ(1u, f.router.stats().late_escalations);
}

TEST(ContainerEventRouterTest, AContainerFirstSeenInAListRefreshIsAlsoEscalated)
{
    Fixture f;

    f.router.onEvent(50, "/srv/data");
    f.router.applyContainerList({{50, "container-listed-late"}, {51, "container-quiet"}});

    f.staging.release();
    const auto batches = DrainBatches(f.staging);

    ASSERT_EQ(1u, batches.size());
    EXPECT_EQ("container-listed-late", batches[0].container_id);
    EXPECT_TRUE(batches[0].suspect);
}

TEST(ContainerEventRouterTest, AKnownContainersDropsEscalateThatContainerOnly)
{
    Fixture f;
    f.router.applyContainerList({{60, "container-lossy"}, {61, "container-fine"}});

    f.router.onEvent(61, "/a/path");
    f.router.onDrops(60, 17);

    f.staging.release();
    const auto batches = DrainBatches(f.staging);

    ASSERT_EQ(2u, batches.size());

    const auto* lossy = FindBatch(batches, "container-lossy");
    ASSERT_NE(nullptr, lossy);
    EXPECT_TRUE(lossy->suspect);

    const auto* fine = FindBatch(batches, "container-fine");
    ASSERT_NE(nullptr, fine);
    EXPECT_FALSE(fine->suspect);
    EXPECT_EQ(1u, fine->paths.size());

    EXPECT_EQ(1u, f.router.stats().drops_routed);
    EXPECT_EQ(0u, f.router.stats().global_escalations);
}

TEST(ContainerEventRouterTest, AZeroDropCountIsNotLoss)
{
    Fixture f;
    f.router.applyContainerList({{70, "container-a"}});

    f.router.onDrops(70, 0);

    f.staging.release();
    EXPECT_TRUE(DrainBatches(f.staging).empty());
    EXPECT_EQ(0u, f.router.stats().drops_routed);
}

TEST(ContainerEventRouterTest, AHostCgroupsDropsAreDiscarded)
{
    Fixture f;
    f.router.applyNotContainer(80);

    f.router.onDrops(80, 900);

    f.staging.release();
    EXPECT_TRUE(DrainBatches(f.staging).empty());
    EXPECT_EQ(1u, f.router.stats().drops_host);
    EXPECT_EQ(0u, f.router.stats().global_escalations);
}

TEST(ContainerEventRouterTest, HostCgroupDropStormNeverEscalatesGlobally)
{
    Fixture f;
    f.router.applyContainerList({{100, "container-a"}});

    // A busy node in RT_CGROUP_MODE_ALL: the ring carries the whole host, so
    // nearly all loss belongs to host cgroups the resolver has not yet ruled on.
    // Treating "an unknown cgroup dropped something" as "re-baseline the node"
    // would re-walk every container over and over for traffic that is not even
    // in scope.
    for (std::uint64_t cgroup = 1000; cgroup < 6000; ++cgroup)
    {
        f.router.onDrops(cgroup, 42);
    }

    f.staging.release();
    const auto batches = DrainBatches(f.staging);

    EXPECT_TRUE(batches.empty());
    EXPECT_EQ(0u, f.router.stats().global_escalations);
    EXPECT_EQ(5000u, f.router.stats().drops_deferred);
}

TEST(ContainerEventRouterTest, DeferredDropsStillEscalateOnceTheCgroupTurnsOutToBeAContainer)
{
    Fixture f;

    // The loss is recorded against a cgroup nobody has identified yet...
    f.router.onDrops(110, 5);
    ASSERT_EQ(0u, f.router.stats().global_escalations);

    // ...and the moment it resolves to a container, that container is re-walked.
    // This is what makes deferring safe rather than merely quiet.
    f.router.applyContainerResolution(110, "container-was-unknown");

    f.staging.release();
    const auto batches = DrainBatches(f.staging);

    ASSERT_EQ(1u, batches.size());
    EXPECT_EQ("container-was-unknown", batches[0].container_id);
    EXPECT_TRUE(batches[0].suspect);
}

TEST(ContainerEventRouterTest, DeferredDropsFromAHostCgroupResolveToNothing)
{
    Fixture f;

    f.router.onDrops(120, 5);
    f.router.applyNotContainer(120);

    f.staging.release();
    EXPECT_TRUE(DrainBatches(f.staging).empty());
    EXPECT_EQ(0u, f.router.stats().global_escalations);
}

TEST(ContainerEventRouterTest, UnattributableLossEscalatesEverything)
{
    Fixture f;
    f.router.applyContainerList({{130, "container-a"}});
    f.router.onEvent(130, "/some/path");

    // The engine could not pin the loss to any cgroup at all, so nothing is
    // known about what changed.
    f.router.onUnattributedDrops();

    f.staging.release();
    const auto batches = DrainBatches(f.staging);

    ASSERT_FALSE(batches.empty());
    EXPECT_TRUE(batches[0].container_id.empty());
    EXPECT_TRUE(batches[0].suspect);
    EXPECT_EQ(1u, f.router.stats().global_escalations);
}

TEST(ContainerEventRouterTest, ACgroupThatCouldNotEvenBeQueuedEscalatesGloballyOnce)
{
    CgroupContainerMap map(2, 8192);
    ContainerEventStaging staging{kMaxPaths, kMaxContainers};
    ContainerEventRouter router{map, staging};

    router.onEvent(1, "/a");
    router.onEvent(2, "/b");

    // No room to file these, so nobody will ever resolve them and the per-cgroup
    // escalation path cannot fire. This is the one case that must go global.
    router.onEvent(3, "/c");
    router.onEvent(4, "/d");

    ASSERT_EQ(0u, router.stats().global_escalations);

    router.pumpUnknownOverflow();
    EXPECT_EQ(1u, router.stats().global_escalations);

    // Consume-once: a second cycle with no new overflow escalates nothing.
    router.pumpUnknownOverflow();
    EXPECT_EQ(1u, router.stats().global_escalations);
}

TEST(ContainerEventRouterTest, AQuietCycleEscalatesNothing)
{
    Fixture f;
    f.router.applyContainerList({{140, "container-a"}});
    f.router.onEvent(140, "/x");

    f.router.pumpUnknownOverflow();

    EXPECT_EQ(0u, f.router.stats().global_escalations);
}

TEST(ContainerEventRouterTest, ARenameReWalksItsContainerBecauseTheSourcePathIsNeverReported)
{
    Fixture f;
    f.router.applyContainerList({{160, "container-a"}});

    // The engine names only the destination. If this staged /etc/passwd.bak and
    // stopped there, the stored row for /etc/passwd would describe a file that
    // no longer exists and nothing would ever correct it.
    f.router.onRename(160);

    f.staging.release();
    const auto batches = DrainBatches(f.staging);

    ASSERT_EQ(1u, batches.size());
    EXPECT_EQ("container-a", batches[0].container_id);
    EXPECT_TRUE(batches[0].suspect);
    EXPECT_EQ(1u, f.router.stats().renames_routed);
}

TEST(ContainerEventRouterTest, ManyRenamesCoalesceIntoOneReWalk)
{
    Fixture f;
    f.router.applyContainerList({{170, "container-busy"}});

    // A package upgrade renaming a thousand files must not cost a thousand
    // re-walks; Suspect is a set keyed by container.
    for (int i = 0; i < 1000; ++i)
    {
        f.router.onRename(170);
    }

    f.staging.release();
    const auto batches = DrainBatches(f.staging);

    EXPECT_EQ(1u, batches.size());
    EXPECT_EQ(1000u, f.router.stats().renames_routed);
}

TEST(ContainerEventRouterTest, ARenameSupersedesPathsAlreadyStagedForThatContainer)
{
    Fixture f;
    f.router.applyContainerList({{180, "container-a"}});

    f.router.onEvent(180, "/etc/hosts");
    f.router.onRename(180);

    f.staging.release();
    const auto batches = DrainBatches(f.staging);

    // The re-walk covers /etc/hosts too, so keeping the path list as well would
    // be duplicated work, not extra safety.
    ASSERT_EQ(1u, batches.size());
    EXPECT_TRUE(batches[0].suspect);
    EXPECT_TRUE(batches[0].paths.empty());
}

TEST(ContainerEventRouterTest, AHostCgroupsRenameIsDiscarded)
{
    Fixture f;
    f.router.applyNotContainer(190);

    f.router.onRename(190);

    f.staging.release();
    EXPECT_TRUE(DrainBatches(f.staging).empty());
    EXPECT_EQ(0u, f.router.stats().renames_routed);
    EXPECT_EQ(0u, f.router.stats().global_escalations);
}

TEST(ContainerEventRouterTest, AnEventForACgroupWhoseContainerDiedIsNoLongerAttributed)
{
    Fixture f;
    f.router.applyContainerList({{150, "container-gone"}});
    ASSERT_TRUE(f.router.onEvent(150, "/before"));

    // The container is gone; its cgroup inode may already belong to something
    // else. Attributing to it would file a stranger's events under a dead id.
    f.router.applyContainerList({});

    EXPECT_FALSE(f.router.onEvent(150, "/after"));

    f.staging.release();
    const auto batches = DrainBatches(f.staging);

    ASSERT_EQ(1u, batches.size());
    ASSERT_EQ(1u, batches[0].paths.size());
    EXPECT_EQ("/before", batches[0].paths[0]);
}
