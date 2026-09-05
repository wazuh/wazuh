/*
 * Wazuh Syscheckd — unit tests for the eBPF drain's cgroup attribution map
 * (#37532 / #37396).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The tests that matter here are the inode-reuse ones. A cgroup id is a
 * directory inode, and the kernel reuses it once the cgroup is gone, so every
 * cached verdict about an inode has a shelf life. Both directions of a stale
 * verdict are covered, because both are silent in production:
 *
 *   - stale container -> a new container's events filed under a dead id;
 *   - stale "not a container" -> a real container invisible for as long as the
 *     verdict is cached.
 */

#include "cgroup_container_map.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <thread>
#include <vector>

using namespace fim_container_events;

namespace
{

bool Contains(const std::vector<std::uint64_t>& haystack, std::uint64_t needle)
{
    return std::find(haystack.begin(), haystack.end(), needle) != haystack.end();
}

bool Contains(const std::vector<std::string>& haystack, const std::string& needle)
{
    return std::find(haystack.begin(), haystack.end(), needle) != haystack.end();
}

} // namespace

TEST(CgroupContainerMapTest, UnseenCgroupIsUnknownAndQueuedForResolution)
{
    CgroupContainerMap map;

    const auto resolution = map.classify(4242);

    EXPECT_EQ(CgroupClass::unknown, resolution.klass);
    EXPECT_TRUE(resolution.container_id.empty());
    EXPECT_EQ(1u, map.unresolvedCount());
    EXPECT_TRUE(Contains(map.takeUnresolved(), 4242u));
}

TEST(CgroupContainerMapTest, ABusyUnresolvedCgroupIsDispatchedOnceNotOncePerEvent)
{
    CgroupContainerMap map;

    for (int i = 0; i < 1000; ++i)
    {
        map.classify(77);
    }

    // Every event is a miss, but the resolver is asked exactly once: an IPC
    // round-trip per event would be 1000 connects against a 2-worker server.
    EXPECT_EQ(1000u, map.stats().misses);
    EXPECT_EQ(1u, map.unresolvedCount());
    EXPECT_EQ(1u, map.takeUnresolved().size());

    // And a second sweep hands out nothing, because it is already dispatched.
    EXPECT_TRUE(map.takeUnresolved().empty());
}

TEST(CgroupContainerMapTest, RearmRedispatchesACgroupResolutionCouldNotConclude)
{
    CgroupContainerMap map;

    map.classify(9);
    EXPECT_TRUE(Contains(map.takeUnresolved(), 9u));
    EXPECT_TRUE(map.takeUnresolved().empty());

    // container_instances answered `pending` (cold cache): without a rearm the
    // cgroup stays dispatched forever and its container is never discovered.
    map.rearm(9);
    EXPECT_TRUE(Contains(map.takeUnresolved(), 9u));
}

TEST(CgroupContainerMapTest, ResolvedContainerIsReturnedByClassify)
{
    CgroupContainerMap map;

    map.noteContainer(100, "abc123");

    const auto resolution = map.classify(100);
    EXPECT_EQ(CgroupClass::container, resolution.klass);
    EXPECT_EQ("abc123", resolution.container_id);

    // A hit is not a miss, so nothing is queued.
    EXPECT_EQ(0u, map.unresolvedCount());
    EXPECT_EQ(0u, map.stats().misses);
}

TEST(CgroupContainerMapTest, ResolvingACgroupWhoseEventsWereAlreadySeenEscalates)
{
    CgroupContainerMap map;

    // Events arrive before anyone knows this cgroup is a container — the window
    // between a container being created and the connector reporting it.
    map.classify(500);
    map.classify(500);

    EXPECT_TRUE(map.noteContainer(500, "late-container"));
    EXPECT_EQ(1u, map.stats().escalations);

    // Those events were discarded unattributed, so the paths they named are
    // unrecoverable: the caller must re-walk rather than reconcile.
    EXPECT_EQ(0u, map.unresolvedCount());
}

TEST(CgroupContainerMapTest, ResolvingACgroupNoEventsWereSeenForDoesNotEscalate)
{
    CgroupContainerMap map;

    EXPECT_FALSE(map.noteContainer(501, "quiet-container"));
    EXPECT_EQ(0u, map.stats().escalations);
}

TEST(CgroupContainerMapTest, HostCgroupVerdictIsCachedSoItIsNotReResolved)
{
    CgroupContainerMap map;

    map.classify(31337);
    map.noteNotContainer(31337);

    for (int i = 0; i < 100; ++i)
    {
        EXPECT_EQ(CgroupClass::notContainer, map.classify(31337).klass);
    }

    // In RT_CGROUP_MODE_ALL the host produces most events; without this cache
    // each one would queue an IPC round-trip.
    EXPECT_EQ(0u, map.unresolvedCount());
    EXPECT_EQ(100u, map.stats().hits_not_container);
}

TEST(CgroupContainerMapTest, ANotContainerVerdictNeverOverridesAKnownContainer)
{
    CgroupContainerMap map;

    map.noteContainer(700, "live-container");
    map.noteNotContainer(700);

    // Believing the negative here would make a running container's events
    // invisible for as long as it is cached.
    const auto resolution = map.classify(700);
    EXPECT_EQ(CgroupClass::container, resolution.klass);
    EXPECT_EQ("live-container", resolution.container_id);
}

TEST(CgroupContainerMapTest, AContradictedNotContainerVerdictIsNotEvenRecorded)
{
    CgroupContainerMap map;

    map.noteContainer(701, "live-container");
    map.noteNotContainer(701); // contradicts the connector's own list

    // classify() checks containers first, so merely ignoring the verdict would
    // look correct here — until the container goes away and the cached verdict
    // starts answering for whatever inherits inode 701.
    ASSERT_EQ(0u, map.notContainerCount());

    map.install({}); // the container is gone

    EXPECT_EQ(CgroupClass::unknown, map.classify(701).klass);
}

TEST(CgroupContainerMapTest, NoteContainerRejectsTheUnresolvableCgroupIdDirectly)
{
    CgroupContainerMap map;

    // install() screens these out too, but the single-resolution path is reached
    // independently by the resolver draining takeUnresolved().
    EXPECT_FALSE(map.noteContainer(0, "kata-container"));
    EXPECT_EQ(0u, map.containerCount());
}

TEST(CgroupContainerMapTest, TheUnresolvableCgroupIdIsNeverQueuedForResolution)
{
    CgroupContainerMap map;

    for (int i = 0; i < 10; ++i)
    {
        EXPECT_EQ(CgroupClass::unknown, map.classify(0).klass);
    }

    // No resolver can ever answer for id 0, so queueing it would park an
    // immortal entry in the pending set that rearm() keeps redispatching.
    EXPECT_EQ(0u, map.unresolvedCount());
    EXPECT_TRUE(map.takeUnresolved().empty());
}

TEST(CgroupContainerMapTest, InodeReuseHostToContainerClearsTheStaleNegative)
{
    CgroupContainerMap map;

    // Inode 800 was a host cgroup...
    map.noteNotContainer(800);
    ASSERT_EQ(CgroupClass::notContainer, map.classify(800).klass);

    // ...then it was removed and the kernel handed the inode to a container.
    map.noteContainer(800, "reused-inode-container");

    const auto resolution = map.classify(800);
    EXPECT_EQ(CgroupClass::container, resolution.klass);
    EXPECT_EQ("reused-inode-container", resolution.container_id);
    EXPECT_EQ(0u, map.notContainerCount());
}

TEST(CgroupContainerMapTest, InstallReplacesPositivesSoADeadContainerStopsMatching)
{
    CgroupContainerMap map;

    map.install({{900, "container-a"}});
    ASSERT_EQ("container-a", map.classify(900).container_id);

    // container-a is gone. Keeping the entry would file the next occupant of
    // inode 900 under a container that no longer exists.
    map.install({});

    EXPECT_EQ(CgroupClass::unknown, map.classify(900).klass);
    EXPECT_EQ(0u, map.containerCount());
}

TEST(CgroupContainerMapTest, InodeReuseContainerToContainerRepointsTheId)
{
    CgroupContainerMap map;

    map.install({{901, "container-a"}});
    map.install({{901, "container-b"}});

    EXPECT_EQ("container-b", map.classify(901).container_id);
}

TEST(CgroupContainerMapTest, InstallReportsContainersWhoseEventsPrecededIt)
{
    CgroupContainerMap map;

    map.classify(1000); // events from a container the connector had not listed yet
    map.classify(2000); // events from something still unidentified

    const auto escalate = map.install({{1000, "seen-first"}, {3000, "never-seen"}});

    EXPECT_EQ(1u, escalate.size());
    EXPECT_TRUE(Contains(escalate, std::string("seen-first")));
    EXPECT_FALSE(Contains(escalate, std::string("never-seen")));

    // 2000 was not identified, so it stays queued for the resolver.
    EXPECT_EQ(1u, map.unresolvedCount());
}

TEST(CgroupContainerMapTest, InstallIgnoresUnresolvableCgroupIds)
{
    CgroupContainerMap map;

    // cgroup_id 0 is the connector saying "I could not determine it" (cgroup v1,
    // kata, cgroupns-host). Indexing on it would collapse every such container
    // onto one key.
    const auto escalate = map.install({{0, "kata-container"}, {0, "cgroupns-host-container"}, {1, "real"}});

    EXPECT_TRUE(escalate.empty());
    EXPECT_EQ(1u, map.containerCount());
    EXPECT_EQ("real", map.classify(1).container_id);
    EXPECT_EQ(CgroupClass::unknown, map.classify(0).klass);
}

TEST(CgroupContainerMapTest, InstallIgnoresEmptyContainerIds)
{
    CgroupContainerMap map;

    map.install({{1, ""}});

    EXPECT_EQ(0u, map.containerCount());
}

TEST(CgroupContainerMapTest, PendingSetOverflowIsSurfacedExactlyOnce)
{
    CgroupContainerMap map(4, 8192);

    for (std::uint64_t id = 1; id <= 4; ++id)
    {
        map.classify(id);
    }
    ASSERT_FALSE(map.takeUnknownOverflow());

    map.classify(5);
    map.classify(6);

    EXPECT_EQ(4u, map.unresolvedCount());
    EXPECT_EQ(2u, map.stats().unknown_overflows);

    // Consume-once: the caller escalates globally one time, not on every poll.
    EXPECT_TRUE(map.takeUnknownOverflow());
    EXPECT_FALSE(map.takeUnknownOverflow());
}

TEST(CgroupContainerMapTest, NegativeCacheIsDroppedWholeWhenFullAndStaysCorrect)
{
    CgroupContainerMap map(1024, 4);

    for (std::uint64_t id = 1; id <= 4; ++id)
    {
        map.noteNotContainer(id);
    }
    ASSERT_EQ(4u, map.notContainerCount());

    map.noteNotContainer(5);

    // Dropping the cache costs re-resolution, never accuracy: the evicted ids
    // become unknown (re-queued), and the new one is cached.
    EXPECT_EQ(1u, map.notContainerCount());
    EXPECT_EQ(1u, map.stats().negative_cache_resets);
    EXPECT_EQ(CgroupClass::notContainer, map.classify(5).klass);
    EXPECT_EQ(CgroupClass::unknown, map.classify(1).klass);
}

TEST(CgroupContainerMapTest, ClassifyStaysConsistentWhileInstallRunsConcurrently)
{
    CgroupContainerMap map;
    std::atomic<bool> stop{false};
    std::atomic<unsigned long> wrong{0};

    map.install({{10, "container-x"}});

    std::thread reader(
        [&map, &stop, &wrong]
        {
            while (!stop.load())
            {
                const auto resolution = map.classify(10);

                // The only two legal observations are "container-x" and, for the
                // instant install() has cleared the map, unknown. Any other
                // container id would be a torn read.
                if (resolution.klass == CgroupClass::container && resolution.container_id != "container-x")
                {
                    ++wrong;
                }
            }
        });

    for (int i = 0; i < 2000; ++i)
    {
        map.install({{10, "container-x"}});
    }

    stop.store(true);
    reader.join();

    EXPECT_EQ(0u, wrong.load());
    EXPECT_EQ("container-x", map.classify(10).container_id);
}

TEST(CgroupContainerMapTest, ConcurrentDrainAndResolverAgreeOnEveryCgroup)
{
    constexpr std::uint64_t kCgroups = 400;

    CgroupContainerMap map(kCgroups * 2, 8192);
    std::atomic<bool> stop{false};

    // Drain: classifies a rotating set of cgroups, queueing whatever misses.
    std::thread drain(
        [&map, &stop]
        {
            while (!stop.load())
            {
                for (std::uint64_t id = 1; id <= kCgroups; ++id)
                {
                    map.classify(id);
                }
            }
        });

    // Resolver: half are containers, half are host cgroups.
    unsigned long resolved = 0;

    while (resolved < kCgroups)
    {
        for (const auto id : map.takeUnresolved())
        {
            if (id % 2 == 0)
            {
                map.noteContainer(id, "c" + std::to_string(id));
            }
            else
            {
                map.noteNotContainer(id);
            }
            ++resolved;
        }
    }

    stop.store(true);
    drain.join();

    EXPECT_EQ(kCgroups / 2, map.containerCount());
    EXPECT_EQ(0u, map.unresolvedCount());

    for (std::uint64_t id = 1; id <= kCgroups; ++id)
    {
        const auto resolution = map.classify(id);

        if (id % 2 == 0)
        {
            EXPECT_EQ(CgroupClass::container, resolution.klass) << "cgroup " << id;
            EXPECT_EQ("c" + std::to_string(id), resolution.container_id);
        }
        else
        {
            EXPECT_EQ(CgroupClass::notContainer, resolution.klass) << "cgroup " << id;
        }
    }
}
