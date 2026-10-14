/*
 * Wazuh container_instances — lifecycle journal (#37532 / #37203 O3).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The journal exists so a consumer can learn what changed without re-reading
 * every container, and its whole value rests on one invariant:
 *
 *   for cursors s1 < s2 with no eviction between them, applying the events in
 *   (s1, s2] to the set as it was at s1 yields the set as it is at s2.
 *
 * That is a statement about VISIBILITY — the set listContainers() returns — not
 * about store writes, and the two differ in ways that are easy to get wrong.
 * The property test at the bottom is the real guard; the named cases above it
 * pin the specific subtleties that make the naive implementation wrong.
 */

#include "cache/metadata_store.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <set>
#include <string>
#include <vector>

using namespace wazuh::container_instances;

namespace
{

    const SourceId kDocker {"docker"};
    const SourceId kK8s {"kubernetes"};

    ContainerRecord
    MakeRecord(const std::string& id, std::uint64_t inode, ContainerState state = ContainerState::running)
    {
        ContainerRecord record;
        record.runtime = ContainerRuntime::docker;
        record.containerId = id;
        record.containerName = id;
        record.image = "img";
        record.hostKey = inode;
        record.state = state;
        return record;
    }

    MetadataStore MakeStore()
    {
        return MetadataStore {[](LogLevel, const std::string&) {}};
    }

    std::set<std::string> ListedIds(const MetadataStore& store)
    {
        std::set<std::string> out;
        for (const auto& record : store.listContainers())
        {
            out.insert(record->containerId);
        }
        return out;
    }

    /// Applies a delta's events to a set of ids, exactly as a consumer would.
    void ApplyEvents(const std::vector<LifecycleEvent>& events, std::set<std::string>& ids)
    {
        for (const auto& event : events)
        {
            switch (event.kind)
            {
                case LifecycleKind::added: ids.insert(event.containerId); break;
                case LifecycleKind::removed: ids.erase(event.containerId); break;
                case LifecycleKind::changed: break; // membership unaffected
            }
        }
    }

    auto Now()
    {
        return std::chrono::steady_clock::now();
    }

} // namespace

TEST(LifecycleJournalTest, UpdateDoesNotEmitRemovedThenAdded)
{
    // The trap. insertResolvedLocked() erases the prior entry before inserting
    // the new one, so a journal hooked onto the raw erase and insert would
    // report every ordinary update as a removal followed by an addition — and a
    // consumer acting on that `removed` would sweep a live container's rows.
    auto store = MakeStore();

    store.applySnapshot(kDocker, {MakeRecord("alpha", 11)}, {11}, Now());
    const auto afterAdd = store.lifecycleCursor();

    auto changed = MakeRecord("alpha", 11);
    changed.image = "img:v2";
    store.applySnapshot(kDocker, {changed}, {11}, Now());

    const auto delta = store.lifecycleSince(afterAdd);

    ASSERT_FALSE(delta.resyncRequired);
    ASSERT_EQ(1u, delta.events.size()) << "an update is one event, not an erase plus an insert";
    EXPECT_EQ(LifecycleKind::changed, delta.events[0].kind);
    EXPECT_TRUE((delta.events[0].changed & LIFECYCLE_IMAGE) != 0);
}

TEST(LifecycleJournalTest, AddedIsPublishedOnlyOnceTheCgroupInodeIsKnown)
{
    auto store = MakeStore();
    const auto start = store.lifecycleCursor();

    // Seen by the connector but not yet joined with a cgroup. Not publishable:
    // its attribution key is about to change.
    store.applySnapshot(kDocker, {MakeRecord("beta", 0)}, {}, Now());
    EXPECT_TRUE(store.lifecycleSince(start).events.empty())
        << "an unresolved record is not a member of the published set, so its insert is not a transition";

    store.applySnapshot(kDocker, {MakeRecord("beta", 22)}, {22}, Now());

    const auto delta = store.lifecycleSince(start);
    ASSERT_EQ(1u, delta.events.size());
    EXPECT_EQ(LifecycleKind::added, delta.events[0].kind);
    EXPECT_EQ(22u, delta.events[0].hostKey);
}

TEST(LifecycleJournalTest, RemovedCarriesTheLastKnownCgroupId)
{
    // FIM keys its kernel allowlist by inode. A removal it cannot map back to
    // one is a removal it cannot act on, so the id has to ride the event.
    auto store = MakeStore();

    store.applySnapshot(kDocker, {MakeRecord("gamma", 33)}, {33}, Now());
    const auto afterAdd = store.lifecycleCursor();

    // Gone from the snapshot while running: grace is marked, then expires.
    store.applySnapshot(kDocker, {}, {}, Now());
    store.applySnapshot(kDocker, {}, {}, Now() + REMOVAL_GRACE + std::chrono::seconds {1});

    const auto delta = store.lifecycleSince(afterAdd);

    ASSERT_EQ(1u, delta.events.size());
    EXPECT_EQ(LifecycleKind::removed, delta.events[0].kind);
    EXPECT_EQ("gamma", delta.events[0].containerId);
    EXPECT_EQ(33u, delta.events[0].hostKey);
    EXPECT_EQ(nullptr, delta.events[0].record);
}

TEST(LifecycleJournalTest, RemovedIsPublishedAtGraceExpiryNotAtSnapshotAbsence)
{
    // The store keeps a vanished container for REMOVAL_GRACE so late events can
    // still be attributed. Publishing the removal when it first goes missing
    // would have consumers delete rows a minute early — and a container that
    // reappears within the grace never left the set at all.
    auto store = MakeStore();

    store.applySnapshot(kDocker, {MakeRecord("delta", 44)}, {44}, Now());
    const auto afterAdd = store.lifecycleCursor();

    store.applySnapshot(kDocker, {}, {}, Now());

    EXPECT_TRUE(store.lifecycleSince(afterAdd).events.empty())
        << "absence from one snapshot is not removal; the grace has not expired";
    EXPECT_EQ(1u, ListedIds(store).count("delta")) << "and it is still listed meanwhile";
}

TEST(LifecycleJournalTest, AStoppedContainerIsChangedNotRemoved)
{
    auto store = MakeStore();

    store.applySnapshot(kDocker, {MakeRecord("eps", 55)}, {55}, Now());
    const auto afterAdd = store.lifecycleCursor();

    // Stops: loses its process and therefore its inode, but still exists.
    store.applySnapshot(kDocker, {MakeRecord("eps", 0, ContainerState::stopped)}, {}, Now());

    const auto delta = store.lifecycleSince(afterAdd);

    ASSERT_EQ(1u, delta.events.size());
    EXPECT_EQ(LifecycleKind::changed, delta.events[0].kind)
        << "reporting a stop as removal is what destroys a stopped container's inventory";
    EXPECT_TRUE((delta.events[0].changed & LIFECYCLE_IDENTITY) != 0);
}

TEST(LifecycleJournalTest, MetadataOnlyChangeAppendsNothing)
{
    // Kubernetes annotations churn on every reconcile. Letting that into the
    // ring would evict real transitions long before a consumer's next poll.
    auto store = MakeStore();

    store.applySnapshot(kDocker, {MakeRecord("zeta", 66)}, {66}, Now());
    const auto afterAdd = store.lifecycleCursor();

    auto relabelled = MakeRecord("zeta", 66);
    relabelled.labels.emplace("rev", "2");
    relabelled.annotations.emplace("checksum", "abc");
    store.applySnapshot(kDocker, {relabelled}, {66}, Now());

    EXPECT_TRUE(store.lifecycleSince(afterAdd).events.empty());

    // ...but the store itself is still up to date; only the journal skipped it.
    EXPECT_EQ(1u, ListedIds(store).count("zeta"));
}

TEST(LifecycleJournalTest, UpsertResolvedFromTheColdPathIsPublished)
{
    // The on-demand resolve path bypasses applySnapshot entirely. A container
    // first seen that way is as new to consumers as one the connector found.
    auto store = MakeStore();
    const auto start = store.lifecycleCursor();

    store.upsertResolved(kDocker, MakeRecord("eta", 77));

    const auto delta = store.lifecycleSince(start);
    ASSERT_EQ(1u, delta.events.size());
    EXPECT_EQ(LifecycleKind::added, delta.events[0].kind);
}

TEST(LifecycleJournalTest, ForeignEpochReportsResyncRequiredWithTheFullSet)
{
    auto store = MakeStore();
    store.applySnapshot(kDocker, {MakeRecord("theta", 88)}, {88}, Now());

    LifecycleCursor foreign;
    foreign.epoch = store.lifecycleCursor().epoch + 1; // a different store's lifetime
    foreign.seq = 1;

    const auto delta = store.lifecycleSince(foreign);

    EXPECT_TRUE(delta.resyncRequired);
    ASSERT_EQ(1u, delta.containers.size()) << "the full set must ride the same reply, not a second call";
    EXPECT_EQ("theta", delta.containers[0]->containerId);
}

TEST(LifecycleJournalTest, AColdCursorGetsTheFullSet)
{
    // A consumer that has never read: epoch 0 is the "no cursor" sentinel.
    auto store = MakeStore();
    store.applySnapshot(kDocker, {MakeRecord("iota", 99)}, {99}, Now());

    const auto delta = store.lifecycleSince(LifecycleCursor {});

    EXPECT_TRUE(delta.resyncRequired);
    EXPECT_EQ(1u, delta.containers.size());
}

TEST(LifecycleJournalTest, RingOverrunReportsResyncRequiredWithTheFullSet)
{
    LifecycleJournal journal {4};
    const auto start = journal.cursor();

    for (int i = 0; i < 10; ++i)
    {
        LifecycleEvent event;
        event.kind = LifecycleKind::added;
        event.containerId = "c" + std::to_string(i);
        journal.append(std::move(event));
    }

    const auto delta = journal.since(start, {});
    EXPECT_TRUE(delta.resyncRequired) << "a cursor whose position has been evicted cannot be served a partial list";

    // A cursor still inside the ring is served normally.
    const auto recent = journal.cursor();
    LifecycleEvent event;
    event.kind = LifecycleKind::added;
    event.containerId = "late";
    journal.append(std::move(event));

    const auto served = journal.since(recent, {});
    EXPECT_FALSE(served.resyncRequired);
    ASSERT_EQ(1u, served.events.size());
    EXPECT_EQ("late", served.events[0].containerId);
}

TEST(LifecycleJournalTest, TheCallbackFiresOncePerBatchAndAfterTheLockIsReleased)
{
    auto store = MakeStore();

    int calls = 0;
    bool reentrantReadWorked = false;

    store.setOnLifecycleChange(
        [&](LifecycleCursor)
        {
            ++calls;
            // Reading the store back is the first thing a real observer does.
            // Under the write lock this deadlocks; the call must therefore
            // happen after it is released.
            reentrantReadWorked = !store.listContainers().empty();
        });

    // One batch, three containers: one signal, not three.
    store.applySnapshot(kDocker, {MakeRecord("a", 1), MakeRecord("b", 2), MakeRecord("c", 3)}, {1, 2, 3}, Now());

    EXPECT_EQ(1, calls);
    EXPECT_TRUE(reentrantReadWorked);

    // A batch that journals nothing must stay silent, or a quiet host would
    // wake its consumers every reconcile for no reason.
    store.applySnapshot(kDocker, {MakeRecord("a", 1), MakeRecord("b", 2), MakeRecord("c", 3)}, {1, 2, 3}, Now());

    EXPECT_EQ(1, calls);
}

TEST(LifecycleJournalTest, JournalMirrorsListContainersMembership)
{
    // The invariant itself, over a scripted sequence that exercises every
    // transition the store can make, including the ones that must NOT appear.
    auto store = MakeStore();

    auto expected = ListedIds(store);
    auto cursor = store.lifecycleCursor();

    const auto step = [&](std::vector<ContainerRecord> snapshot,
                          std::unordered_set<std::uint64_t> inodes,
                          std::chrono::steady_clock::time_point when)
    {
        store.applySnapshot(kDocker, std::move(snapshot), inodes, when);

        const auto delta = store.lifecycleSince(cursor);
        ASSERT_FALSE(delta.resyncRequired);

        ApplyEvents(delta.events, expected);
        cursor = delta.cursor;

        EXPECT_EQ(ListedIds(store), expected);
    };

    const auto t0 = Now();

    step({MakeRecord("a", 1)}, {1}, t0);                                              // add
    step({MakeRecord("a", 1), MakeRecord("b", 0)}, {1}, t0);                          // b unresolved: invisible
    step({MakeRecord("a", 1), MakeRecord("b", 2)}, {1, 2}, t0);                       // b resolves: add
    step({MakeRecord("a", 1, ContainerState::stopped), MakeRecord("b", 2)}, {2}, t0); // a stops: still a member
    step({MakeRecord("b", 2)}, {2}, t0);                                              // a removed (no grace: no inode)
    step({MakeRecord("b", 2)}, {2}, t0 + REMOVAL_GRACE + std::chrono::seconds {1});
    step({}, {}, t0 + REMOVAL_GRACE + std::chrono::seconds {2});     // b vanishes: grace starts
    step({}, {}, t0 + REMOVAL_GRACE * 2 + std::chrono::seconds {5}); // grace expires: remove

    EXPECT_TRUE(expected.empty());
}

TEST(LifecycleJournalTest, ASecondSourceDoesNotDoubleCountOneContainer)
{
    // cri-dockerd reports the same container through both APIs. It is one
    // member of the published set, so it must produce one `added` — a second
    // would leave a consumer's reconstructed set disagreeing with the store's.
    auto store = MakeStore();
    const auto start = store.lifecycleCursor();

    store.applySnapshot(kDocker, {MakeRecord("shared", 123)}, {123}, Now());
    store.applySnapshot(kK8s, {MakeRecord("shared", 123)}, {123}, Now());

    const auto delta = store.lifecycleSince(start);

    std::set<std::string> rebuilt;
    ApplyEvents(delta.events, rebuilt);

    EXPECT_EQ(ListedIds(store), rebuilt);
    EXPECT_EQ(1u, rebuilt.size());
}
