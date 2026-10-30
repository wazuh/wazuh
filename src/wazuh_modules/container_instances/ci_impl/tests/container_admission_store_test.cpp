/*
 * Wazuh container_instances — admission inside the metadata store.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The rule itself is pinned next door, without a store. What is pinned HERE is
 * the property the rule cannot guarantee on its own, and the one the whole
 * design turns on:
 *
 *   a withheld container is still PUBLISHED.
 *
 * Both consumers delete the rows of every container absent from listContainers()
 * -- sweepStale() in FIM, sweepContainerRowsNotIn() in syscollector. So a cap
 * implemented by shortening that list would not withhold a container's data, it
 * would DELETE it, and then re-create it the moment the cap moved. Withholding
 * and deleting are opposite outcomes reached by one plausible shortcut, which
 * is why this is asserted rather than assumed.
 */

#include "cache/container_admission.hpp"
#include "cache/metadata_store.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <thread>

using namespace wazuh::container_instances;

namespace
{

    const SourceId kDocker {"docker"};
    const SourceId kCri {"cri"};

    ContainerRecord MakeRecord(const std::string& id, std::uint64_t inode)
    {
        ContainerRecord record;
        record.runtime = ContainerRuntime::docker;
        record.containerId = id;
        record.containerName = id;
        record.image = "img";
        record.hostKey = inode;
        record.state = ContainerState::running;
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

    /// The host key must be STABLE per container id across snapshots.
    ///
    /// Numbering them positionally instead looks harmless and is not: drop one
    /// container and every later container silently inherits a different key,
    /// so the store correctly reads it as a different container and the test
    /// ends up measuring its own helper.
    std::uint64_t InodeFor(const std::string& id)
    {
        return 100 + static_cast<std::uint64_t>(std::hash<std::string> {}(id) % 10000);
    }

    std::vector<ContainerRecord> Snapshot(const std::vector<std::string>& ids)
    {
        std::vector<ContainerRecord> out;

        for (const auto& id : ids)
        {
            out.push_back(MakeRecord(id, InodeFor(id)));
        }

        return out;
    }

    auto Now()
    {
        return std::chrono::steady_clock::now();
    }

} // namespace

TEST(ContainerAdmissionStoreTest, WithheldCountsContainersTheListOmitsNotUnresolvedRecords)
{
    auto store = MakeStore();

    // One container, two sources -- cri-dockerd publishes the same container
    // through both APIs. The docker record is resolved; the cri one is not.
    ContainerRecord resolved = MakeRecord("shared", InodeFor("shared"));
    ContainerRecord unresolved = MakeRecord("shared", 0);
    unresolved.runtime = ContainerRuntime::docker;

    store.applySnapshot(kDocker, {resolved}, {}, Now());
    store.applySnapshot(kCri, {unresolved}, {}, Now());

    ASSERT_EQ(ListedIds(store), (std::set<std::string> {"shared"}))
        << "either source resolving is enough to publish the container";

    // Counting the unresolved RECORD rather than the omitted CONTAINER left
    // this at 1 while the container sat in the list, so every consumer that
    // waits for a complete list before cleaning up waited for ever.
    EXPECT_TRUE(store.unkeyedContainerIds().empty()) << "a container that IS in the list is not withheld from it";

    // A container no source can key is genuinely absent from the list, and must
    // still be counted.
    store.applySnapshot(kDocker, {resolved, MakeRecord("ghost", 0)}, {}, Now());
    EXPECT_EQ(ListedIds(store), (std::set<std::string> {"shared"}));
    EXPECT_EQ(store.unkeyedContainerIds(), (std::set<std::string> {"ghost"}))
        << "and the sweeps need its id, not just a count, to keep its rows";
}

// A container RESTARTING is one whose record is replaced: keyed, then unkeyed
// for as long as the resolver takes to catch up, then keyed again. Both
// consumers keep the rows of every container in the list OR in the unkeyed
// ids, and delete the rest -- so the two sets have to describe one instant. Read
// one after the other they do not, and a container crossing between them while
// the reads are in flight is in neither, which costs it every row it has.
TEST(ContainerAdmissionStoreTest, ARestartingContainerIsNeverAbsentFromBothSets)
{
    auto store = MakeStore();

    // Seeded before the reader starts. Without this the reader's first poll can
    // beat the writer's first snapshot and report a container that does not
    // exist yet as lost -- the harness measuring itself rather than the store.
    store.applySnapshot(
        kDocker, {MakeRecord("steady", InodeFor("steady")), MakeRecord("flap", InodeFor("flap"))}, {}, Now());

    std::atomic<bool> writerDone {false};
    std::atomic<int> reads {0};
    std::atomic<int> lost {0};

    std::thread writer(
        [&]
        {
            for (int i = 0; i < 20000; ++i)
            {
                // hostKey 0 while running is precisely "exists, not keyed yet".
                store.applySnapshot(
                    kDocker, {MakeRecord("steady", InodeFor("steady")), MakeRecord("flap", 0)}, {}, Now());
                store.applySnapshot(kDocker,
                                    {MakeRecord("steady", InodeFor("steady")), MakeRecord("flap", InodeFor("flap"))},
                                    {},
                                    Now());
            }
            writerDone.store(true);
        });

    while (!writerDone.load())
    {
        const auto snapshot = store.listSnapshot(std::nullopt);

        std::set<std::string> present = snapshot.unkeyed;

        for (const auto& record : snapshot.containers)
        {
            present.insert(record->containerId);
        }

        reads.fetch_add(1);

        if (present.count("flap") == 0)
        {
            lost.fetch_add(1);
        }
    }

    writer.join();

    ASSERT_GT(reads.load(), 0) << "the reader never ran, so this proves nothing";
    EXPECT_EQ(lost.load(), 0) << "a restarting container fell between the list and the unkeyed ids in " << lost.load()
                              << " of " << reads.load() << " reads; a consumer would delete every row it holds for it";
}

// ...and the snapshot must still be the three accessors, not merely consistent
// with itself. A quiet store is enough to pin that.
TEST(ContainerAdmissionStoreTest, TheSnapshotAgreesWithTheAccessorsItReplaces)
{
    auto store = MakeStore();
    store.setSyncLimit(1);
    store.applySnapshot(kDocker, {MakeRecord("a", InodeFor("a")), MakeRecord("b", InodeFor("b"))}, {}, Now());
    store.applySnapshot(kCri, {MakeRecord("ghost", 0)}, {}, Now());

    const auto snapshot = store.listSnapshot(std::nullopt);

    std::set<std::string> listed;

    for (const auto& record : snapshot.containers)
    {
        listed.insert(record->containerId);
    }

    EXPECT_EQ(listed, ListedIds(store));
    EXPECT_EQ(snapshot.admitted, store.admittedIds());
    EXPECT_EQ(snapshot.unkeyed, store.unkeyedContainerIds());
    EXPECT_EQ(snapshot.unkeyed, (std::set<std::string> {"ghost"}));
    EXPECT_FALSE(snapshot.delta) << "no cursor was asked for";

    // With a cursor the delta rides along, built from the very list above
    // rather than from a second one taken a moment later.
    const auto followed = store.listSnapshot(std::optional<LifecycleCursor> {LifecycleCursor {}});
    ASSERT_TRUE(followed.delta);
    EXPECT_TRUE(followed.delta->resyncRequired) << "a default cursor is from another store lifetime";
    EXPECT_EQ(followed.delta->containers.size(), followed.containers.size());
}

TEST(ContainerAdmissionStoreTest, WithheldContainersAreStillPublished)
{
    auto store = MakeStore();
    store.setSyncLimit(2);

    store.applySnapshot(kDocker, Snapshot({"a", "b", "c", "d"}), {}, Now());

    // THE assertion. Every container is still listed -- the cap decides what
    // reports, never what exists.
    EXPECT_EQ(ListedIds(store), (std::set<std::string> {"a", "b", "c", "d"}))
        << "a withheld container vanished from the list, which is how the stale sweeps are told to DELETE it";

    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a", "b"}));
}

TEST(ContainerAdmissionStoreTest, NoLimitAdmitsEveryContainer)
{
    auto store = MakeStore();

    store.applySnapshot(kDocker, Snapshot({"a", "b", "c"}), {}, Now());

    // The shipped default changes nothing for anyone.
    EXPECT_EQ(store.admittedIds(), ListedIds(store));
}

TEST(ContainerAdmissionStoreTest, AnIncumbentKeepsItsSlotWhenALowerIdAppears)
{
    auto store = MakeStore();
    store.setSyncLimit(2);

    store.applySnapshot(kDocker, Snapshot({"m", "n"}), {}, Now());
    ASSERT_EQ(store.admittedIds(), (std::set<std::string> {"m", "n"}));

    // "a" sorts below both incumbents and still must not displace either, or
    // every container creation on a busy node costs a delete and a create.
    store.applySnapshot(kDocker, Snapshot({"a", "m", "n"}), {}, Now());

    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"m", "n"}));
    EXPECT_EQ(ListedIds(store), (std::set<std::string> {"a", "m", "n"}));
}

TEST(ContainerAdmissionStoreTest, LoweringTheLimitTakesEffectImmediately)
{
    auto store = MakeStore();
    store.setSyncLimit(3);

    store.applySnapshot(kDocker, Snapshot({"a", "b", "c"}), {}, Now());
    ASSERT_EQ(3U, store.admittedIds().size());

    store.setSyncLimit(1);

    // Without recomputing on the limit change, the new cap would not bind until
    // the next reconcile -- which on a quiet node is never.
    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a"}));
    EXPECT_EQ(ListedIds(store), (std::set<std::string> {"a", "b", "c"}));
}

TEST(ContainerAdmissionStoreTest, RaisingTheLimitAdmitsWaitingContainers)
{
    auto store = MakeStore();
    store.setSyncLimit(1);

    store.applySnapshot(kDocker, Snapshot({"a", "b", "c"}), {}, Now());
    ASSERT_EQ(store.admittedIds(), (std::set<std::string> {"a"}));

    store.setSyncLimit(3);

    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a", "b", "c"}));
}

TEST(ContainerAdmissionStoreTest, ADepartedContainerHandsItsSlotOn)
{
    auto store = MakeStore();
    store.setSyncLimit(2);

    store.applySnapshot(kDocker, Snapshot({"a", "b", "c"}), {}, Now());
    ASSERT_EQ(store.admittedIds(), (std::set<std::string> {"a", "b"}));

    // "a" drops out of the snapshot. It is MARKED for removal, not erased --
    // a container with a live key keeps serving lookups for REMOVAL_GRACE, and
    // listContainers() still publishes it. So it must keep its slot too:
    // withholding a container the consumers can still see would be wrong, and
    // a container that comes back within the grace never lost anything.
    const auto departed = Now();
    store.applySnapshot(kDocker, Snapshot({"b", "c"}), {}, departed);

    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a", "b"}))
        << "a container inside its removal grace is still published, so it must still hold its slot";

    // A second snapshot past the grace is what actually erases it. Only then is
    // the slot free, and it must go to the waiting container, or a cap on a
    // churning node decays toward admitting nothing.
    store.applySnapshot(kDocker, Snapshot({"b", "c"}), {}, departed + REMOVAL_GRACE + std::chrono::seconds {1});

    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"b", "c"}));
    EXPECT_EQ(ListedIds(store), (std::set<std::string> {"b", "c"}));
}

// The price of ranking by existence, written down because it is a real cost and
// not an oversight: an unresolved container can hold a slot it cannot yet use.
// It publishes nothing while it has no key, so for that moment the node reports
// one container fewer than the limit allows.
//
// Taken deliberately. The alternative is to leave it out of the ranking, and
// then no consumer has a decision to apply to it, so every consumer reports it
// and the node runs OVER the limit instead -- unbounded rather than one short,
// which is the opposite of what the cap is for. One short is also temporary:
// the slot comes into use as soon as the resolver keys the container. The case
// that does not resolve itself is a container nothing can ever key, and the
// "Reporting N of M" line names that cost rather than hiding it.
TEST(ContainerAdmissionStoreTest, AnUnresolvedRunningContainerCanHoldASlotItCannotYetUse)
{
    auto store = MakeStore();
    store.setSyncLimit(1);

    // hostKey 0 on a running container means the resolver has not keyed it yet,
    // and "a" sorts below "visible", so it takes the only slot.
    auto snapshot = Snapshot({"visible"});
    snapshot.push_back(MakeRecord("a", 0));

    store.applySnapshot(kDocker, snapshot, {}, Now());

    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a"}));
    EXPECT_EQ(ListedIds(store), (std::set<std::string> {"visible"}));

    // ...and it is handed over the moment the resolver catches up, because the
    // ranking never had to change its mind about who exists.
    store.applySnapshot(kDocker, Snapshot({"a", "visible"}), {}, Now());
    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a"}));
    EXPECT_EQ(ListedIds(store), (std::set<std::string> {"a", "visible"}));
}

// The cap bounds how many containers the node REPORTS ON. That is a question
// about container ids, and a container the resolver has not keyed yet is one of
// them -- it exists, consumers know of it, and no consumer can be told it is
// refused unless the ranking considered it.
//
// Ranking only the published containers therefore did not bound anything. An
// unkeyed container was absent from the ranking, so it was in nobody's admitted
// set, so every consumer read "no decision" and reported it. The node ran at
// limit + 1.
TEST(ContainerAdmissionStoreTest, AnUnresolvedContainerIsRankedByTheCapLikeAnyOther)
{
    auto store = MakeStore();
    store.setSyncLimit(2);

    // "a" is running and the resolver has no key for it yet. It sorts below both
    // keyed containers, so a ranking that weighs it takes a different decision
    // from one that does not -- which is what makes this test say anything.
    ContainerRecord unresolved = MakeRecord("a", 0);

    store.applySnapshot(
        kDocker, {unresolved, MakeRecord("m", InodeFor("m")), MakeRecord("n", InodeFor("n"))}, {}, Now());

    EXPECT_EQ(store.unkeyedContainerIds(), (std::set<std::string> {"a"}));
    EXPECT_EQ(ListedIds(store), (std::set<std::string> {"m", "n"})) << "still withheld from the list";

    // Two slots, three containers, and the ranking weighed all three. So "n" is
    // REFUSED and says so, instead of the cap quietly becoming a cap on the
    // keyed ones alone while "a" reports outside it.
    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a", "m"}));
    EXPECT_EQ(store.admittedIds().count("n"), 0U);
}

// The other half, and it pulls the opposite way: a container that restarts is
// not a container that left. Its cgroup inode changes, so it is unkeyed for a
// moment -- and a ranking built from the published list treats that moment as a
// departure, hands the slot to the next id, and refuses the container when its
// key comes back. Its documents are created on the manager and deleted again on
// every restart.
TEST(ContainerAdmissionStoreTest, ARestartingContainerKeepsItsSlotWhileItHasNoKey)
{
    auto store = MakeStore();
    store.setSyncLimit(1);

    store.applySnapshot(kDocker, Snapshot({"b"}), {}, Now());
    ASSERT_EQ(store.admittedIds(), (std::set<std::string> {"b"}));

    // "b" restarts and "a" shows up meanwhile. "a" sorts lower, so a ranking
    // that has dropped "b" would hand it the only slot.
    ContainerRecord restarting = MakeRecord("b", 0);
    store.applySnapshot(kDocker, {MakeRecord("a", InodeFor("a")), restarting}, {}, Now());

    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"b"})) << "a restart is not a departure";

    // And when its key comes back it is still the incumbent, so nothing was
    // withdrawn and nothing re-created.
    store.applySnapshot(kDocker, Snapshot({"a", "b"}), {}, Now());
    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"b"}));
}
