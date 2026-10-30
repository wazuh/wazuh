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

    /// Whether the store is willing to give a verdict at all. Read through the
    /// snapshot because that is how a consumer reads it: an unsettled store
    /// omits the set from the reply rather than sending an empty one.
    ///
    /// Deliberately NOT through settleAdmissionIfDue(): this has to observe the
    /// barrier, not advance it.
    bool AdmissionKnown(const MetadataStore& store)
    {
        return store.listSnapshot(std::nullopt).admissionKnown;
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

// The slot goes to a container that can use it, and is handed over without a
// recompute changing its mind about who exists.
//
// This used to assert the opposite -- that an unresolved container holds a slot
// it cannot yet use -- and that was written down as a deliberate cost of
// ranking by existence. It was not a cost worth paying: a container nothing can
// ever key held a slot for the life of the process, and the node reported one
// container fewer than the limit allows with the "Reporting N of M" line as the
// only evidence. Filling free slots from what can be PUBLISHED removes the cost
// without giving back the overshoot that ranking by visibility alone caused,
// because incumbency is still decided over what EXISTS.
TEST(ContainerAdmissionStoreTest, AnUnresolvedRunningContainerDoesNotHoldASlotItCannotUse)
{
    auto store = MakeStore();
    store.setSyncLimit(1);

    // hostKey 0 on a running container means the resolver has not keyed it yet.
    // "a" sorts below "visible" and would take the only slot if free slots were
    // filled from everything that exists.
    auto snapshot = Snapshot({"visible"});
    snapshot.push_back(MakeRecord("a", 0));

    store.applySnapshot(kDocker, snapshot, {}, Now());

    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"visible"}))
        << "the only container that can publish gets the only slot";
    EXPECT_EQ(ListedIds(store), (std::set<std::string> {"visible"}));

    // "a" resolves. It does NOT evict the incumbent -- that is stickiness, and
    // it is what keeps a busy node from trading one container's documents for
    // another's every time the resolver catches up.
    store.applySnapshot(kDocker, Snapshot({"a", "visible"}), {}, Now());
    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"visible"}));
    EXPECT_EQ(ListedIds(store), (std::set<std::string> {"a", "visible"}));
}

// A container the resolver has never keyed takes no slot, and is still REFUSED
// rather than undecided.
//
// Both halves matter and they are easy to confuse. Refused is what the consumers
// need: absence from the admitted set is the only way they can be told, and
// while the ranking skipped unkeyed containers entirely they read "no decision"
// and reported them, so the node ran over the cap for the length of every
// restart. Taking a slot is what they must NOT do: a container with no key
// publishes nothing, so a slot it holds is a slot the node cannot use.
TEST(ContainerAdmissionStoreTest, AnUnresolvedContainerTakesNoSlotAndIsStillRefused)
{
    auto store = MakeStore();
    store.setSyncLimit(2);

    // "a" is running and the resolver has no key for it yet. It sorts below both
    // keyed containers, so a rule that filled free slots from everything that
    // exists would hand it one.
    ContainerRecord unresolved = MakeRecord("a", 0);

    store.applySnapshot(
        kDocker, {unresolved, MakeRecord("m", InodeFor("m")), MakeRecord("n", InodeFor("n"))}, {}, Now());

    EXPECT_EQ(store.unkeyedContainerIds(), (std::set<std::string> {"a"}));
    EXPECT_EQ(ListedIds(store), (std::set<std::string> {"m", "n"})) << "still withheld from the list";

    // Both slots go to containers that can use them.
    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"m", "n"}));

    // ...and "a" is absent from that set, which is how every consumer is told it
    // may not report. Not being keyable is not a free pass past the cap.
    EXPECT_EQ(store.admittedIds().count("a"), 0U);
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

// An admission shift wakes consumers, even when nothing became visible or
// stopped being visible.
//
// The journal records VISIBILITY transitions, so it has nothing to say about a
// container the resolver cannot key gaining or losing admission, and nothing at
// all about the operator moving the cap. Those changes reached the drain only
// on its next scheduled poll -- up to resolver_interval_ms, 5 s by default --
// and the containers involved went on reporting, or went on not reporting, for
// that whole window.
TEST(ContainerAdmissionStoreTest, LoweringTheLimitWakesConsumersAtOnce)
{
    auto store = MakeStore();
    int calls = 0;
    store.setOnLifecycleChange([&](LifecycleCursor) { ++calls; });

    store.applySnapshot(kDocker, Snapshot({"a", "b"}), {}, Now());
    ASSERT_EQ(1, calls) << "the snapshot itself is one signal";

    // Nothing appeared and nothing left. Only the cap moved, and it pushed "b"
    // out: a consumer that is not told goes on reporting it.
    store.setSyncLimit(1);

    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a"}));
    EXPECT_EQ(2, calls) << "an admission change is a change";

    // ...and a limit that changes nothing stays silent, or a quiet node would
    // wake its consumers for no reason.
    store.setSyncLimit(1);
    EXPECT_EQ(2, calls);

    store.setSyncLimit(5);
    EXPECT_EQ(3, calls) << "raising it readmits 'b', which is equally worth hearing";
}

// The reviewer's case: a container whose admission changes while it has NO key.
//
// It is invisible to listContainers() at that moment, so no visibility
// transition describes what happened to it, and the journal is silent. It is
// still a container that was reporting and now may not, and every consumer has
// to be told before it sends another of its documents.
TEST(ContainerAdmissionStoreTest, AnUnkeyedIncumbentLosingAdmissionStillSignals)
{
    auto store = MakeStore();
    store.setSyncLimit(2);

    int calls = 0;
    store.setOnLifecycleChange([&](LifecycleCursor) { ++calls; });

    store.applySnapshot(kDocker, Snapshot({"a", "b"}), {}, Now());
    ASSERT_EQ(store.admittedIds(), (std::set<std::string> {"a", "b"}));

    // "b" restarts: no key for the moment, so it leaves the list but keeps its
    // slot. That much IS a visibility transition and signals on its own.
    store.applySnapshot(kDocker, {MakeRecord("a", InodeFor("a")), MakeRecord("b", 0)}, {}, Now());
    ASSERT_EQ(ListedIds(store), (std::set<std::string> {"a"}));
    ASSERT_EQ(store.admittedIds(), (std::set<std::string> {"a", "b"}));
    const int beforeCap = calls;

    // Now the cap pushes it out while it is still unkeyed. Nothing about its
    // visibility changed -- it was already invisible -- so this is the signal
    // that did not exist.
    store.setSyncLimit(1);

    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a"}));
    EXPECT_EQ(calls, beforeCap + 1);
}

// The line that names containers.synced_limit must only fire when that limit
// is what held a container back.
//
// It counted every known container that was not admitted, which includes ones
// the resolver has not keyed yet. With the limit at 5 and three containers, one
// of them unkeyed, it said "1 withheld by containers.synced_limit=5" -- a limit
// holding nothing back, and an operator who raises it sees no change.
TEST(ContainerAdmissionStoreTest, TheWithheldLineBlamesTheLimitOnlyWhenTheLimitBinds)
{
    std::vector<std::string> messages;
    MetadataStore store {[&](LogLevel level, const std::string& text)
                         {
                             if (level == LogLevel::info)
                             {
                                 messages.push_back(text);
                             }
                         }};

    store.setSyncLimit(5);

    // Three containers, one with no key. Two slots of five are in use and
    // nothing has been turned down.
    store.applySnapshot(
        kDocker, {MakeRecord("a", 0), MakeRecord("m", InodeFor("m")), MakeRecord("n", InodeFor("n"))}, {}, Now());

    // "a" takes the third slot: nothing publishable wants it, and refusing it
    // would retract its rows for the seconds until the resolver keys it.
    ASSERT_EQ(store.admittedIds(), (std::set<std::string> {"a", "m", "n"}));

    for (const auto& text : messages)
    {
        EXPECT_EQ(text.find("withheld by containers.synced_limit"), std::string::npos)
            << "the limit is 5 and three containers exist; it held nothing back. Got: " << text;
    }

    // Lower it so it really does bind, and the line must appear -- and count
    // only the container that could have published and was refused.
    messages.clear();
    store.setSyncLimit(1);

    ASSERT_EQ(store.admittedIds().size(), 1U);
    ASSERT_EQ(messages.size(), 1U);
    EXPECT_NE(messages[0].find("Reporting 1 of 2 resolved container(s)"), std::string::npos) << "got: " << messages[0];
    EXPECT_NE(messages[0].find("1 withheld by containers.synced_limit=1"), std::string::npos) << "got: " << messages[0];
}

// ---------------------------------------------------------------------------
// Settling: the store gives no verdict until it can see the whole node.
//
// Admission is sticky, so whoever holds a slot keeps it. Rank before the node
// is in view and the set freezes around whichever containers the resolver
// happened to key first -- which differs from run to run, so a restart with no
// real change moves documents on the manager for the rest of the process.
// ---------------------------------------------------------------------------

// The case the first draft of this got wrong. "Every container I know of is
// keyed" is trivially true of a store that knows of none, and setSyncLimit()
// runs from the facade constructor, before a single connector thread starts.
// Settling there would make the whole barrier a no-op.
TEST(ContainerAdmissionStoreTest, TheLimitSetBeforeAnyConnectorRunsDoesNotSettleAdmission)
{
    auto store = MakeStore();

    // The facade's own order, and the reason it is that order.
    store.setExpectedSources(1);
    store.setSyncLimit(2);

    EXPECT_FALSE(AdmissionKnown(store)) << "a store that has enumerated nothing has nothing to say";
    EXPECT_TRUE(store.admittedIds().empty());

    store.applySnapshot(kDocker, Snapshot({"a", "b", "c"}), {}, Now());

    EXPECT_TRUE(AdmissionKnown(store));
    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a", "b"})) << "the two lowest ids of the whole node";
}

TEST(ContainerAdmissionStoreTest, AdmissionIsWithheldUntilEverySourceHasEnumerated)
{
    auto store = MakeStore();
    store.setExpectedSources(2);
    store.setSyncLimit(1);

    // One source answered. Its containers are not the node, and nothing here
    // can tell a node of two from a node of three.
    store.applySnapshot(kDocker, Snapshot({"b", "c"}), {}, Now());

    EXPECT_FALSE(AdmissionKnown(store));
    EXPECT_TRUE(store.admittedIds().empty()) << "no verdict means no verdict, not an empty one";

    store.applySnapshot(kCri, Snapshot({"a"}), {}, Now());

    EXPECT_TRUE(AdmissionKnown(store));
    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a"})) << "and \"a\" was in the source that spoke last";
}

TEST(ContainerAdmissionStoreTest, AdmissionIsWithheldUntilTheResolverHasKeyedEverything)
{
    auto store = MakeStore();
    store.setExpectedSources(1);
    store.setSyncLimit(1);

    // Everything that exists is enumerated; "b" just has no key yet.
    store.applySnapshot(kDocker, {MakeRecord("a", InodeFor("a")), MakeRecord("b", 0)}, {}, Now());

    EXPECT_FALSE(AdmissionKnown(store));

    store.applySnapshot(kDocker, Snapshot({"a", "b"}), {}, Now());

    EXPECT_TRUE(AdmissionKnown(store));
    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a"}));
}

// An empty node is an answer. Before the barrier distinguished them, "nobody
// has reported yet" and "this host runs no containers" were the same state.
TEST(ContainerAdmissionStoreTest, AnAuthoritativeEmptyEnumerationSettlesAdmission)
{
    auto store = MakeStore();
    store.setExpectedSources(1);
    store.setSyncLimit(1);

    store.applySnapshot(kDocker, {}, {}, Now());

    EXPECT_TRUE(AdmissionKnown(store));
    EXPECT_TRUE(store.admittedIds().empty());
}

// A container whose cgroup nothing ever reports never keys, so the barrier
// never clears on its own. Without the grace one such container would suspend
// containers.synced_limit for the life of the agent.
TEST(ContainerAdmissionStoreTest, AdmissionSettlesOnTheGraceWhenAContainerNeverKeys)
{
    auto store = MakeStore();
    store.setExpectedSources(1);
    store.setSyncLimit(1);

    const auto start = Now();
    const std::vector<ContainerRecord> stuck {MakeRecord("a", InodeFor("a")), MakeRecord("ghost", 0)};

    store.applySnapshot(kDocker, stuck, {}, start);
    EXPECT_FALSE(AdmissionKnown(store));

    store.applySnapshot(kDocker, stuck, {}, start + ADMISSION_SETTLE_GRACE);

    EXPECT_TRUE(AdmissionKnown(store));
    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a"}))
        << "and the slot goes to the one that can publish, not the one that sorts lowest";
}

// The grace has to expire on a node whose snapshots have STOPPED -- a connector
// that died, a source that never starts. Reading a timestamp written by the
// snapshot path cannot do that: the clock it reads stops with the snapshots.
TEST(ContainerAdmissionStoreTest, AdmissionSettlesOnTheGraceWhenSnapshotsStop)
{
    auto store = MakeStore();
    store.setExpectedSources(2); // the second source never answers
    store.setSyncLimit(1);

    const auto start = Now();
    store.applySnapshot(kDocker, Snapshot({"a", "b"}), {}, start);
    ASSERT_FALSE(AdmissionKnown(store));

    store.settleAdmissionIfDue(start + ADMISSION_SETTLE_GRACE - std::chrono::seconds {1});
    EXPECT_FALSE(AdmissionKnown(store)) << "the grace is a deadline, not a hint";

    store.settleAdmissionIfDue(start + ADMISSION_SETTLE_GRACE);

    EXPECT_TRUE(AdmissionKnown(store));
    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a"}));
}

// The property the barrier exists for. Two runs of the same node, differing
// only in the order the sources answer and the resolver keys, must reach the
// same verdict -- otherwise a restart that changed nothing moves documents.
//
// Varying key order alone does not discriminate: source order is the half that
// a store built from `m_bySource` cannot see.
TEST(ContainerAdmissionStoreTest, TheFirstVerdictRanksTheWholeNodeNotWhoeverKeyedFirst)
{
    const auto settledSet = [](bool criFirst)
    {
        auto store = MakeStore();
        store.setExpectedSources(2);
        store.setSyncLimit(2);

        if (criFirst)
        {
            store.applySnapshot(kCri, Snapshot({"a", "b"}), {}, Now());
            store.applySnapshot(kDocker, {MakeRecord("c", 0)}, {}, Now());
            store.applySnapshot(kDocker, Snapshot({"c"}), {}, Now());
        }
        else
        {
            store.applySnapshot(kDocker, Snapshot({"c"}), {}, Now());
            store.applySnapshot(kCri, {MakeRecord("a", 0), MakeRecord("b", 0)}, {}, Now());
            store.applySnapshot(kCri, Snapshot({"a", "b"}), {}, Now());
        }

        return store.admittedIds();
    };

    EXPECT_EQ(settledSet(false), (std::set<std::string> {"a", "b"})) << "the two lowest ids, whoever keyed first";
    EXPECT_EQ(settledSet(true), settledSet(false));
}

// Unknown -> known is a transition in its own right. Comparing the admitted
// SETS cannot see it: on a node with nothing to admit the set is empty before
// and after, while every consumer flips from "report everything" to "report
// what the verdict says".
TEST(ContainerAdmissionStoreTest, SettlingWithNothingAdmittedStillWakesConsumers)
{
    auto store = MakeStore();
    int calls = 0;
    store.setOnLifecycleChange([&](LifecycleCursor) { ++calls; });

    store.setExpectedSources(1);
    store.setSyncLimit(1);
    ASSERT_EQ(0, calls);

    // An empty enumeration journals no container event, so the settle is the
    // only thing here that a consumer could be told about.
    store.applySnapshot(kDocker, {}, {}, Now());

    EXPECT_TRUE(AdmissionKnown(store));
    EXPECT_TRUE(store.admittedIds().empty());
    EXPECT_EQ(1, calls) << "a consumer still reporting everything has to hear that the verdict landed";
}

// The cold path discovers containers too, and the recompute it triggers is not
// free: it walks every record of every source and builds several id sets, under
// the exclusive lock, once per cold-path event. The ordinary resolve re-files a
// container that already existed and was already publishable, and that cannot
// move anyone's admission -- so it skips the walk.
//
// What it must NOT skip is a container this very call discovered. Comparing
// visibility alone does not tell the two apart: "invisible before, invisible
// after" describes an unchanged unkeyed container AND a brand new one, and
// since a free slot now goes to a container with no key, the new one has to be
// ranked.
TEST(ContainerAdmissionStoreTest, AContainerFirstSeenThroughAResolveIsStillRanked)
{
    auto store = MakeStore();
    store.setSyncLimit(3);

    store.applySnapshot(kDocker, Snapshot({"m"}), {}, Now());
    ASSERT_EQ(store.admittedIds(), (std::set<std::string> {"m"}));

    // Running, and no key yet -- so it is invisible before this call and
    // invisible after it, and only its EXISTENCE is new.
    store.upsertResolved(kDocker, MakeRecord("a", 0));

    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a", "m"}))
        << "a free slot goes to it, and nothing else would rank it until the next unrelated reconcile";

    // ...and a resolve that re-files what is already there changes nothing.
    store.upsertResolved(kDocker, MakeRecord("m", InodeFor("m")));
    EXPECT_EQ(store.admittedIds(), (std::set<std::string> {"a", "m"}));
}
