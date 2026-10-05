/*
 * Wazuh container_instances — keying the store by the host's own key.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * One number was doing two jobs: the index a record is filed under, and the
 * value the kernel stamps into every event. On a unified hierarchy they are
 * the same cgroup inode. On a legacy one they cannot be — the kernel side
 * collapses to a constant — so the two roles have to come apart.
 *
 * What makes this worth testing rather than reading: every failure here is a
 * HEALTHY-LOOKING one. A store keyed on the wrong kind still lists containers,
 * still answers status, still reports a sensible count, and then misses every
 * lookup it is asked to serve.
 */

#include "cache/metadata_store.hpp"
#include "core/host_key.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <string>

using namespace wazuh::container_instances;

namespace
{

    const SourceId kDocker {"docker"};

    constexpr std::uint64_t kCgroupInode = 4242;
    constexpr std::uint64_t kMntNsInode = 4026532281;

    ContainerRecord MakeRecord(const std::string& id, std::uint64_t key)
    {
        ContainerRecord record;
        record.runtime = ContainerRuntime::docker;
        record.containerId = id;
        record.containerName = id;
        record.hostKey = key;
        record.state = ContainerState::running;
        return record;
    }

    MetadataStore MakeStore(KeyKind kind)
    {
        return MetadataStore {[](LogLevel, const std::string&) {}, kind};
    }

} // namespace

TEST(HostKeyTest, TheKindFollowsTheHostHierarchy)
{
    EXPECT_EQ(KeyKind::cgroupInode, keyKindFor(WZ_CGROUP_MODE_UNIFIED));
    EXPECT_EQ(KeyKind::mntNsInode, keyKindFor(WZ_CGROUP_MODE_LEGACY));

    // Hybrid follows unified: the helper returns unified-hierarchy ids there,
    // so cgroup_id does correlate and there is no reason to fall back to a
    // weaker key.
    EXPECT_EQ(KeyKind::cgroupInode, keyKindFor(WZ_CGROUP_MODE_HYBRID));
}

TEST(HostKeyTest, ALegacyStoreIsFoundByItsMountNamespaceKey)
{
    auto store = MakeStore(KeyKind::mntNsInode);
    store.applySnapshot(kDocker, {MakeRecord("alpha", kMntNsInode)}, {kMntNsInode}, std::chrono::steady_clock::now());

    const auto found = store.lookup(HostKey {KeyKind::mntNsInode, kMntNsInode});

    ASSERT_TRUE(found.record != nullptr);
    EXPECT_EQ("alpha", found.record->containerId);
}

TEST(HostKeyTest, AskingWithTheWrongKindIsRefusedRatherThanMissed)
{
    /* The reason lookup takes a HostKey and not an integer.
     *
     * The key arrives over IPC from a process that classified the host for
     * itself. Both kinds are 64-bit inode numbers, so a mismatched one does
     * not look wrong — it just fails to match, and "not found" means "unknown
     * container, go and resolve it" to every consumer. The container is
     * sitting right there. */
    auto store = MakeStore(KeyKind::mntNsInode);
    store.applySnapshot(kDocker, {MakeRecord("alpha", kMntNsInode)}, {kMntNsInode}, std::chrono::steady_clock::now());

    EXPECT_EQ(nullptr, store.lookup(HostKey {KeyKind::cgroupInode, kMntNsInode}).record)
        << "the right number with the wrong kind must not resolve";
    EXPECT_EQ(nullptr, store.lookup(HostKey {KeyKind::mntNsInode, kCgroupInode}).record);
}

TEST(HostKeyTest, TheStorePublishesWhichKindItUsesSoConsumersNeedNotGuess)
{
    // Two components independently classifying one host is the defect the
    // shared probe exists to prevent. A consumer asks the store instead.
    EXPECT_EQ(KeyKind::mntNsInode, MakeStore(KeyKind::mntNsInode).keyKind());
    EXPECT_EQ(KeyKind::cgroupInode, MakeStore(KeyKind::cgroupInode).keyKind());

    // Pinned because it is published on the wire and a consumer parses it.
    EXPECT_STREQ("mnt_ns", keyKindName(KeyKind::mntNsInode));
    EXPECT_STREQ("cgroup", keyKindName(KeyKind::cgroupInode));

    KeyKind parsed {};
    EXPECT_TRUE(keyKindFromName("mnt_ns", parsed));
    EXPECT_EQ(KeyKind::mntNsInode, parsed);
    EXPECT_TRUE(keyKindFromName("cgroup", parsed));
    EXPECT_EQ(KeyKind::cgroupInode, parsed);
    EXPECT_FALSE(keyKindFromName("something-added-later", parsed))
        << "an unknown kind must be rejected, never defaulted: defaulting picks a key space at random";
}

TEST(HostKeyTest, AKeyedLegacyContainerIsPublishedToConsumers)
{
    // The point of phase 1: a legacy host used to resolve no key at all, so
    // every running container was withheld and inventory stayed empty on
    // RHEL 8 and Amazon Linux 2.
    auto store = MakeStore(KeyKind::mntNsInode);
    store.applySnapshot(kDocker, {MakeRecord("alpha", kMntNsInode)}, {kMntNsInode}, std::chrono::steady_clock::now());

    const auto listed = store.listContainers();

    ASSERT_EQ(1U, listed.size());
    EXPECT_EQ("alpha", listed.front()->containerId);
}

TEST(HostKeyTest, TheVisibilityGuardStillHasBothOfItsTerms)
{
    /* The trap this package was warned about.
     *
     * The guard is "no key AND running". Swapping only the key half — which is
     * the obvious reading of "key the store by HostKey" — drops the state term
     * and makes a STOPPED container with no key disappear from the list again,
     * which every consumer reads as a deletion and sweeps the rows for. That
     * regression would pass every other test in this file. */
    auto store = MakeStore(KeyKind::mntNsInode);

    auto stopped = MakeRecord("alpha", 0);
    stopped.state = ContainerState::stopped;
    store.applySnapshot(kDocker, {stopped}, {}, std::chrono::steady_clock::now());

    ASSERT_EQ(1U, store.listContainers().size()) << "a stopped container has no key to wait for and must stay listed";

    // And the other term still does its job: running with no key is withheld,
    // because publishing it hands consumers a key that is about to change.
    auto store2 = MakeStore(KeyKind::mntNsInode);
    store2.applySnapshot(kDocker, {MakeRecord("beta", 0)}, {}, std::chrono::steady_clock::now());

    EXPECT_TRUE(store2.listContainers().empty());
}

TEST(HostKeyTest, LivenessEvictionComparesKeysFromTheSameSpace)
{
    /* allHostKeys is matched against the keys entries are filed under, so both
     * have to be drawn from the same space.
     *
     * The failure mode if they are not is quiet and total: `liveInodes.count()`
     * would miss on every entry, every scan, so every verdict would age out
     * after MISSED_SCANS_LIMIT scans and be rediscovered, forever. The cache
     * would still answer, just never from the cache. */
    auto store = MakeStore(KeyKind::mntNsInode);
    store.upsertVerdict(kMntNsInode, VerdictReason::hostProcess);

    ASSERT_TRUE(store.lookup(HostKey {KeyKind::mntNsInode, kMntNsInode}).reason.has_value());

    // Observed, repeatedly: the counter keeps resetting and it never ages out.
    for (int scan = 0; scan < MISSED_SCANS_LIMIT + 2; ++scan)
    {
        store.applySnapshot(kDocker, {}, {kMntNsInode}, std::chrono::steady_clock::now());
    }
    EXPECT_TRUE(store.lookup(HostKey {KeyKind::mntNsInode, kMntNsInode}).reason.has_value())
        << "the live set is being compared against a different key space";

    // Genuinely gone: ages out on the documented schedule, not immediately.
    for (int scan = 0; scan < MISSED_SCANS_LIMIT; ++scan)
    {
        store.applySnapshot(kDocker, {}, {}, std::chrono::steady_clock::now());
    }
    EXPECT_FALSE(store.lookup(HostKey {KeyKind::mntNsInode, kMntNsInode}).reason.has_value());
}
