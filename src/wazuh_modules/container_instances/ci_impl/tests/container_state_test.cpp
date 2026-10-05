/*
 * Wazuh container_instances — stopped-container visibility (#37532 / #37203 D20).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * listContainers() used to hide every record with no cgroup inode, because a
 * zero inode meant exactly one thing: the resolver had not caught up with a
 * container that was starting. Listing Docker with all=1 gives it a second
 * meaning — a container with no process has no inode either — and the two need
 * opposite treatment:
 *
 *   unresolved running  withhold. Publishing it would hand consumers an
 *                       attribution key that is about to change.
 *   stopped             publish. Its filesystem is still on disk, and to a
 *                       consumer "absent from the list" means "deleted, sweep
 *                       its rows" — which is how a stop used to destroy the
 *                       inventory of a container that `docker start` could
 *                       bring straight back.
 *
 * ContainerState is what tells them apart, so these pin both directions and the
 * parsers that produce it.
 */

#include "cache/metadata_store.hpp"
#include "cache/lifecycle_journal.hpp"
#include "cache/reconciler.hpp"
#include "docker/docker_object_parser.hpp"
#include "kubernetes/k8s_object_parser.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

using namespace wazuh::container_instances;

namespace
{

const SourceId kDocker {"docker"};

ContainerRecord MakeRecord(const std::string& id, std::uint64_t inode, ContainerState state)
{
    ContainerRecord record;
    record.runtime = ContainerRuntime::docker;
    record.containerId = id;
    record.containerName = id;
    record.cgroupId = inode;
    record.state = state;
    return record;
}

std::vector<std::string> ListedIds(MetadataStore& store)
{
    std::vector<std::string> out;
    for (const auto& record : store.listContainers())
    {
        out.push_back(record->containerId);
    }
    std::sort(out.begin(), out.end());
    return out;
}

bool Contains(const std::vector<std::string>& haystack, const std::string& needle)
{
    return std::find(haystack.begin(), haystack.end(), needle) != haystack.end();
}

MetadataStore MakeStore()
{
    return MetadataStore {[](LogLevel, const std::string&) {}};
}

} // namespace

TEST(ContainerStateTest, StoppedContainerStaysInList)
{
    auto store = MakeStore();

    store.applySnapshot(kDocker, {MakeRecord("alpha", 4242, ContainerState::running)}, {4242},
                        std::chrono::steady_clock::now());
    ASSERT_TRUE(Contains(ListedIds(store), "alpha"));

    // It stops: no process, so no cgroup inode. The container itself is still
    // there — `docker ps -a` still shows it, its layers are still on disk.
    store.applySnapshot(kDocker, {MakeRecord("alpha", 0, ContainerState::stopped)}, {},
                        std::chrono::steady_clock::now());

    EXPECT_TRUE(Contains(ListedIds(store), "alpha"))
        << "a stopped container dropping out of the list reads as a deletion to every consumer, "
           "and its file and package inventory is swept";
}

TEST(ContainerStateTest, UnresolvedRunningStaysHidden)
{
    auto store = MakeStore();

    // Running, but the /proc join has not produced an inode yet. Publishing it
    // now would mean a consumer attributes events to a key of 0 and then has to
    // be told it changed.
    store.applySnapshot(kDocker, {MakeRecord("beta", 0, ContainerState::running)}, {},
                        std::chrono::steady_clock::now());

    EXPECT_FALSE(Contains(ListedIds(store), "beta"));

    store.applySnapshot(kDocker, {MakeRecord("beta", 7777, ContainerState::running)}, {7777},
                        std::chrono::steady_clock::now());

    EXPECT_TRUE(Contains(ListedIds(store), "beta")) << "it must appear once the inode is known";
}

TEST(ContainerStateTest, AnUnknownStateIsTreatedAsRunningSoItIsNeverPublishedWithoutAnInode)
{
    auto store = MakeStore();

    // A runtime whose state vocabulary we failed to parse. Erring toward
    // `running` keeps the old behaviour (withhold until resolved) rather than
    // publishing a zero key; erring the other way would publish nonsense.
    store.applySnapshot(kDocker, {MakeRecord("gamma", 0, ContainerState::unknown)}, {},
                        std::chrono::steady_clock::now());

    EXPECT_FALSE(Contains(ListedIds(store), "gamma"));
}

TEST(ContainerStateTest, ADeletedStoppedContainerLeavesTheListAtOnce)
{
    auto store = MakeStore();

    store.applySnapshot(kDocker, {MakeRecord("delta", 0, ContainerState::stopped)}, {},
                        std::chrono::steady_clock::now());
    ASSERT_TRUE(Contains(ListedIds(store), "delta"));

    // `docker rm`: now it really is gone, and it must leave immediately rather
    // than waiting out the removal grace — the grace exists to serve late events
    // against a cgroup, and a stopped container has none.
    store.applySnapshot(kDocker, {}, {}, std::chrono::steady_clock::now());

    EXPECT_FALSE(Contains(ListedIds(store), "delta"));
}

TEST(ContainerStateTest, DockerStateVocabularyMapsToHavingAProcessOrNot)
{
    using docker::parseDockerState;

    EXPECT_EQ(ContainerState::running, parseDockerState("running"));

    for (const auto* stopped : {"created", "exited", "dead", "restarting", "removing"})
    {
        EXPECT_EQ(ContainerState::stopped, parseDockerState(stopped)) << stopped;
    }

    // Paused is the one that looks like it should be running and must not be:
    // the tasks are frozen, so nothing can be read out of the container even
    // though its cgroup still exists.
    EXPECT_EQ(ContainerState::stopped, parseDockerState("paused"));

    EXPECT_EQ(ContainerState::unknown, parseDockerState("something-docker-added-later"));
    EXPECT_EQ(ContainerState::unknown, parseDockerState(""));
}

TEST(ContainerStateTest, KubernetesContainerStateMapsToHavingAProcessOrNot)
{
    using k8s::detail::parseContainerState;

    EXPECT_EQ(ContainerState::running,
              parseContainerState(nlohmann::json::parse(R"({"state":{"running":{"startedAt":"now"}}})")));

    // A completed Job.
    EXPECT_EQ(ContainerState::stopped,
              parseContainerState(nlohmann::json::parse(R"({"state":{"terminated":{"exitCode":0}}})")));

    // CrashLoopBackOff / ImagePullBackOff: in the pod, no process.
    EXPECT_EQ(ContainerState::stopped,
              parseContainerState(nlohmann::json::parse(R"({"state":{"waiting":{"reason":"CrashLoopBackOff"}}})")));

    EXPECT_EQ(ContainerState::unknown, parseContainerState(nlohmann::json::parse(R"({})")));
}

TEST(ContainerStateTest, AStateChangeAloneCountsAsAChangedRecord)
{
    // recordEquals drives the reconcile diff. If it ignored state, a stop with
    // no other field change would be invisible to it, and the journal WP1 adds
    // on top would never publish the transition.
    const auto running = MakeRecord("eps", 0, ContainerState::running);
    const auto stopped = MakeRecord("eps", 0, ContainerState::stopped);

    EXPECT_FALSE(recordEquals(running, stopped));
    EXPECT_TRUE(recordEquals(running, MakeRecord("eps", 0, ContainerState::running)));
}

/* --- restart detection ----------------------------------------------------
 *
 * A restart keeps the container id and may reuse the cgroup inode, so without
 * a start time nothing in the record distinguishes a container whose processes
 * and files are entirely new from one that never moved.
 *
 * restartCount does not serve: it is driven by the restart POLICY, so a
 * container restarted by hand leaves it where it was.
 */

TEST(ContainerStateTest, ARestartIsVisibleEvenWhenNothingElseMoves)
{
    auto before = MakeRecord("alpha", 4242, ContainerState::running);
    before.startedAt = "2026-10-05T10:00:00Z";

    auto after = MakeRecord("alpha", 4242, ContainerState::running);
    after.startedAt = "2026-10-05T11:30:00Z";

    // Same id, same inode, same image, same restart count — and yet a different
    // run, whose contents nobody has walked.
    EXPECT_FALSE(recordEquals(before, after));
    EXPECT_TRUE((lifecycleChangeMask(before, after) & LIFECYCLE_IDENTITY) != 0)
            << "a restart has to reach a consumer as an identity change, or the container is never re-scanned";
}

TEST(ContainerStateTest, RestartCountAloneWouldHaveMissedIt)
{
    // Pinning why startedAt was added rather than leaning on what was already
    // there: a manual `docker restart` does not touch restartCount, which only
    // the restart policy increments.
    auto before = MakeRecord("beta", 1, ContainerState::running);
    before.startedAt = "2026-10-05T10:00:00Z";
    before.restartCount = 0;

    auto after = before;
    after.startedAt = "2026-10-05T12:00:00Z";

    EXPECT_EQ(before.restartCount, after.restartCount);
    EXPECT_FALSE(recordEquals(before, after)) << "restartCount is unchanged, so only startedAt can catch this";
}

TEST(ContainerStateTest, DockerInspectSuppliesTheStartTimeAndPid)
{
    const auto detail = docker::parseInspect(nlohmann::json::parse(R"({
        "Id": "abc123",
        "Name": "/demo",
        "State": {"Status": "running", "Pid": 4321, "StartedAt": "2026-10-05T10:00:00.123456789Z"},
        "Config": {"Image": "alpine:latest"}
    })"));

    EXPECT_EQ(ContainerState::running, detail.record.state);
    EXPECT_EQ("2026-10-05T10:00:00.123456789Z", detail.record.startedAt);
    EXPECT_EQ(4321, detail.record.pid) << "the runtime knew the pid all along; consumers walk /proc to rediscover it";
}

TEST(ContainerStateTest, AStoppedDockerContainerReportsNoPid)
{
    const auto detail = docker::parseInspect(nlohmann::json::parse(R"({
        "Id": "abc123",
        "Name": "/demo",
        "State": {"Status": "exited", "Pid": 0, "StartedAt": "2026-10-05T10:00:00Z"},
        "Config": {"Image": "alpine:latest"}
    })"));

    EXPECT_EQ(ContainerState::stopped, detail.record.state);
    EXPECT_EQ(0, detail.record.pid);
}

TEST(ContainerStateTest, KubernetesTakesTheStartTimeFromTheRunningStateOnly)
{
    // A terminated container carries startedAt too, under `terminated`, and it
    // describes a run that has ENDED. Reading it would make a finished
    // container look freshly started.
    const auto running = k8s::detail::parseContainerState(
        nlohmann::json::parse(R"({"state":{"running":{"startedAt":"2026-10-05T10:00:00Z"}}})"));
    EXPECT_EQ(ContainerState::running, running);

    const auto terminated = k8s::detail::parseContainerState(
        nlohmann::json::parse(R"({"state":{"terminated":{"startedAt":"2026-10-05T09:00:00Z","exitCode":0}}})"));
    EXPECT_EQ(ContainerState::stopped, terminated);
}
