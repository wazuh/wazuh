/*
 * Wazuh Syscheckd — tests for the eBPF→reconcile staging buffer.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Every test here pins a property that, if it broke, would fail silently in
 * production: rows quietly lost, a container never re-read, or a consumer
 * re-baselining the node forever. The class has no I/O, so all of it is
 * reachable from a unit test — which is the reason it was separated from the
 * drain and the consumer in the first place.
 */

#include "container_event_staging.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

using fim_container_events::Batch;
using fim_container_events::ContainerEventStaging;

namespace
{
    constexpr int kNoWait = 0;
    constexpr int kShortWait = 200;

    /* Drains everything currently available. */
    std::vector<Batch> drainAll(ContainerEventStaging& staging)
    {
        std::vector<Batch> out;
        Batch batch;

        while (staging.nextBatch(batch, kNoWait))
        {
            out.push_back(batch);
        }

        return out;
    }
} // namespace

/* --- the release gate ------------------------------------------------------
 *
 * The 502-of-504 row loss: a reconcile that runs while the baseline walk holds
 * an open scoped transaction for the same container. Nothing may reach the
 * consumer before release().
 */

TEST(ContainerEventStaging, NothingIsServedBeforeRelease)
{
    ContainerEventStaging staging(1024, 128);

    staging.onEvent("c1", "/etc/passwd");
    staging.onEvent("c2", "/etc/hosts");
    staging.onDrops("c3");

    Batch batch;
    EXPECT_FALSE(staging.nextBatch(batch, kShortWait))
        << "work was served while the baseline walk could still be running";

    /* The work is not discarded, only withheld. */
    EXPECT_EQ(staging.pendingContainers(), 3u);

    staging.release();
    EXPECT_EQ(drainAll(staging).size(), 3u);
}

TEST(ContainerEventStaging, ReleaseWakesAWaitingConsumer)
{
    ContainerEventStaging staging(1024, 128);
    std::atomic<bool> got{false};

    std::thread consumer([&staging, &got] {
        Batch batch;

        if (staging.nextBatch(batch, 5000))
        {
            got = true;
        }
    });

    staging.onEvent("c1", "/etc/passwd");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(got.load()) << "served before release()";

    staging.release();
    consumer.join();
    EXPECT_TRUE(got.load()) << "release() did not wake a consumer that was already waiting";
}

/* --- de-duplication -------------------------------------------------------
 *
 * The reason this is a map and not fim::BoundedQueue: a container rewriting one
 * file in a loop is thousands of events and one unit of work.
 */

TEST(ContainerEventStaging, RepeatedWritesToOnePathAreOneUnitOfWork)
{
    ContainerEventStaging staging(1024, 128);
    staging.release();

    for (int i = 0; i < 5000; ++i)
    {
        staging.onEvent("c1", "/var/log/app.log");
    }

    const auto batches = drainAll(staging);
    ASSERT_EQ(batches.size(), 1u);
    EXPECT_FALSE(batches[0].suspect);
    ASSERT_EQ(batches[0].paths.size(), 1u);
    EXPECT_EQ(batches[0].paths[0], "/var/log/app.log");

    const auto stats = staging.stats();
    EXPECT_EQ(stats.staged, 1u);
    EXPECT_EQ(stats.deduplicated, 4999u);
}

TEST(ContainerEventStaging, PathsAreScopedPerContainer)
{
    ContainerEventStaging staging(1024, 128);
    staging.release();

    /* The same path in two containers is two distinct files — /etc/passwd in
     * container A is not /etc/passwd in container B. */
    staging.onEvent("a", "/etc/passwd");
    staging.onEvent("b", "/etc/passwd");

    const auto batches = drainAll(staging);
    ASSERT_EQ(batches.size(), 2u);
    EXPECT_EQ(batches[0].paths.size(), 1u);
    EXPECT_EQ(batches[1].paths.size(), 1u);
    EXPECT_NE(batches[0].container_id, batches[1].container_id);
}

/* --- the overflow rule ----------------------------------------------------
 *
 * "Suspect supersedes staged paths": exceeding the budget must escalate to a
 * re-walk, never drop the paths on the floor. This is the property that stops
 * this buffer from being a silent loss channel of its own.
 */

TEST(ContainerEventStaging, ExceedingThePathBudgetEscalatesToAReWalk)
{
    ContainerEventStaging staging(4 /* tiny budget */, 128);
    staging.release();

    for (int i = 0; i < 100; ++i)
    {
        staging.onEvent("c1", "/etc/f" + std::to_string(i));
    }

    const auto batches = drainAll(staging);
    ASSERT_EQ(batches.size(), 1u);
    EXPECT_TRUE(batches[0].suspect) << "the budget was exceeded and no re-walk was requested — those "
                                       "changes would never be reported";
    EXPECT_EQ(batches[0].container_id, "c1");
    EXPECT_TRUE(batches[0].paths.empty()) << "a Suspect batch must not also carry a partial path list, "
                                             "or the consumer does the work twice";
    EXPECT_EQ(staging.stats().path_overflows, 1u);
}

TEST(ContainerEventStaging, ExceedingTheContainerBudgetForcesAFullReBaseline)
{
    ContainerEventStaging staging(1024, 2 /* only two containers fit */);
    staging.release();

    staging.onEvent("a", "/etc/one");
    staging.onEvent("b", "/etc/two");
    staging.onEvent("c", "/etc/three"); /* does not fit at all */

    const auto batches = drainAll(staging);

    bool sawGlobalSuspect = false;

    for (const auto& batch : batches)
    {
        if (batch.suspect && batch.container_id.empty())
        {
            sawGlobalSuspect = true;
        }
    }

    EXPECT_TRUE(sawGlobalSuspect) << "a container that did not fit was dropped silently; nothing would "
                                     "ever re-read it";
    EXPECT_EQ(staging.stats().unknown_overflows, 1u);
}

/* --- loss escalation ------------------------------------------------------ */

TEST(ContainerEventStaging, AttributedDropsEscalateOnlyThatContainer)
{
    ContainerEventStaging staging(1024, 128);
    staging.release();

    staging.onEvent("quiet", "/etc/passwd");
    staging.onDrops("noisy");

    const auto batches = drainAll(staging);
    ASSERT_EQ(batches.size(), 2u);

    for (const auto& batch : batches)
    {
        if (batch.container_id == "noisy")
        {
            EXPECT_TRUE(batch.suspect);
        }
        else if (batch.container_id == "quiet")
        {
            EXPECT_FALSE(batch.suspect) << "a drop attributed to another container escalated this one — "
                                           "this is the whole-node re-baseline the per-cgroup drop map "
                                           "exists to avoid";
            EXPECT_EQ(batch.paths.size(), 1u);
        }
        else
        {
            FAIL() << "unexpected container '" << batch.container_id << "'";
        }
    }
}

TEST(ContainerEventStaging, DropsSupersedeAlreadyStagedPaths)
{
    ContainerEventStaging staging(1024, 128);
    staging.release();

    staging.onEvent("c1", "/etc/passwd");
    staging.onEvent("c1", "/etc/hosts");
    staging.onDrops("c1");

    const auto batches = drainAll(staging);
    ASSERT_EQ(batches.size(), 1u);
    EXPECT_TRUE(batches[0].suspect);
    EXPECT_TRUE(batches[0].paths.empty()) << "the re-walk covers the staged paths; carrying both means "
                                             "reading them twice";
}

TEST(ContainerEventStaging, EventsForAnAlreadySuspectContainerAreNotAccumulated)
{
    ContainerEventStaging staging(1024, 128);
    staging.release();

    staging.onDrops("c1");

    for (int i = 0; i < 1000; ++i)
    {
        staging.onEvent("c1", "/etc/f" + std::to_string(i));
    }

    /* Memory must not grow: the container is already going to be re-walked. */
    EXPECT_EQ(staging.pendingContainers(), 1u);
    EXPECT_EQ(staging.stats().staged, 0u);

    const auto batches = drainAll(staging);
    ASSERT_EQ(batches.size(), 1u);
    EXPECT_TRUE(batches[0].suspect);
}

TEST(ContainerEventStaging, UnattributedDropsEscalateEverything)
{
    ContainerEventStaging staging(1024, 128);
    staging.release();

    staging.onEvent("c1", "/etc/passwd");
    staging.onUnattributedDrops();

    const auto batches = drainAll(staging);

    bool sawGlobalSuspect = false;

    for (const auto& batch : batches)
    {
        if (batch.suspect && batch.container_id.empty())
        {
            sawGlobalSuspect = true;
        }
    }

    EXPECT_TRUE(sawGlobalSuspect) << "loss that cannot be attributed to a cgroup must escalate every "
                                     "container, since nothing is known about what changed";
}

TEST(ContainerEventStaging, TheGlobalSuspectIsServedOnceNotForever)
{
    ContainerEventStaging staging(1024, 128);
    staging.release();

    staging.onUnattributedDrops();

    Batch batch;
    ASSERT_TRUE(staging.nextBatch(batch, kNoWait));
    EXPECT_TRUE(batch.suspect);
    EXPECT_TRUE(batch.container_id.empty());

    EXPECT_FALSE(staging.nextBatch(batch, kNoWait))
        << "the node-wide Suspect was served again — the consumer would re-baseline in a loop";
}

/* --- lifecycle ------------------------------------------------------------ */

TEST(ContainerEventStaging, StopUnblocksAWaitingConsumer)
{
    ContainerEventStaging staging(1024, 128);
    staging.release();

    std::atomic<bool> returned{false};

    std::thread consumer([&staging, &returned] {
        Batch batch;
        staging.nextBatch(batch, 10000);
        returned = true;
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(returned.load());

    staging.stop();
    consumer.join();
    EXPECT_TRUE(returned.load()) << "stop() did not wake the consumer; shutdown would hang for the "
                                    "full poll timeout";
}

TEST(ContainerEventStaging, EmptyWhenNothingHappened)
{
    ContainerEventStaging staging(1024, 128);
    staging.release();

    Batch batch;
    EXPECT_FALSE(staging.nextBatch(batch, kNoWait));
    EXPECT_EQ(staging.pendingContainers(), 0u);
}

/* --- concurrency ---------------------------------------------------------
 *
 * The drain and the consumer are different threads by construction, so the
 * accounting has to hold under contention, not just in sequence.
 */

TEST(ContainerEventStaging, EveryStagedPathIsServedExactlyOnceUnderContention)
{
    ContainerEventStaging staging(100000, 1024);
    staging.release();

    constexpr int kProducers = 4;
    constexpr int kPathsEach = 2000;

    std::atomic<bool> producing{true};
    std::atomic<int> served{0};

    std::thread consumer([&staging, &producing, &served] {
        Batch batch;

        for (;;)
        {
            if (staging.nextBatch(batch, 50))
            {
                served += static_cast<int>(batch.paths.size());
            }
            else if (!producing.load())
            {
                /* One last sweep after the producers stopped. */
                while (staging.nextBatch(batch, 0))
                {
                    served += static_cast<int>(batch.paths.size());
                }

                return;
            }
        }
    });

    std::vector<std::thread> producers;

    for (int p = 0; p < kProducers; ++p)
    {
        producers.emplace_back([&staging, p] {
            for (int i = 0; i < kPathsEach; ++i)
            {
                staging.onEvent("c" + std::to_string(p), "/etc/f" + std::to_string(i));
            }
        });
    }

    for (auto& t : producers)
    {
        t.join();
    }

    producing = false;
    consumer.join();

    EXPECT_EQ(served, kProducers * kPathsEach)
        << "paths were lost or duplicated between the drain and the consumer";
    EXPECT_EQ(staging.stats().staged, static_cast<unsigned long long>(kProducers * kPathsEach));
    EXPECT_EQ(staging.stats().path_overflows, 0u);
    EXPECT_EQ(staging.pendingContainers(), 0u);
}
