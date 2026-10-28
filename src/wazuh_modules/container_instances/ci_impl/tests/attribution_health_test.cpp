/*
 * Wazuh container_instances — noticing when cgroup attribution has stopped working.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Everything else that can go wrong on this path announces itself. This one
 * does not: the runtime answers, records are published, and every one of them
 * carries key 0. The module looks healthy and container FIM is empty.
 *
 * So what these tests pin is mostly the NEGATIVE half — the four ordinary
 * situations that also produce zero keys and must stay quiet. A warning that
 * fires on a host with nothing but stopped containers, or on the first
 * reconcile after startup, is a warning that gets ignored, and then the real
 * one is ignored with it.
 */

#include "core/attribution_health.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace wazuh::container_instances;

namespace
{

    wz_cgroup_mode_t hybridProbe()
    {
        return WZ_CGROUP_MODE_HYBRID;
    }

    wz_cgroup_mode_t unifiedProbe()
    {
        return WZ_CGROUP_MODE_UNIFIED;
    }

    ContainerRecord makeRecord(std::string id, ContainerState state, std::uint64_t hostKey)
    {
        ContainerRecord record;
        record.containerId = std::move(id);
        record.state = state;
        record.hostKey = hostKey;
        return record;
    }

    /// Collects warnings only: the levels below it are noise for these tests.
    struct WarningSink
    {
        std::vector<std::string> messages;

        Logger logger()
        {
            return [this](LogLevel level, const std::string& message)
            {
                if (level == LogLevel::warn)
                {
                    messages.push_back(message);
                }
            };
        }
    };

    /// The threshold is private, so drive it rather than read it.
    void observeTimes(AttributionHealth& health,
                      const std::vector<ContainerRecord>& records,
                      const Logger& logger,
                      int times,
                      AttributionHealth::CgroupModeProbe probe = &hybridProbe)
    {
        for (int i = 0; i < times; ++i)
        {
            health.observe(records, logger, probe);
        }
    }

} // namespace

TEST(AttributionHealthTest, WarnsOnceWhenNoRunningContainerResolves)
{
    WarningSink sink;
    AttributionHealth health;

    const std::vector<ContainerRecord> records {makeRecord("a", ContainerState::running, 0),
                                                makeRecord("b", ContainerState::running, 0)};

    observeTimes(health, records, sink.logger(), 10);

    ASSERT_EQ(sink.messages.size(), 1u) << "one message per outage, not one per reconcile";
    EXPECT_NE(sink.messages[0].find("2 running container(s)"), std::string::npos);
    EXPECT_NE(sink.messages[0].find("hybrid"), std::string::npos);
    // The remedy, not just the symptom: this host's cause is diagnosable and
    // the admin has an action, so the message says what it is.
    EXPECT_NE(sink.messages[0].find("runc"), std::string::npos);
}

TEST(AttributionHealthTest, StaysQuietUntilTheFaultHasPersisted)
{
    WarningSink sink;
    AttributionHealth health;

    const std::vector<ContainerRecord> records {makeRecord("a", ContainerState::running, 0)};

    // A container the runtime reports running a moment before its cgroup is
    // visible looks exactly like the fault. Warning on the first sighting would
    // put this message in the log of every healthy host at startup.
    observeTimes(health, records, sink.logger(), 2);
    EXPECT_TRUE(sink.messages.empty());

    observeTimes(health, records, sink.logger(), 1);
    EXPECT_EQ(sink.messages.size(), 1u);
}

TEST(AttributionHealthTest, StoppedContainersAreNotEvidenceOfAnything)
{
    WarningSink sink;
    AttributionHealth health;

    // Correct and ordinary: no process, so no cgroup, so no key. A host whose
    // containers are all stopped is not a host with broken attribution.
    const std::vector<ContainerRecord> records {makeRecord("a", ContainerState::stopped, 0),
                                                makeRecord("b", ContainerState::stopped, 0)};

    observeTimes(health, records, sink.logger(), 10);

    EXPECT_TRUE(sink.messages.empty());
}

TEST(AttributionHealthTest, OneResolvedContainerClearsTheSuspicion)
{
    WarningSink sink;
    AttributionHealth health;

    // Attribution demonstrably works; the unresolved one is a container the
    // resolver has not caught up with, which is the normal transient.
    const std::vector<ContainerRecord> records {makeRecord("a", ContainerState::running, 0),
                                                makeRecord("b", ContainerState::running, 4242)};

    observeTimes(health, records, sink.logger(), 10);

    EXPECT_TRUE(sink.messages.empty());
}

TEST(AttributionHealthTest, AnEmptyHostIsNotABrokenHost)
{
    WarningSink sink;
    AttributionHealth health;

    observeTimes(health, {}, sink.logger(), 10);

    EXPECT_TRUE(sink.messages.empty());
}

TEST(AttributionHealthTest, RecoveryRearmsTheWarning)
{
    WarningSink sink;
    AttributionHealth health;

    const std::vector<ContainerRecord> blind {makeRecord("a", ContainerState::running, 0)};
    const std::vector<ContainerRecord> healthy {makeRecord("a", ContainerState::running, 99)};

    observeTimes(health, blind, sink.logger(), 5);
    ASSERT_EQ(sink.messages.size(), 1u);

    observeTimes(health, healthy, sink.logger(), 1);
    observeTimes(health, blind, sink.logger(), 5);

    // A second outage is a second event worth knowing about. The latch exists
    // to stop a message repeating, not to make it once per process lifetime.
    EXPECT_EQ(sink.messages.size(), 2u);
}

TEST(AttributionHealthTest, TheRuncHintIsHybridOnly)
{
    WarningSink sink;
    AttributionHealth health;

    const std::vector<ContainerRecord> records {makeRecord("a", ContainerState::running, 0)};

    observeTimes(health, records, sink.logger(), 5, &unifiedProbe);

    ASSERT_EQ(sink.messages.size(), 1u);
    EXPECT_NE(sink.messages[0].find("unified"), std::string::npos);
    // On a unified host the cause is something else entirely, and pointing at
    // runc would send whoever reads it down the wrong path.
    EXPECT_EQ(sink.messages[0].find("runc"), std::string::npos);
}

TEST(AttributionHealthTest, AnUnknownStateCountsAsRunning)
{
    WarningSink sink;
    AttributionHealth health;

    // isRunning() treats `unknown` as running so an unparsed state can never
    // cause a container's rows to be swept. The same reading applies here: a
    // container whose state nobody could parse is still a container that
    // should have resolved.
    const std::vector<ContainerRecord> records {makeRecord("a", ContainerState::unknown, 0)};

    observeTimes(health, records, sink.logger(), 5);

    EXPECT_EQ(sink.messages.size(), 1u);
}
