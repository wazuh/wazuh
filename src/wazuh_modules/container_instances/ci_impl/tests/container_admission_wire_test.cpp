/*
 * Wazuh container_instances — publishing the admission decision.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The decision is made once, in this module, and both consumers read it from
 * the `list` reply — that is the only way syscheckd and modulesd, which are
 * separate processes, can withhold the SAME containers and leave the dashboard
 * showing one coherent set.
 *
 * What is pinned here is mostly about silence. A reply that did not consult the
 * decision must omit the key rather than guess a value, because a consumer that
 * finds a key treats it as an answer; and an agent talking to a server that
 * predates the key must keep reporting everything, since the failure mode of
 * the opposite default is an agent that silently stops reporting at all.
 */

#include "ipc/wire_protocol.hpp"

#include "container_instances_client.hpp"

#include <gtest/gtest.h>

#include <set>
#include <string>

using namespace wazuh::container_instances;

namespace
{

    ContainerRecord MakeRecord(const std::string& containerId)
    {
        ContainerRecord record;
        record.runtime = ContainerRuntime::docker;
        record.containerId = containerId;
        record.containerName = "demo";
        record.hostKey = 4242;
        record.state = ContainerState::running;
        return record;
    }

} // namespace

TEST(ContainerAdmissionWireTest, AnAdmittedContainerIsPublishedAsSynced)
{
    const std::set<std::string> admitted {"admitted-one"};

    const auto data = wire::recordToJson(MakeRecord("admitted-one"), KeyKind::cgroupInode, &admitted);

    ASSERT_TRUE(data.contains("synced"));
    EXPECT_TRUE(data["synced"].get<bool>());
}

TEST(ContainerAdmissionWireTest, AWithheldContainerIsPublishedButNotSynced)
{
    const std::set<std::string> admitted {"admitted-one"};

    const auto data = wire::recordToJson(MakeRecord("withheld-one"), KeyKind::cgroupInode, &admitted);

    // Still a full record: the container EXISTS, and every consumer must keep
    // counting it as known. Dropping it from the list instead would make the
    // stale sweeps delete its rows rather than withhold them.
    EXPECT_EQ("withheld-one", data["container_id"].get<std::string>());
    EXPECT_EQ("4242", data["key"].get<std::string>());

    ASSERT_TRUE(data.contains("synced"));
    EXPECT_FALSE(data["synced"].get<bool>());
}

TEST(ContainerAdmissionWireTest, ARecordSerialisedWithNoDecisionOmitsTheKey)
{
    // A `resolve` asks which container an event belongs to; it says nothing
    // about reporting. Emitting `synced` here would be an answer to a question
    // that was never asked, and the client's own default already covers it.
    const auto data = wire::recordToJson(MakeRecord("any"), KeyKind::cgroupInode);

    EXPECT_FALSE(data.contains("synced")) << "a reply that never consulted the admission decision claimed one anyway";
}

TEST(ContainerAdmissionWireTest, AnUnlimitedCapPublishesEveryContainerAsSynced)
{
    // With no cap the store admits everything, so the set holds every visible
    // id rather than being empty — one question to ask, no second code path.
    const std::set<std::string> admitted {"a", "b", "c"};

    for (const auto& id : admitted)
    {
        const auto data = wire::recordToJson(MakeRecord(id), KeyKind::cgroupInode, &admitted);
        EXPECT_TRUE(data["synced"].get<bool>()) << "container " << id << " was withheld with no cap configured";
    }
}

TEST(ContainerAdmissionWireTest, ADeltaEventCarriesTheDecisionToo)
{
    // A consumer that follows the cursor never re-reads the full list, so a
    // decision that only reached the full-list path would never reach it.
    const std::set<std::string> admitted {"kept"};

    LifecycleDelta delta;

    LifecycleEvent kept;
    kept.kind = LifecycleKind::added;
    kept.containerId = "kept";
    kept.hostKey = 4242;
    kept.record = std::make_shared<const ContainerRecord>(MakeRecord("kept"));

    LifecycleEvent withheld;
    withheld.kind = LifecycleKind::added;
    withheld.containerId = "withheld";
    withheld.hostKey = 4243;
    withheld.record = std::make_shared<const ContainerRecord>(MakeRecord("withheld"));

    delta.events.push_back(kept);
    delta.events.push_back(withheld);

    nlohmann::json body;
    wire::serialiseDelta(delta, body, KeyKind::cgroupInode, &admitted);

    ASSERT_TRUE(body.contains("events"));
    ASSERT_EQ(2U, body["events"].size());
    EXPECT_TRUE(body["events"][0]["data"]["synced"].get<bool>());
    EXPECT_FALSE(body["events"][1]["data"]["synced"].get<bool>());
}

/* The other half of the contract: the consumer reading what the producer just
 * wrote. Both halves in one test on purpose -- the key only does its job if the
 * two agree on its name, its type and which object carries it, and a producer
 * test alone cannot see the reader drift away from any of the three.
 *
 * This is the delta path specifically. A container created while the agent runs
 * is announced as an `added` EVENT, never as a fresh full list, so a decision
 * that reaches only the full-list reader never reaches such a container at all.
 */
TEST(ContainerAdmissionWireTest, TheClientReadsAdmissionOffADeltaEvent)
{
    const std::set<std::string> admitted {"kept"};

    LifecycleDelta delta;

    LifecycleEvent kept;
    kept.kind = LifecycleKind::added;
    kept.containerId = "kept";
    kept.hostKey = 4242;
    kept.record = std::make_shared<const ContainerRecord>(MakeRecord("kept"));

    LifecycleEvent withheld;
    withheld.kind = LifecycleKind::added;
    withheld.containerId = "withheld";
    withheld.hostKey = 4243;
    withheld.record = std::make_shared<const ContainerRecord>(MakeRecord("withheld"));

    delta.events.push_back(kept);
    delta.events.push_back(withheld);

    nlohmann::json body;
    body["containers"] = nlohmann::json::array();
    wire::serialiseDelta(delta, body, KeyKind::cgroupInode, &admitted);

    const auto parsed = wazuh::container_instances_client::ContainerInstancesClient::parseListReply(body);

    ASSERT_TRUE(parsed.deltaSupported);
    ASSERT_EQ(2U, parsed.events.size());
    EXPECT_EQ("kept", parsed.events[0].containerId);
    EXPECT_TRUE(parsed.events[0].synced);
    EXPECT_EQ("withheld", parsed.events[1].containerId);
    EXPECT_FALSE(parsed.events[1].synced);
}

/* The admitted set rides every list reply, so a consumer learns about an
 * admission change for a container that produced no lifecycle event -- which
 * is how a readmitted container is readmitted at all. A reader that predates
 * the key must not read its absence as "nobody is admitted".
 */
TEST(ContainerAdmissionWireTest, TheAdmittedSetRoundTripsAndIsOptional)
{
    QueryResponse response;
    response.status = QueryResponse::Status::ok;
    response.listReply = true;
    response.admitted = {"a", "b"};

    const auto parsed = nlohmann::json::parse(wire::serializeResponse(response));
    ASSERT_TRUE(parsed.contains("admitted"));

    const auto read = wazuh::container_instances_client::ContainerInstancesClient::parseListReply(parsed);
    EXPECT_TRUE(read.admittedKnown);
    EXPECT_EQ(read.admitted, (std::set<std::string> {"a", "b"}));

    // A reply from before the key existed.
    nlohmann::json legacy;
    legacy["containers"] = nlohmann::json::array();
    const auto old = wazuh::container_instances_client::ContainerInstancesClient::parseListReply(legacy);
    EXPECT_FALSE(old.admittedKnown) << "absent must not read as an empty admitted set";
    EXPECT_TRUE(old.admitted.empty());
}

/* A server that predates the key sends no `synced`, and the reader must leave
 * its default standing. The opposite default silently stops a working agent
 * from reporting anything about the container.
 */
TEST(ContainerAdmissionWireTest, ADeltaEventWithoutTheKeyStaysSynced)
{
    LifecycleDelta delta;

    LifecycleEvent event;
    event.kind = LifecycleKind::added;
    event.containerId = "legacy";
    event.hostKey = 4242;
    event.record = std::make_shared<const ContainerRecord>(MakeRecord("legacy"));
    delta.events.push_back(event);

    nlohmann::json body;
    body["containers"] = nlohmann::json::array();
    // No admitted set: exactly what a server built before the decision existed
    // puts on the wire.
    wire::serialiseDelta(delta, body, KeyKind::cgroupInode);

    ASSERT_FALSE(body["events"][0]["data"].contains("synced"));

    const auto parsed = wazuh::container_instances_client::ContainerInstancesClient::parseListReply(body);

    ASSERT_EQ(1U, parsed.events.size());
    EXPECT_TRUE(parsed.events[0].synced) << "absent must read as 'may report'";
}
