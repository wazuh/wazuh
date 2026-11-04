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

/* A store that cannot yet see the whole node has no verdict, and a reply must
 * say so by SILENCE -- no `admitted` key, no per-record `synced`. An empty
 * `admitted` array would say the opposite of what is meant: every consumer
 * reads absence from that set as a refusal, so the agent would stop reporting
 * every container for the length of the settle window.
 *
 * Silence is already the path against a connector older than the decision, so
 * no consumer needs a branch it does not already have.
 */
TEST(ContainerAdmissionWireTest, AReplyWithNoVerdictOmitsTheSetAndEveryRecordFlag)
{
    QueryResponse response;
    response.status = QueryResponse::Status::ok;
    response.listReply = true;
    response.admissionKnown = false;
    response.admitted = {"a"}; // whatever the store happens to hold is not an answer yet
    response.containers = {std::make_shared<const ContainerRecord>(MakeRecord("a")),
                           std::make_shared<const ContainerRecord>(MakeRecord("b"))};

    const auto parsed = nlohmann::json::parse(wire::serializeResponse(response));

    EXPECT_FALSE(parsed.contains("admitted")) << "an empty or partial set reads as a refusal";

    ASSERT_EQ(2U, parsed["containers"].size());
    for (const auto& record : parsed["containers"])
    {
        EXPECT_FALSE(record.contains("synced")) << "including the one the store happens to hold";
    }

    const auto read = wazuh::container_instances_client::ContainerInstancesClient::parseListReply(parsed);
    EXPECT_FALSE(read.admittedKnown);

    for (const auto& ref : read.containers)
    {
        EXPECT_TRUE(ref.synced) << "and the client keeps reporting, as against a server too old to decide";
    }
}

// V1/V8. Omission alone cannot tell a consumer WHY there is no verdict, and the
// two reasons call for opposite behaviour: a connector too old to decide never
// will, so reporting everything is right and permanent; this one decides in a
// moment, so reporting everything writes default-true sync flags over refusals
// it is about to re-issue.
TEST(ContainerAdmissionWireTest, AWithheldVerdictSaysItIsPendingRatherThanMerelyAbsent)
{
    QueryResponse response;
    response.status = QueryResponse::Status::ok;
    response.listReply = true;
    response.admissionKnown = false;
    response.containers = {std::make_shared<const ContainerRecord>(MakeRecord("a"))};

    const auto parsed = nlohmann::json::parse(wire::serializeResponse(response));

    ASSERT_TRUE(parsed.contains("admission_pending"));
    EXPECT_TRUE(parsed["admission_pending"].get<bool>());

    const auto read = wazuh::container_instances_client::ContainerInstancesClient::parseListReply(parsed);
    EXPECT_TRUE(read.admissionPending);
    EXPECT_FALSE(read.admittedKnown) << "still no verdict; pending says why, it does not supply one";
}

TEST(ContainerAdmissionWireTest, ASettledReplyDoesNotCarryThePendingKeyAtAll)
{
    QueryResponse response;
    response.status = QueryResponse::Status::ok;
    response.listReply = true;
    response.admissionKnown = true;
    response.admitted = {"a"};
    response.containers = {std::make_shared<const ContainerRecord>(MakeRecord("a"))};

    const auto parsed = nlohmann::json::parse(wire::serializeResponse(response));

    EXPECT_FALSE(parsed.contains("admission_pending")) << "emitted only when true, so an older client sees nothing new";

    const auto read = wazuh::container_instances_client::ContainerInstancesClient::parseListReply(parsed);
    EXPECT_FALSE(read.admissionPending);
    EXPECT_TRUE(read.complete);
}

// V8, which no finding in the round named. The barrier gates the ADMISSION
// verdict, but `withheld` and `known_unkeyed` describe only the resolver's
// backlog -- they say nothing about a source that has not enumerated at all.
// So a reply sent while only Docker had listed looked like a complete node, and
// a consumer that deletes rows on absence deleted live Kubernetes containers'.
TEST(ContainerAdmissionWireTest, APendingReplyIsNotAuthoritativeAboutWhatExists)
{
    QueryResponse response;
    response.status = QueryResponse::Status::ok;
    response.listReply = true;
    response.admissionKnown = false;
    // Everything this source can see IS keyed, so the resolver's own backlog is
    // empty and the reply would otherwise claim to be the whole node.
    response.containers = {std::make_shared<const ContainerRecord>(MakeRecord("docker-one"))};

    const auto parsed = nlohmann::json::parse(wire::serializeResponse(response));
    ASSERT_EQ(0U, parsed["withheld"].get<std::uint64_t>()) << "nothing is waiting on a key";

    const auto read = wazuh::container_instances_client::ContainerInstancesClient::parseListReply(parsed);

    EXPECT_FALSE(read.complete) << "a node half of whose sources have not spoken is not a complete node";
    EXPECT_FALSE(read.unkeyedKnown) << "and its unkeyed ids are not the node's unkeyed ids either";
}

// The compatibility half, pulling the other way. A server from before any of
// this sends no `admitted` and no `admission_pending`, and must keep being read
// as "decides nothing, ever" -- not as a node that is still settling, which
// would stop the agent reporting and never resume.
TEST(ContainerAdmissionWireTest, AServerTooOldToDecideIsNotMistakenForOneStillSettling)
{
    const auto parsed = nlohmann::json::parse(R"({"status":"ok","containers":[]})");

    const auto read = wazuh::container_instances_client::ContainerInstancesClient::parseListReply(parsed);

    EXPECT_FALSE(read.admissionPending);
    EXPECT_FALSE(read.admittedKnown);
    EXPECT_TRUE(read.complete) << "the default every consumer already relies on";
}

// Settlement and permission to DELETE are different questions, and the
// grace separates them.
//
// The verdict settles on the grace whether or not every source has spoken --
// withholding it for ever would mean the cap never applies at all. So after a
// grace settle with one runtime still silent, `admission_pending` is gone and
// the reply looks authoritative about a node whose Kubernetes containers are
// entirely absent from it. `withheld` and `known_unkeyed` cannot catch that:
// they describe the resolver's backlog, and a source that never enumerated
// contributes no records to have a backlog about.
TEST(ContainerAdmissionWireTest, ASettledVerdictStillSaysWhenASourceHasNotEnumerated)
{
    QueryResponse response;
    response.status = QueryResponse::Status::ok;
    response.listReply = true;
    response.admissionKnown = true; // the grace decided it
    response.admitted = {"docker-one"};
    response.sourcesEnumerated = false; // ...but Kubernetes never listed
    response.containers = {std::make_shared<const ContainerRecord>(MakeRecord("docker-one"))};

    const auto parsed = nlohmann::json::parse(wire::serializeResponse(response));

    EXPECT_FALSE(parsed.contains("admission_pending")) << "the verdict really is settled";
    ASSERT_TRUE(parsed.contains("sources_pending"));
    ASSERT_EQ(0U, parsed["withheld"].get<std::uint64_t>()) << "nothing is waiting on a key, either";

    const auto read = wazuh::container_instances_client::ContainerInstancesClient::parseListReply(parsed);

    EXPECT_TRUE(read.admittedKnown) << "the cap applies; this is not a reason to stop enforcing it";
    EXPECT_FALSE(read.admissionPending) << "and consumers must NOT freeze their sync flags for it";
    EXPECT_TRUE(read.sourcesPending) << "the consumer must distinguish a silent source from an old connector";
    EXPECT_FALSE(read.complete) << "but the node is not fully described, so nothing may be deleted";
    EXPECT_FALSE(read.unkeyedKnown);
}

TEST(ContainerAdmissionWireTest, AFullyEnumeratedNodeCarriesNoSourcesPendingKey)
{
    QueryResponse response;
    response.status = QueryResponse::Status::ok;
    response.listReply = true;
    response.admissionKnown = true;
    response.admitted = {"a"};
    response.containers = {std::make_shared<const ContainerRecord>(MakeRecord("a"))};

    const auto parsed = nlohmann::json::parse(wire::serializeResponse(response));

    EXPECT_FALSE(parsed.contains("sources_pending")) << "emitted only when true, like every additive key here";

    const auto read = wazuh::container_instances_client::ContainerInstancesClient::parseListReply(parsed);
    EXPECT_FALSE(read.sourcesPending);
    EXPECT_TRUE(read.complete) << "a whole node, authoritative about what exists";
}

TEST(ContainerAdmissionWireTest, ASilentSourcePreservesTheNamedVerdictsOnADeltaReply)
{
    QueryResponse response;
    response.status = QueryResponse::Status::ok;
    response.listReply = true;
    response.admissionKnown = true;
    response.sourcesEnumerated = false;
    response.admitted = {"kept"};
    response.delta.emplace();
    LifecycleEvent event;
    event.kind = LifecycleKind::added;
    event.containerId = "refused";
    event.hostKey = 4242;
    event.record = std::make_shared<const ContainerRecord>(MakeRecord("refused"));
    response.delta->events.push_back(event);

    const auto parsed = nlohmann::json::parse(wire::serializeResponse(response));
    const auto read = wazuh::container_instances_client::ContainerInstancesClient::parseListReply(parsed);

    EXPECT_TRUE(read.sourcesPending);
    EXPECT_TRUE(read.admittedKnown);
    EXPECT_FALSE(read.admissionPending);
    EXPECT_FALSE(read.complete);
    EXPECT_FALSE(read.unkeyedKnown);
    EXPECT_EQ(read.admitted, (std::set<std::string> {"kept"}));
    ASSERT_EQ(read.events.size(), 1u);
    EXPECT_FALSE(read.events[0].synced) << "a named refusal is still a real verdict";
}
