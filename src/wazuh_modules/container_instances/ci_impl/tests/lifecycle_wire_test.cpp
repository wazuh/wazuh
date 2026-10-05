/*
 * Wazuh container_instances — the cursor on the wire (#37532 / #37203).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The delta rides the existing `list` op as optional fields rather than
 * arriving as a new op, and the protocol version stays at 1. That only works
 * if the additions are genuinely invisible to anyone who does not ask for
 * them, in both directions:
 *
 *   old client, new server   a request without a cursor must get back exactly
 *                            the reply it got before, byte for byte.
 *   new client, old server   the reply has no epoch, which is the signal to
 *                            fall back to whole-list diffing — with no error
 *                            path on either side.
 *
 * The version check is strict equality, so getting this wrong is not a
 * degradation but a hard refusal between an agent and a module that disagree
 * by one release.
 */

#include "cache/metadata_store.hpp"
#include "ipc/wire_protocol.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <string>

using namespace wazuh::container_instances;

namespace
{

QueryResponse MakeListReply(std::vector<ContainerRecordPtr> containers)
{
    QueryResponse response;
    response.status = QueryResponse::Status::ok;
    response.listReply = true;
    response.connectorName = "docker";
    response.containers = std::move(containers);
    return response;
}

ContainerRecordPtr MakeRecord(const std::string& id, std::uint64_t inode)
{
    ContainerRecord record;
    record.runtime = ContainerRuntime::docker;
    record.containerId = id;
    record.containerName = id;
    record.cgroupId = inode;
    record.state = ContainerState::running;
    return std::make_shared<const ContainerRecord>(std::move(record));
}

const QueryRequest& AsRequest(const std::variant<QueryRequest, QueryResponse>& parsed)
{
    return std::get<QueryRequest>(parsed);
}

} // namespace

TEST(LifecycleWireTest, ListWithoutACursorIsByteIdenticalToTheV1Reply)
{
    // The compatibility guarantee, stated as an equality rather than an
    // inspection: whatever the delta added must not reach a client that did not
    // ask for it, including as an empty key.
    const auto reply = MakeListReply({MakeRecord("alpha", 10)});

    const auto serialised = wire::serializeResponse(reply);
    const auto parsed = nlohmann::json::parse(serialised);

    EXPECT_FALSE(parsed.contains("epoch"));
    EXPECT_FALSE(parsed.contains("seq"));
    EXPECT_FALSE(parsed.contains("events"));
    EXPECT_FALSE(parsed.contains("resync_required"));
    EXPECT_TRUE(parsed.contains("containers"));
}

TEST(LifecycleWireTest, ProtocolVersionStaysOne)
{
    // The check is strict equality, so a bump is not a compatible change: an
    // agent and a module one release apart would simply refuse each other.
    EXPECT_EQ(1, wire::PROTOCOL_VERSION);

    const auto rejected = wire::parseRequest(R"({"version":2,"op":"list"})");
    ASSERT_TRUE(std::holds_alternative<QueryResponse>(rejected));
}

TEST(LifecycleWireTest, ACursorIsParsedFromTheListRequest)
{
    const auto parsed = wire::parseRequest(R"({"version":1,"op":"list","since_epoch":"42","since_seq":"7"})");

    ASSERT_TRUE(std::holds_alternative<QueryRequest>(parsed));
    const auto& request = AsRequest(parsed);

    ASSERT_TRUE(request.since.has_value());
    EXPECT_EQ(42u, request.since->epoch);
    EXPECT_EQ(7u, request.since->seq);
}

TEST(LifecycleWireTest, AListRequestWithoutACursorStillParses)
{
    const auto parsed = wire::parseRequest(R"({"version":1,"op":"list"})");

    ASSERT_TRUE(std::holds_alternative<QueryRequest>(parsed));
    EXPECT_FALSE(AsRequest(parsed).since.has_value());
}

TEST(LifecycleWireTest, AHalfCursorIsRejectedRatherThanTreatedAsCold)
{
    // Serving half a cursor as "read from the start" would hand back a full set
    // on every poll and look like it was working.
    const auto halfA = wire::parseRequest(R"({"version":1,"op":"list","since_epoch":"42"})");
    const auto halfB = wire::parseRequest(R"({"version":1,"op":"list","since_seq":"7"})");

    EXPECT_FALSE(AsRequest(halfA).since.has_value());
    EXPECT_FALSE(AsRequest(halfB).since.has_value());
}

TEST(LifecycleWireTest, ACursorThatIsNotADecimalStringIsAnError)
{
    // Numbers specifically: cJSON parses them as doubles and rounds above 2^53,
    // so accepting one would corrupt an epoch rather than fail.
    const auto numeric = wire::parseRequest(R"({"version":1,"op":"list","since_epoch":42,"since_seq":7})");
    ASSERT_TRUE(std::holds_alternative<QueryResponse>(numeric));

    const auto garbage = wire::parseRequest(R"({"version":1,"op":"list","since_epoch":"x","since_seq":"7"})");
    ASSERT_TRUE(std::holds_alternative<QueryResponse>(garbage));
}

TEST(LifecycleWireTest, EpochAndSeqAreSerialisedAsDecimalStrings)
{
    LifecycleDelta delta;
    delta.cursor = LifecycleCursor {18446744073709551615ULL, 9007199254740993ULL}; // > 2^53

    auto reply = MakeListReply({});
    reply.delta = delta;

    const auto parsed = nlohmann::json::parse(wire::serializeResponse(reply));

    ASSERT_TRUE(parsed["epoch"].is_string());
    ASSERT_TRUE(parsed["seq"].is_string());
    EXPECT_EQ("18446744073709551615", parsed["epoch"].get<std::string>());
    EXPECT_EQ("9007199254740993", parsed["seq"].get<std::string>()) << "a double would have rounded this";
}

TEST(LifecycleWireTest, RemovedEventCarriesCgroupIdAndNoRecord)
{
    LifecycleEvent removed;
    removed.seq = 5;
    removed.kind = LifecycleKind::removed;
    removed.containerId = "gone";
    removed.cgroupId = 4242;

    LifecycleDelta delta;
    delta.cursor = LifecycleCursor {1, 5};
    delta.events.push_back(removed);

    auto reply = MakeListReply({});
    reply.delta = delta;

    const auto parsed = nlohmann::json::parse(wire::serializeResponse(reply));

    ASSERT_EQ(1u, parsed["events"].size());
    const auto& event = parsed["events"][0];

    EXPECT_EQ("removed", event["kind"].get<std::string>());
    EXPECT_EQ("4242", event["cgroup_id"].get<std::string>()) << "FIM keys its allowlist by inode";
    EXPECT_FALSE(event.contains("data"));
}

TEST(LifecycleWireTest, ChangedClassesTravelAsNamesNotABitmask)
{
    // A class a consumer does not know must be VISIBLY unknown so it can
    // re-scan conservatively. An unrecognised bit in an integer reads as zero
    // and the consumer silently skips the work it owed.
    LifecycleEvent changed;
    changed.kind = LifecycleKind::changed;
    changed.containerId = "c";
    changed.changed = LIFECYCLE_IMAGE | LIFECYCLE_NETWORK;

    LifecycleDelta delta;
    delta.events.push_back(changed);

    auto reply = MakeListReply({});
    reply.delta = delta;

    const auto parsed = nlohmann::json::parse(wire::serializeResponse(reply));
    const auto& names = parsed["events"][0]["changed"];

    ASSERT_TRUE(names.is_array());
    EXPECT_EQ(2u, names.size());
    EXPECT_EQ("image", names[0].get<std::string>());
    EXPECT_EQ("network", names[1].get<std::string>());
}

TEST(LifecycleWireTest, ResyncSaysSoExplicitlyAndSendsTheSetInContainers)
{
    // An empty event list is also what "nothing changed" looks like, so the
    // flag is explicit rather than inferred. The set rides `containers`, the
    // key every existing client already reads.
    LifecycleDelta delta;
    delta.resyncRequired = true;
    delta.cursor = LifecycleCursor {7, 100};

    auto reply = MakeListReply({MakeRecord("still-here", 1)});
    reply.delta = delta;

    const auto parsed = nlohmann::json::parse(wire::serializeResponse(reply));

    EXPECT_TRUE(parsed.value("resync_required", false));
    ASSERT_EQ(1u, parsed["containers"].size());
    EXPECT_FALSE(parsed.contains("events"));
}

TEST(LifecycleWireTest, AnEmptyDeltaStillCarriesTheCursorToComeBackWith)
{
    // Nothing changed is the commonest reply by far. It must still advance the
    // caller's cursor, or every poll would re-read from the same point and the
    // ring would eventually overrun behind it.
    LifecycleDelta delta;
    delta.cursor = LifecycleCursor {3, 55};

    auto reply = MakeListReply({});
    reply.delta = delta;

    const auto parsed = nlohmann::json::parse(wire::serializeResponse(reply));

    EXPECT_EQ("3", parsed["epoch"].get<std::string>());
    EXPECT_EQ("55", parsed["seq"].get<std::string>());
    ASSERT_TRUE(parsed.contains("events"));
    EXPECT_TRUE(parsed["events"].empty());
}
