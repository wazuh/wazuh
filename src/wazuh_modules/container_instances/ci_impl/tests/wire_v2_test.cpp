/*
 * Wazuh container_instances — protocol version 2 (#37203 O4, plan 18 WP5).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The only breaking change to a published contract in #37203, so the parts
 * that make it survivable are the parts worth pinning:
 *
 *   - the server answers BOTH versions for one release, because modulesd and
 *     syscheckd are separate processes restarted by separate units and cannot
 *     be upgraded atomically;
 *   - `cgroup_id` keeps meaning what it always meant, and is never used to
 *     carry something that is not one.
 *
 * The second is the subtle one. A field named `cgroup_id` holding a mount
 * namespace inode would be read, believed, and pushed into a kernel allowlist
 * that then matches nothing — while every log line reports success.
 */

#include "ipc/wire_protocol.hpp"

#include <gtest/gtest.h>

#include <string>
#include <variant>

using namespace wazuh::container_instances;

namespace
{

    const QueryRequest& AsRequest(const std::variant<QueryRequest, QueryResponse>& parsed)
    {
        return std::get<QueryRequest>(parsed);
    }

    ContainerRecord MakeRecord(std::uint64_t key)
    {
        ContainerRecord record;
        record.runtime = ContainerRuntime::docker;
        record.containerId = "abc123";
        record.containerName = "demo";
        record.hostKey = key;
        record.state = ContainerState::running;
        return record;
    }

} // namespace

TEST(WireV2Test, AVersionOneResolveStillWorksAndMeansCgroup)
{
    /* The alias window. A consumer that has not been restarted yet still sends
     * `cgroup_id`, and it must keep being answered — otherwise the upgrade
     * window is an outage window. */
    const auto parsed = wire::parseRequest(R"({"version":1,"op":"resolve","cgroup_id":"4242"})");

    ASSERT_TRUE(std::holds_alternative<QueryRequest>(parsed));
    EXPECT_EQ(4242u, AsRequest(parsed).hostKey);
    EXPECT_EQ(KeyKind::cgroupInode, AsRequest(parsed).keyKind) << "v1 had only one key space, and it was this one";
    EXPECT_EQ(1, AsRequest(parsed).version);
}

TEST(WireV2Test, AVersionTwoResolveStatesWhichKeySpaceItIsAskingIn)
{
    const auto parsed = wire::parseRequest(R"({"version":2,"op":"resolve","key_kind":"mnt_ns","key":"4026532281"})");

    ASSERT_TRUE(std::holds_alternative<QueryRequest>(parsed));
    EXPECT_EQ(4026532281u, AsRequest(parsed).hostKey);
    EXPECT_EQ(KeyKind::mntNsInode, AsRequest(parsed).keyKind);
}

TEST(WireV2Test, AKeyWithoutAKnownKindIsRefusedRatherThanGuessed)
{
    /* Defaulting an absent or unrecognised kind to `cgroup` would silently ask
     * in the wrong space on a legacy host — which is the exact confusion
     * key_kind was introduced to end, reintroduced as a convenience. */
    for (const auto* line : {R"({"version":2,"op":"resolve","key":"4242"})",
                             R"({"version":2,"op":"resolve","key":"4242","key_kind":"something_new"})",
                             R"({"version":2,"op":"resolve","key":"4242","key_kind":7})"})
    {
        EXPECT_TRUE(std::holds_alternative<QueryResponse>(wire::parseRequest(line))) << line;
    }
}

TEST(WireV2Test, AResolveWithNoKeyAtAllIsARequestError)
{
    const auto parsed = wire::parseRequest(R"({"version":2,"op":"resolve"})");

    ASSERT_TRUE(std::holds_alternative<QueryResponse>(parsed));
    EXPECT_EQ(QueryResponse::Status::error, std::get<QueryResponse>(parsed).status);
}

TEST(WireV2Test, TheKeyIsStillADecimalString)
{
    // cJSON parses JSON numbers as doubles and rounds silently above 2^53, and
    // a mount namespace inode shares the slot a 64-bit cgroup inode travels in.
    EXPECT_TRUE(std::holds_alternative<QueryResponse>(
        wire::parseRequest(R"({"version":2,"op":"resolve","key_kind":"cgroup","key":4242})")))
        << "a bare number must be refused, not accepted and rounded";

    const auto big =
        wire::parseRequest(R"({"version":2,"op":"resolve","key_kind":"cgroup","key":"18446744073709551615"})");
    ASSERT_TRUE(std::holds_alternative<QueryRequest>(big));
    EXPECT_EQ(18446744073709551615ull, AsRequest(big).hostKey);
}

TEST(WireV2Test, AnErrorIsReturnedInTheVersionThatCausedIt)
{
    // So the client that sent the bad request can actually read why.
    const auto parsed = wire::parseRequest(R"({"version":2,"op":"nonsense"})");

    ASSERT_TRUE(std::holds_alternative<QueryResponse>(parsed));
    const auto body = nlohmann::json::parse(wire::serializeResponse(std::get<QueryResponse>(parsed)));
    EXPECT_EQ(2, body["version"].get<int>());
}

/* --- the half that must never lie ---------------------------------------- */

TEST(WireV2Test, ARecordOnACgroupKeyedHostStillCarriesCgroupId)
{
    const auto data = wire::recordToJson(MakeRecord(4242), KeyKind::cgroupInode);

    EXPECT_EQ("4242", data["key"].get<std::string>());
    EXPECT_EQ("4242", data["cgroup_id"].get<std::string>())
        << "a v1 consumer reads this key and nothing else; dropping it on a host where it is "
           "correct would break it for no reason";
}

TEST(WireV2Test, ARecordOnANamespaceKeyedHostOmitsCgroupIdEntirely)
{
    /* The whole point. Writing the namespace inode under `cgroup_id` would be
     * read by a v1 consumer, believed, and installed into a kernel allowlist
     * keyed by cgroup — where it matches nothing, forever, with no error
     * anywhere. Omitting it makes that consumer read 0, which it already
     * treats as "not resolved yet". */
    const auto data = wire::recordToJson(MakeRecord(4026532281), KeyKind::mntNsInode);

    EXPECT_EQ("4026532281", data["key"].get<std::string>());
    EXPECT_FALSE(data.contains("cgroup_id")) << "a mount namespace inode was published under a field named cgroup_id";
}

TEST(WireV2Test, ADeltaEventFollowsTheSameRule)
{
    // Removals carry the key so a consumer can withdraw what it installed —
    // which means the same lie is available here, on the path that drives the
    // kernel allowlist directly.
    LifecycleDelta delta;
    delta.cursor = LifecycleCursor {7, 3};

    LifecycleEvent event;
    event.seq = 3;
    event.kind = LifecycleKind::removed;
    event.containerId = "abc123";
    event.hostKey = 4026532281;
    delta.events.push_back(event);

    nlohmann::json legacyBody;
    wire::serialiseDelta(delta, legacyBody, KeyKind::mntNsInode);
    EXPECT_EQ("4026532281", legacyBody["events"][0]["key"].get<std::string>());
    EXPECT_FALSE(legacyBody["events"][0].contains("cgroup_id"));

    nlohmann::json unifiedBody;
    wire::serialiseDelta(delta, unifiedBody, KeyKind::cgroupInode);
    EXPECT_EQ("4026532281", unifiedBody["events"][0]["cgroup_id"].get<std::string>());
}

TEST(WireV2Test, StatusPublishesTheHostsKeyKindSoConsumersNeedNotProbe)
{
    /* Two components independently classifying one host is the defect the
     * shared probe exists to prevent. If a consumer had to work the key space
     * out for itself, the protocol would hand that defect straight back. */
    QueryResponse response;
    response.status = QueryResponse::Status::ok;
    response.version = 2;
    response.keyKind = KeyKind::mntNsInode;
    response.connectorName = "docker";

    const auto body = nlohmann::json::parse(wire::serializeResponse(response));
    EXPECT_EQ("mnt_ns", body["data"]["key_kind"].get<std::string>());

    response.keyKind = KeyKind::cgroupInode;
    const auto unified = nlohmann::json::parse(wire::serializeResponse(response));
    EXPECT_EQ("cgroup", unified["data"]["key_kind"].get<std::string>());
}

TEST(WireV2Test, AVersionOneListReplyIsUnchangedForAVersionOneClient)
{
    // The delta keys were additive within v1 and must stay that way: a v1
    // client on a cgroup-keyed host sees exactly the reply it always saw.
    QueryResponse response;
    response.status = QueryResponse::Status::ok;
    response.version = 1;
    response.keyKind = KeyKind::cgroupInode;
    response.listReply = true;
    response.connectorName = "docker";
    response.containers.push_back(std::make_shared<const ContainerRecord>(MakeRecord(4242)));

    const auto body = nlohmann::json::parse(wire::serializeResponse(response));

    EXPECT_EQ(1, body["version"].get<int>());
    ASSERT_EQ(1U, body["containers"].size());
    EXPECT_EQ("4242", body["containers"][0]["cgroup_id"].get<std::string>());
}
