/*
 * Wazuh remoted module - Admin route POST /_internal/agents/groups unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// The membership publication route, driven directly: the handler makeAgentGroupsHandler() returns,
// a real AgentRegistry and a real wazuh_metrics manager, with a responder that records the answer.
// What these pin: a publication only invalidates -- it never establishes or renews a membership,
// whatever else the body carries ("set" included) -- existing entries only (absent agents skipped,
// never created), activity untouched, the whole body validated before anything is applied, 503 once
// the registry is gone, and the counters per agent. The route's registration on the admin socket
// (class, body cap, 405) is adminServer_test.cpp's.

#include "admin/agentGroupsRoute.hpp"
#include "control/agentRegistry.hpp"
#include "control/metrics.hpp"

#include "json.hpp"

#include <gtest/gtest.h>
#include <wazuh_metrics/manager.hpp>

#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace remoted::control;

namespace
{
    /// Records the one response the handler sends (it answers inline, before returning).
    class RecordingResponder : public wazuh::uds_http::IHttpResponder
    {
    public:
        void send(wazuh::uds_http::HttpResponse response) override
        {
            ++m_sends;
            m_response = std::move(response);
        }
        int sends() const
        {
            return m_sends;
        }
        const wazuh::uds_http::HttpResponse& response() const
        {
            return *m_response;
        }
        nlohmann::json json() const
        {
            return nlohmann::json::parse(m_response->body);
        }

    private:
        int m_sends {0};
        std::optional<wazuh::uds_http::HttpResponse> m_response;
    };

    uint64_t wallSec()
    {
        return static_cast<uint64_t>(std::time(nullptr));
    }

    struct Fixture
    {
        wazuh::metrics::Manager manager;
        PushMetrics metrics {makePushMetrics(manager)};
        std::shared_ptr<AgentRegistry> registry = std::make_shared<AgentRegistry>();
        wazuh::uds_http::RouteHandler handler {remoted::admin::makeAgentGroupsHandler(registry, metrics)};

        /// An entry as /control leaves it: an established membership plus activity fields a
        /// publication must leave alone.
        void putAgent(AgentId id, std::vector<std::string> groups, uint64_t refreshedAt)
        {
            registry->update(id,
                             [&](std::shared_ptr<const AgentEntry>)
                             {
                                 auto e = std::make_shared<AgentEntry>();
                                 e->groups = groups;
                                 e->groupsRefreshedAtSec = refreshedAt;
                                 e->groupsSeq = registry->nextGroupsSeq();
                                 e->lastKeepaliveUpdateSec = 200;
                                 e->lastActivitySec = 300;
                                 e->createdAtSec = 50;
                                 e->hostPersisted = true;
                                 return e;
                             });
        }

        std::shared_ptr<RecordingResponder> post(const std::string& body)
        {
            auto request = std::make_shared<wazuh::uds_http::HttpRequest>();
            request->method = wazuh::uds_http::Method::Post;
            request->target = remoted::admin::AGENT_GROUPS_ROUTE_PATH;
            request->body = body;
            auto responder = std::make_shared<RecordingResponder>();
            handler(request, responder);
            return responder;
        }
    };

    void expectCounts(const RecordingResponder& r, uint64_t invalidated, uint64_t skipped)
    {
        ASSERT_EQ(r.response().status, 200) << r.response().body;
        const auto body = r.json();
        EXPECT_EQ(body.at("invalidated").get<uint64_t>(), invalidated) << r.response().body;
        EXPECT_EQ(body.at("skipped").get<uint64_t>(), skipped) << r.response().body;
        EXPECT_FALSE(body.contains("updated")) << "a publication never establishes groups: " << r.response().body;
    }
} // namespace

// The case the route exists for, and the one a late publication must not break: the entry holds a
// fresh membership a read established -- possibly newer than what the cluster daemon wrote when it
// published -- and the publication withdraws it without replacing or renewing it.
TEST(AgentGroupsRouteTest, InvalidateMarksEntriesNotEstablished)
{
    Fixture f;
    f.putAgent(1, {"g-read"}, wallSec());
    const auto before = f.registry->get(1);
    ASSERT_TRUE(groupsFresh(*before, wallSec(), 60));

    const auto r = f.post(R"({"invalidate":[1,9]})");

    EXPECT_EQ(r->sends(), 1);
    expectCounts(*r, 1, 1);
    const auto entry = f.registry->get(1);
    EXPECT_FALSE(groupsFresh(*entry, wallSec(), 60)) << "the next reader asks wazuh-db";
    EXPECT_EQ(entry->groupsRefreshedAtSec, 0U);
    EXPECT_EQ(entry->groups, std::vector<std::string> {"g-read"}) << "kept for notify's cached-on-error path";
    EXPECT_GT(entry->groupsSeq, before->groupsSeq) << "a read in flight across it is superseded";
    EXPECT_EQ(entry->lastKeepaliveUpdateSec, 200U);
    EXPECT_EQ(entry->lastActivitySec, 300U);
    EXPECT_EQ(entry->createdAtSec, 50U);
    EXPECT_TRUE(entry->hostPersisted);
    EXPECT_EQ(f.registry->get(9), nullptr) << "an absent agent is skipped, never created";
    EXPECT_EQ(f.registry->size(), 1U);
}

// S48: a publication never carries groups, so "set" is ignored like any other unknown key.
TEST(AgentGroupsRouteTest, SetIsIgnoredLikeAnyUnknownKey)
{
    Fixture f;
    f.putAgent(1, {"old"}, wallSec());
    f.putAgent(2, {"old"}, wallSec());
    const auto second = f.registry->get(2);

    const auto r = f.post(R"({"set":[{"id":2,"groups":["g-pushed"]}],"invalidate":[1]})");

    expectCounts(*r, 1, 0);
    EXPECT_EQ(f.registry->get(1)->groupsRefreshedAtSec, 0U);
    EXPECT_EQ(f.registry->get(2), second) << "the ignored set wrote nothing";
}

TEST(AgentGroupsRouteTest, UnknownKeysAreIgnored)
{
    Fixture f;
    f.putAgent(1, {"old"}, 10);

    const auto r = f.post(R"({"invalidate":[1],"extra":true})");

    expectCounts(*r, 1, 0);
    EXPECT_EQ(f.registry->get(1)->groupsRefreshedAtSec, 0U);
}

TEST(AgentGroupsRouteTest, MalformedBodiesAreRejectedAndNothingIsApplied)
{
    const std::vector<std::string> bodies {
        "not json",
        "[]",
        "{}",
        R"({"extra":1})",
        // Nothing but "set": ignored, so nothing this route applies -- refused for the missing "invalidate".
        R"({"set":[{"id":1,"groups":["g1"]}]})",
        R"({"invalidate":5})",
        R"({"invalidate":null})",
        R"({"invalidate":{}})",
        R"({"invalidate":["x"]})",
        R"({"invalidate":["1"]})",
        R"({"invalidate":[0]})",
        R"({"invalidate":[4294967296]})",
        R"({"invalidate":[-1]})",
        R"({"invalidate":[1.5]})",
        R"({"invalidate":[true]})",
        R"({"invalidate":[[1]]})",
        // A valid id before a bad one: validated whole, so the first is not applied either.
        R"({"invalidate":[1,0]})",
    };

    Fixture f;
    f.putAgent(1, {"g1"}, wallSec());
    const auto before = f.registry->get(1);

    for (const auto& body : bodies)
    {
        const auto r = f.post(body);
        EXPECT_EQ(r->sends(), 1) << body;
        EXPECT_EQ(r->response().status, 400) << body;
        const auto json = r->json();
        EXPECT_EQ(json.at("code").get<int>(), 400) << body;
        EXPECT_FALSE(json.at("error").get<std::string>().empty()) << body;
        EXPECT_EQ(f.registry->get(1), before) << "applied something from: " << body;
    }
    EXPECT_EQ(f.registry->size(), 1U);
    EXPECT_EQ(f.metrics.rejected->get(), bodies.size());
    EXPECT_EQ(f.metrics.invalidated->get() + f.metrics.skipped->get(), 0U);
}

TEST(AgentGroupsRouteTest, ExpiredRegistryAnswers503)
{
    Fixture f;
    f.handler = remoted::admin::makeAgentGroupsHandler(std::weak_ptr<AgentRegistry> {}, f.metrics);

    const auto r = f.post(R"({"invalidate":[1]})");

    EXPECT_EQ(r->response().status, 503);
    EXPECT_EQ(r->json().at("error"), "registry unavailable");
    EXPECT_EQ(r->json().at("code").get<int>(), 503);
    EXPECT_EQ(f.metrics.rejected->get(), 1U);
}

TEST(AgentGroupsRouteTest, CountersFollowOutcomes)
{
    Fixture f;
    f.putAgent(1, {"old"}, 10);
    f.putAgent(2, {"old"}, 10);

    f.post(R"({"invalidate":[1,7,2]})");
    f.post(R"({"invalidate":[2,8,9]})");
    f.post("not json");

    // Per agent, not per request: 3 invalidated (1, 2, 2 again), 3 skipped (7, 8, 9).
    EXPECT_EQ(f.metrics.invalidated->get(), 3U);
    EXPECT_EQ(f.metrics.skipped->get(), 3U);
    EXPECT_EQ(f.metrics.rejected->get(), 1U);
    // The same counters the manager dumps (GET /metrics), under the family's names.
    EXPECT_EQ(static_cast<uint64_t>(f.manager.get(METRIC_PUSH_INVALIDATED)->value()), 3U);
    EXPECT_EQ(static_cast<uint64_t>(f.manager.get(METRIC_PUSH_SKIPPED)->value()), 3U);
    EXPECT_EQ(f.manager.get("remoted.control.registry.push.updated"), nullptr) << "no \"updated\" outcome exists";
}
