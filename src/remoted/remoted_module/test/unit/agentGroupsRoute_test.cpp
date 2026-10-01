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
// What these pin: sets before invalidations, existing entries only (absent agents skipped, never
// created), activity untouched, an empty group list stored as "default", the whole body validated
// before anything is applied, 503 once the registry is gone, and the counters per agent. The route's
// registration on the admin socket (class, body cap, 405) is adminServer_test.cpp's.

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

    void expectCounts(const RecordingResponder& r, uint64_t updated, uint64_t invalidated, uint64_t skipped)
    {
        ASSERT_EQ(r.response().status, 200) << r.response().body;
        const auto body = r.json();
        EXPECT_EQ(body.at("updated").get<uint64_t>(), updated) << r.response().body;
        EXPECT_EQ(body.at("invalidated").get<uint64_t>(), invalidated) << r.response().body;
        EXPECT_EQ(body.at("skipped").get<uint64_t>(), skipped) << r.response().body;
    }
} // namespace

TEST(AgentGroupsRouteTest, SetUpdatesExistingEntriesAndSkipsAbsentOnes)
{
    Fixture f;
    f.putAgent(1, {"old"}, 10);
    f.putAgent(2, {"other"}, 10);
    const auto before = f.registry->get(1);

    const auto r = f.post(R"({"set":[{"id":1,"groups":["g1","default"]},{"id":3,"groups":["x"]}]})");

    EXPECT_EQ(r->sends(), 1);
    expectCounts(*r, 1, 0, 1);
    const auto entry = f.registry->get(1);
    EXPECT_EQ(entry->groups, (std::vector<std::string> {"g1", "default"})); // wazuh-db order, verbatim
    EXPECT_TRUE(groupsFresh(*entry, wallSec(), 60)) << "a publication is an established membership";
    EXPECT_GT(entry->groupsSeq, before->groupsSeq);
    EXPECT_EQ(entry->lastKeepaliveUpdateSec, 200U);
    EXPECT_EQ(entry->lastActivitySec, 300U);
    EXPECT_EQ(entry->createdAtSec, 50U);
    EXPECT_TRUE(entry->hostPersisted);
    EXPECT_EQ(f.registry->get(2)->groups, std::vector<std::string> {"other"});
    EXPECT_EQ(f.registry->get(3), nullptr) << "an absent agent is skipped, never created";
    EXPECT_EQ(f.registry->size(), 2U);
}

TEST(AgentGroupsRouteTest, InvalidateMarksEntriesNotEstablished)
{
    Fixture f;
    f.putAgent(1, {"g1"}, wallSec());
    const auto before = f.registry->get(1);

    const auto r = f.post(R"({"invalidate":[1,9]})");

    expectCounts(*r, 0, 1, 1);
    const auto entry = f.registry->get(1);
    EXPECT_EQ(entry->groupsRefreshedAtSec, 0U);
    EXPECT_EQ(entry->groups, std::vector<std::string> {"g1"});
    EXPECT_GT(entry->groupsSeq, before->groupsSeq);
    EXPECT_EQ(entry->lastActivitySec, 300U);
    EXPECT_EQ(f.registry->get(9), nullptr);
}

TEST(AgentGroupsRouteTest, SetsApplyBeforeInvalidationsAndLastWins)
{
    Fixture f;
    f.putAgent(1, {"old"}, 10);

    // The invalidation is listed first in the body and still applies last.
    const auto r = f.post(R"({"invalidate":[1],"set":[{"id":1,"groups":["a"]},{"id":1,"groups":["b"]}]})");

    expectCounts(*r, 2, 1, 0);
    const auto entry = f.registry->get(1);
    EXPECT_EQ(entry->groups, std::vector<std::string> {"b"});
    EXPECT_EQ(entry->groupsRefreshedAtSec, 0U);
}

TEST(AgentGroupsRouteTest, EmptyGroupListIsStoredAsDefault)
{
    Fixture f;
    f.putAgent(1, {"old"}, 10);

    const auto r = f.post(R"({"set":[{"id":1,"groups":[]}]})");

    expectCounts(*r, 1, 0, 0);
    // A row with no groups is membership of "default" -- stored as every other writer stores it.
    EXPECT_EQ(f.registry->get(1)->groups, std::vector<std::string> {"default"});
}

TEST(AgentGroupsRouteTest, UnknownKeysAreIgnored)
{
    Fixture f;
    f.putAgent(1, {"old"}, 10);

    const auto r = f.post(R"({"set":[{"id":1,"name":"web01","groups":["g1"]}],"invalidate":[],"extra":true})");

    expectCounts(*r, 1, 0, 0);
    EXPECT_EQ(f.registry->get(1)->groups, std::vector<std::string> {"g1"});
}

TEST(AgentGroupsRouteTest, MalformedBodiesAreRejectedAndNothingIsApplied)
{
    const std::vector<std::string> bodies {
        "not json",
        "[]",
        "{}",
        R"({"extra":1})",
        R"({"set":{}})",
        R"({"invalidate":5})",
        R"({"set":[5]})",
        R"({"set":[{"groups":["g1"]}]})",
        R"({"set":[{"id":"1","groups":["g1"]}]})",
        R"({"set":[{"id":0,"groups":["g1"]}]})",
        R"({"set":[{"id":4294967296,"groups":["g1"]}]})",
        R"({"set":[{"id":-1,"groups":["g1"]}]})",
        R"({"set":[{"id":1.5,"groups":["g1"]}]})",
        R"({"set":[{"id":1}]})",
        R"({"set":[{"id":1,"groups":"g1"}]})",
        R"({"set":[{"id":1,"groups":[""]}]})",
        R"({"set":[{"id":1,"groups":["a,b"]}]})",
        R"({"set":[{"id":1,"groups":[7]}]})",
        R"({"invalidate":["x"]})",
        // A valid element before a bad one: validated whole, so the first is not applied either.
        R"({"set":[{"id":1,"groups":["applied?"]},{"id":2,"groups":[""]}]})",
        R"({"set":[{"id":1,"groups":["applied?"]}],"invalidate":[0]})",
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
    EXPECT_EQ(f.metrics.updated->get() + f.metrics.invalidated->get() + f.metrics.skipped->get(), 0U);
}

TEST(AgentGroupsRouteTest, ExpiredRegistryAnswers503)
{
    Fixture f;
    f.handler = remoted::admin::makeAgentGroupsHandler(std::weak_ptr<AgentRegistry> {}, f.metrics);

    const auto r = f.post(R"({"set":[{"id":1,"groups":["g1"]}]})");

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

    f.post(R"({"set":[{"id":1,"groups":["g1"]},{"id":7,"groups":["g1"]}],"invalidate":[2,8,9]})");
    f.post(R"({"set":[{"id":2,"groups":["g2"]}]})");
    f.post("not json");

    // Per agent, not per request: 2 updated (1, 2), 1 invalidated (2), 3 skipped (7, 8, 9).
    EXPECT_EQ(f.metrics.updated->get(), 2U);
    EXPECT_EQ(f.metrics.invalidated->get(), 1U);
    EXPECT_EQ(f.metrics.skipped->get(), 3U);
    EXPECT_EQ(f.metrics.rejected->get(), 1U);
    // The same counters the manager dumps (GET /metrics), under the family's names.
    EXPECT_EQ(static_cast<uint64_t>(f.manager.get(METRIC_PUSH_UPDATED)->value()), 2U);
    EXPECT_EQ(static_cast<uint64_t>(f.manager.get(METRIC_PUSH_SKIPPED)->value()), 3U);
}
