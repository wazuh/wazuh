/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_TESTS_COMPONENT_QUERY_FIXTURE_HPP
#define _INDEXER_CLIENT_TESTS_COMPONENT_QUERY_FIXTURE_HPP

// Shared by the query component suites (plan 18, plan-E4a §Tests): fakes that answer the health probe (green) plus
// the case's rules, the runtime started on their hosts with the probe running (one round applied before the case),
// a client without buckets and helpers over the recorded requests and detail::query::queryStats(). Time bounds are
// multiplied by TIME_SCALE (3 under TSAN, as bulkFairness_test.cpp).

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "componentFixture.hpp"
#include "fakeIndexer.hpp"
#include "health/nodeSet.hpp"
#include "health/prober.hpp"
#include "healthRules.hpp"
#include "indexer_client/runtime.hpp"
#include "json.hpp"
#include "query/query.hpp"
#include "testing/hooks.hpp"

#if defined(__SANITIZE_THREAD__)
#define QUERY_TEST_TSAN 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define QUERY_TEST_TSAN 1
#else
#define QUERY_TEST_TSAN 0
#endif
#else
#define QUERY_TEST_TSAN 0
#endif

namespace query_component
{
    using namespace std::chrono_literals;
    namespace ic = indexer_client;
    namespace q = indexer_client::detail::query;
    using indexer_client::testing::FakeIndexer;
    using indexer_client::testing::FakeIndexerOptions;
    using indexer_client::testing::RecordedRequest;
    using indexer_client::testing::Rule;
    using NodeState = indexer_client::HealthView::NodeState;

    constexpr int TIME_SCALE = QUERY_TEST_TSAN ? 3 : 1;

    /// A time bound of the plan («< 1 s», «+ margin»), x3 under TSAN.
    inline std::chrono::milliseconds scaled(std::chrono::milliseconds bound)
    {
        return bound * TIME_SCALE;
    }

    inline ic::TimePoint now()
    {
        return std::chrono::steady_clock::now();
    }

    inline ic::Deadline in(std::chrono::milliseconds span)
    {
        return now() + span;
    }

    inline std::chrono::milliseconds since(ic::TimePoint from)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(now() - from);
    }

    inline Rule rule(std::string method, std::string pathRegex, int status = 200, std::string body = "{}")
    {
        Rule r;
        r.method = std::move(method);
        r.pathRegex = std::move(pathRegex);
        r.status = status;
        r.body = std::move(body);
        return r;
    }

    /// An OpenSearch error body.
    inline std::string errorBody(const std::string& type, const std::string& reason, int status)
    {
        return nlohmann::json {{"error", {{"type", type}, {"reason", reason}}}, {"status", status}}.dump();
    }

    inline std::string indexNotFound(const std::string& index)
    {
        return errorBody("index_not_found_exception", "no such index [" + index + "]", 404);
    }

    /// The query string of a recorded target ("" without one).
    inline std::string queryString(const RecordedRequest& request)
    {
        const auto mark = request.target.find('?');
        return mark == std::string::npos ? std::string() : request.target.substr(mark + 1);
    }

    /// The requests of a fake other than the health probe, in arrival order.
    inline std::vector<RecordedRequest> queries(const FakeIndexer& fake)
    {
        std::vector<RecordedRequest> out;
        for (auto& request : fake.requests())
        {
            if (request.path != indexer_client::testing::HEALTH_PATH)
            {
                out.push_back(std::move(request));
            }
        }
        return out;
    }

    inline std::chrono::milliseconds gap(const RecordedRequest& first, const RecordedRequest& second)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(second.receivedAt - first.receivedAt);
    }

    /// queryStats() of `after` minus `before`.
    inline q::QueryStats delta(const q::QueryStats& before, const q::QueryStats& after)
    {
        q::QueryStats d;
        d.requests = after.requests - before.requests;
        d.failovers = after.failovers - before.failovers;
        d.throttles = after.throttles - before.throttles;
        d.unavailable = after.unavailable - before.unavailable;
        d.tooLarge = after.tooLarge - before.tooLarge;
        d.conflictRetries = after.conflictRetries - before.conflictRetries;
        return d;
    }

    /// Fast I82 options for the cases: 10 ms base, 100 ms cap, no jitter.
    inline ic::QueryOptions fastOptions()
    {
        ic::QueryOptions options;
        options.retry.base = ic::Duration {10};
        options.retry.cap = ic::Duration {100};
        options.retry.jitter = 0.0;
        return options;
    }

    /// One search hit: {"_index","_id","_source":{"n":k},"sort":[k]}.
    inline nlohmann::json hit(std::int64_t k)
    {
        return {{"_index", "idx"}, {"_id", "d" + std::to_string(k)}, {"_source", {{"n", k}}}, {"sort", {k}}};
    }

    /// A search response whose hits are `hits`.
    inline std::string searchResponse(const nlohmann::json& hits)
    {
        return nlohmann::json {{"took", 1},
                               {"timed_out", false},
                               {"hits", {{"total", {{"value", hits.size()}, {"relation", "eq"}}}, {"hits", hits}}}}
            .dump();
    }
} // namespace query_component

class QueryTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        indexer_client::testing_hooks::resetAll(); // The probe starts with the runtime (auto start on).
    }

    void TearDown() override
    {
        indexer_client::RuntimeOwner::shutdown();
        indexer_client::testing_hooks::resetAll();
        EXPECT_FALSE(indexer_client::RuntimeOwner::running());
        m_fakes.clear(); // The fakes outlive the runtime.
    }

    /// A fake answering the health probe green and then `rules` in order (bodies recorded unless `options` says
    /// otherwise).
    std::shared_ptr<query_component::FakeIndexer> fake(std::vector<query_component::Rule> rules = {},
                                                       std::optional<query_component::FakeIndexerOptions> options = {})
    {
        query_component::FakeIndexerOptions effective;
        effective.recordBodies = true;
        auto node = std::make_shared<query_component::FakeIndexer>(options ? std::move(*options) : effective);
        node->addRule(indexer_client::testing::healthRule("green"));
        for (auto& r : rules)
        {
            node->addRule(std::move(r));
        }
        node->start();
        m_fakes.push_back(node);
        return node;
    }

    /// Replaces the rules of `node` (the health rule first again).
    static void rules(query_component::FakeIndexer& node, std::vector<query_component::Rule> rules)
    {
        node.clearRules();
        node.addRule(indexer_client::testing::healthRule("green"));
        for (auto& r : rules)
        {
            node.addRule(std::move(r));
        }
    }

    /// Starts the runtime (K = 1, M = 2, probe every hour) on `hosts` with any other `indexer_client_<name>` values
    /// and, when `ssl` is set, that `ssl` object; waits (<= 5 s) until the first probe round has been applied.
    void start(const std::vector<std::string>& hosts,
               std::map<std::string, std::string> extra = {},
               const std::string& ssl = {})
    {
        std::map<std::string, std::string> values {{"analysisd.indexer_client_network_threads", "1"},
                                                   {"analysisd.indexer_client_cpu_threads", "2"},
                                                   {"analysisd.indexer_client_probe_interval_ms", "3600000"}};
        for (auto& [name, value] : extra)
        {
            values["analysisd.indexer_client_" + name] = value;
        }
        std::string json = "{\"hosts\":[";
        for (std::size_t i = 0; i < hosts.size(); ++i)
        {
            json += (i == 0 ? "\"" : ",\"") + hosts[i] + "\"";
        }
        json += "]";
        if (!ssl.empty())
        {
            json += ",\"ssl\":" + ssl;
        }
        json += "}";
        auto started = indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Analysisd,
                                                           component::MapSource(values, json));
        ASSERT_TRUE(started.ok()) << indexer_client::toString(started.cause) << ": " << started.reason;
        m_ref = started.value;
        ASSERT_TRUE(component::eventually([] { return probeRounds() >= 1; }, std::chrono::seconds(5)))
            << "the first probe round was never applied";
    }

    std::shared_ptr<indexer_client::Client> client(const std::string& consumer = "c")
    {
        auto created = m_ref.client(consumer, {});
        EXPECT_TRUE(created.ok()) << indexer_client::toString(created.cause) << ": " << created.reason;
        return created.value;
    }

    static std::uint64_t probeRounds()
    {
        const auto prober = indexer_client::detail::runtimeProber();
        return prober ? prober->stats().roundsApplied : 0;
    }

    static query_component::NodeState nodeState(std::size_t index)
    {
        return indexer_client::detail::runtimeNodeSet()->view().nodes.at(index).state;
    }

    static std::uint64_t transitions(std::size_t index)
    {
        return indexer_client::detail::runtimeNodeSet()->transitions(index);
    }

    indexer_client::RuntimeRef m_ref;
    std::vector<std::shared_ptr<query_component::FakeIndexer>> m_fakes;
};

#endif // _INDEXER_CLIENT_TESTS_COMPONENT_QUERY_FIXTURE_HPP
