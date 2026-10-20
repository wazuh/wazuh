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

#ifndef _INDEXER_CLIENT_TESTS_BULK_FIXTURE_HPP
#define _INDEXER_CLIENT_TESTS_BULK_FIXTURE_HPP

// End-to-end fixture of the bulk sender (stage E3b-2): one fake per node answering `/_cluster/health` (green by
// default) and `_bulk` through a BulkResponder, the runtime started on those hosts with the probe running, and the
// WriteTest helpers (clients, buckets, stats, the drain check of the TearDown) on top. The production sink stays in
// place.

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "bulkResponder.hpp"
#include "health/nodeSet.hpp"
#include "health/prober.hpp"
#include "healthRules.hpp"
#include "writeFixture.hpp"

namespace bulk_component
{
    using indexer_client::testing::BulkItem;
    using indexer_client::testing::BulkResponder;
    using indexer_client::testing::BulkScript;
    using indexer_client::testing::FakeIndexer;
    using indexer_client::testing::FakeIndexerOptions;

    /// One indexer node of the test: its fake and its `_bulk` responder.
    struct Node final
    {
        std::shared_ptr<FakeIndexer> fake;
        std::shared_ptr<BulkResponder> bulk;

        std::string url() const
        {
            return fake->baseUrl();
        }
    };
} // namespace bulk_component

class BulkTest : public WriteTest
{
protected:
    std::vector<bulk_component::Node> m_nodes;

    void SetUp() override
    {
        indexer_client::testing_hooks::resetAll(); // The probe starts with the runtime (auto start on).
    }

    void TearDown() override
    {
        WriteTest::TearDown(); // Drain check, then shutdown: the fakes outlive the runtime.
        m_nodes.clear();
    }

    /// Rewrites a `_bulk` answer after the responder rendered it (e.g. a 413 for one chosen op).
    using BulkRewrite = std::function<void(const httplib::Request&, indexer_client::testing::Rule&)>;

    /// A node whose health answers `health` and whose `_bulk` answers `script` (by default every op succeeds), served
    /// with `options` (e.g. recordBodies); `rewrite`, when set, runs after the responder on every `_bulk` answer.
    bulk_component::Node startNode(bulk_component::BulkScript script = bulk_component::BulkScript::items(),
                                   const std::string& health = "green",
                                   bulk_component::FakeIndexerOptions options = {},
                                   BulkRewrite rewrite = {})
    {
        bulk_component::Node node;
        node.bulk = std::make_shared<bulk_component::BulkResponder>(std::move(script));
        node.fake = std::make_shared<bulk_component::FakeIndexer>(std::move(options));
        node.fake->addRule(indexer_client::testing::healthRule(health));
        auto rule = indexer_client::testing::bulkRule(node.bulk);
        if (rewrite)
        {
            rule.dynamic = [answer = std::move(rule.dynamic), rewrite = std::move(rewrite)](
                               const httplib::Request& request, indexer_client::testing::Rule& reply)
            {
                answer(request, reply);
                rewrite(request, reply);
            };
        }
        node.fake->addRule(std::move(rule));
        node.fake->start();
        m_nodes.push_back(node);
        return node;
    }

    /// Starts the runtime (K = 1, M = 2) on `hosts` with the probe interval and any other `indexer_client_<name>`
    /// values, and waits (<= 5 s) until the first probe round has been applied.
    void startOn(const std::vector<std::string>& hosts,
                 std::chrono::milliseconds probeInterval = std::chrono::milliseconds(3600000),
                 std::map<std::string, std::string> extra = {})
    {
        std::map<std::string, std::string> values {
            {"analysisd.indexer_client_network_threads", "1"},
            {"analysisd.indexer_client_cpu_threads", "2"},
            {"analysisd.indexer_client_probe_interval_ms", std::to_string(probeInterval.count())}};
        for (auto& [name, value] : extra)
        {
            values["analysisd.indexer_client_" + name] = value;
        }
        std::string json = "{\"hosts\":[";
        for (std::size_t i = 0; i < hosts.size(); ++i)
        {
            json += (i == 0 ? "\"" : ",\"") + hosts[i] + "\"";
        }
        json += "]}";
        auto started = indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Analysisd,
                                                           component::MapSource(values, json));
        ASSERT_TRUE(started.ok()) << indexer_client::toString(started.cause) << ": " << started.reason;
        m_ref = started.value;
        m_path = write_component::wr::runtimeWritePath();
        ASSERT_NE(m_path, nullptr);
        ASSERT_TRUE(component::eventually([] { return probeRounds() >= 1; }, std::chrono::seconds(5)))
            << "the first probe round was never applied";
    }

    static std::uint64_t probeRounds()
    {
        const auto prober = indexer_client::detail::runtimeProber();
        return prober ? prober->stats().roundsApplied : 0;
    }

    /// Runs one probe round now and waits (<= 5 s) until it has been applied.
    static bool probeNowAndWait()
    {
        const auto before = probeRounds();
        const auto prober = indexer_client::detail::runtimeProber();
        return prober && prober->probeNow() &&
               component::eventually([before] { return probeRounds() > before; }, std::chrono::seconds(5));
    }

    static indexer_client::HealthView::NodeState nodeState(std::size_t index)
    {
        return indexer_client::detail::runtimeNodeSet()->view().nodes.at(index).state;
    }
};

#endif // _INDEXER_CLIENT_TESTS_BULK_FIXTURE_HPP
