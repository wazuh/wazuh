/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_TEST_REAL_INDEXER_HPP
#define _INVSYNC_TEST_REAL_INDEXER_HPP

// A REAL indexer_client runtime on the client library's in-process fake indexer (IC/tests/fake), with the module's
// own Client: the `inventory` and `agent-state` buckets built by the production spec functions. What the tests of
// the by-id half of a whole-agent deletion, of the sweeper and of the ordered bucket need: a Group and its tickets
// cannot be faked without the library's internals, and the fake indexer keeps NO documents, so the oracles of these
// tests read the wire (paths, bodies, the order of the requests, the scripted answers).

#include "indexer/indexerClientSyncAdapter.hpp"
#include "inventory_sync_server.h"

#include <indexer_client/keyValueConfigSource.hpp>
#include <indexer_client/runtime.hpp>

#include "bulkResponder.hpp"
#include "fakeIndexer.hpp"
#include "healthRules.hpp"

#include <json.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace invsync::test
{
    using namespace std::chrono_literals;

    constexpr std::uint64_t REAL_INDEXER_GLOBAL_QUOTA {256ULL * 1024ULL * 1024ULL};

    /// The body of a delete-by-query that deleted @p deleted documents.
    inline std::string dbqBody(std::uint64_t deleted)
    {
        return std::string {R"({"took":1,"timed_out":false,"deleted":)"} + std::to_string(deleted) +
               R"(,"version_conflicts":0,"failures":[]})";
    }

    /// Polls @p condition every 2 ms until it holds or @p timeout passes.
    inline bool waitUntil(const std::function<bool()>& condition, std::chrono::milliseconds timeout = 5000ms)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (!condition())
        {
            if (std::chrono::steady_clock::now() >= deadline)
            {
                return condition();
            }
            std::this_thread::sleep_for(2ms);
        }
        return true;
    }

    /// A `_delete_by_query` rule for @p index: the path is `/<index>/_delete_by_query`.
    inline indexer_client::testing::Rule
    dbqRuleFor(const std::string& index, int status, std::string body, std::chrono::milliseconds latency = 0ms)
    {
        indexer_client::testing::Rule rule;
        rule.method = "POST";
        rule.pathRegex = "/" + index + "/_delete_by_query";
        rule.status = status;
        rule.body = std::move(body);
        rule.latency = latency;
        return rule;
    }

    /**
     * @brief The module's Client on a real runtime over a fake indexer.
     *
     * Lifecycle: construct (the fake is up, health green, `_bulk` answered by `bulk`), add rules of your own
     * (they precede the defaults), startRuntime(), makeClient(). The destructor closes everything in order.
     * Rules added before startRuntime() win over the default `_delete_by_query` / `_update_by_query` rules.
     */
    class RealIndexer
    {
    public:
        struct Specs
        {
            indexer_client::BucketSpec inventory;
            indexer_client::BucketSpec agentState;
        };

        explicit RealIndexer(
            indexer_client::testing::BulkScript defaultScript = indexer_client::testing::BulkScript::items())
        {
            indexer_client::testing::FakeIndexerOptions options;
            options.recordBodies = true;
            fake = std::make_shared<indexer_client::testing::FakeIndexer>(options);
            bulk = std::make_shared<indexer_client::testing::BulkResponder>(std::move(defaultScript));
            fake->addRule(indexer_client::testing::healthRule("green"));
            fake->addRule(indexer_client::testing::bulkRule(bulk));
            fake->start();
        }

        ~RealIndexer()
        {
            shutdown();
        }

        RealIndexer(const RealIndexer&) = delete;
        RealIndexer& operator=(const RealIndexer&) = delete;

        /// Starts the runtime on the fake. @p extraOptions are more `key=value` lines of the internal options
        /// (`wazuh_modules.indexer_client_...`), e.g. a short `request_timeout_ms`.
        void startRuntime(const std::string& extraOptions = "")
        {
            // Defaults last, so any rule a test added for the same route wins.
            indexer_client::testing::Rule dbq;
            dbq.method = "POST";
            dbq.pathRegex = "(/[^/]+)?/_delete_by_query";
            dbq.body = dbqBody(0);
            fake->addRule(std::move(dbq));
            indexer_client::testing::Rule update;
            update.method = "POST";
            update.pathRegex = "(/[^/]+)?/_update_by_query";
            update.body = R"({"updated":0,"version_conflicts":0,"failures":[]})";
            fake->addRule(std::move(update));

            const std::string text = "wazuh_modules.indexer_client_network_threads=1\n"
                                     "wazuh_modules.indexer_client_cpu_threads=2\n"
                                     "wazuh_modules.indexer_client_probe_interval_ms=200\n" +
                                     extraOptions;
            const std::string json = "{\"hosts\":[\"" + fake->baseUrl() + "\"]}";
            auto source =
                indexer_client::KeyValueConfigSource::parse(text, json, indexer_client::Credentials {"admin", "admin"});
            startError = source.ok() ? "" : source.reason;
            if (!source.ok())
            {
                return;
            }
            auto started = indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Modulesd, source.value);
            if (!started.ok())
            {
                startError = std::string {indexer_client::toString(started.cause)} + ": " + started.reason;
                return;
            }
            ref = started.value;
            runtimeStarted = true;
        }

        /// The module's two bucket specs as the facade derives them (agent-state first, inventory from the rest),
        /// tuned for a test: quick retries and pending ops that wait long enough to be looked at.
        static Specs specs(const inventory_sync_server_config_t& config = noOpinionConfig())
        {
            Specs result;
            result.agentState = invsync::indexer::agentStateBucketSpec(config, REAL_INDEXER_GLOBAL_QUOTA);
            result.agentState.retry.base = 20ms;
            result.inventory = invsync::indexer::inventoryBucketSpec(
                config, REAL_INDEXER_GLOBAL_QUOTA - result.agentState.quotaBytes, 2000ms);
            result.inventory.retry.base = 20ms;
            result.inventory.bulk.maxAge = 60s;
            return result;
        }

        /// The module's options with every knob at "no opinion" (< 0): the defaults.
        static inventory_sync_server_config_t noOpinionConfig()
        {
            inventory_sync_server_config_t config {};
            config.indexer_sync_connector_max_bulk_size = -1;
            config.indexer_sync_max_retry_attempts = -1;
            config.indexer_sync_max_retry_duration_seconds = -1;
            config.indexer_sync_max_retry_delay_seconds = -1;
            config.indexer_async_bulk_max_bytes = -1;
            config.indexer_async_max_retry_delay_seconds = -1;
            return config;
        }

        /// One Client with both buckets, once a node is Available. False (and a reason) when refused.
        bool makeClient(const Specs& buckets, bool waitAvailable = true)
        {
            auto outcome = ref.client(invsync::indexer::INDEXER_CLIENT_CONSUMER,
                                      std::vector<indexer_client::BucketSpec> {buckets.inventory, buckets.agentState});
            if (!outcome.ok())
            {
                startError = std::string {indexer_client::toString(outcome.cause)} + ": " + outcome.reason;
                return false;
            }
            client = outcome.value;
            return !waitAvailable || waitUntil([this] { return client->health().anyAvailable(); });
        }

        std::shared_ptr<indexer_client::IWriter> agentStateWriter() const
        {
            return client->writer(invsync::indexer::AGENT_STATE_BUCKET);
        }

        /// A sync adapter over the Client, on `inventory`.
        std::unique_ptr<invsync::indexer::IndexerClientSyncAdapter>
        makeAdapter(const std::string& tag = "w0", std::size_t capBytes = 4U * 1024U * 1024U)
        {
            invsync::indexer::AdapterOptions options;
            options.capBytes = capBytes;
            options.budgets = invsync::indexer::budgets(noOpinionConfig());
            return std::make_unique<invsync::indexer::IndexerClientSyncAdapter>(client, options, closing, tag);
        }

        /// Every op of every `_bulk` received, in arrival order.
        std::vector<indexer_client::testing::BulkOp> bulkOps() const
        {
            std::vector<indexer_client::testing::BulkOp> ops;
            for (const auto& request : bulk->received())
            {
                ops.insert(ops.end(), request.begin(), request.end());
            }
            return ops;
        }

        /// The `_delete_by_query` requests received for @p index, in arrival order.
        std::vector<indexer_client::testing::RecordedRequest> dbqRequests(const std::string& index) const
        {
            std::vector<indexer_client::testing::RecordedRequest> result;
            for (auto& request : fake->requests())
            {
                if (request.method == "POST" && request.path == "/" + index + "/_delete_by_query")
                {
                    result.push_back(std::move(request));
                }
            }
            return result;
        }

        /// The `terms._id` ids of a recorded delete-by-query body (empty when it has none).
        static std::vector<std::string> termsIds(const indexer_client::testing::RecordedRequest& request)
        {
            std::vector<std::string> ids;
            const auto body = nlohmann::json::parse(request.body, nullptr, false);
            if (body.is_discarded() || !body.contains("query") || !body["query"].contains("terms") ||
                !body["query"]["terms"].contains("_id"))
            {
                return ids;
            }
            for (const auto& id : body["query"]["terms"]["_id"])
            {
                ids.push_back(id.get<std::string>());
            }
            return ids;
        }

        /// Closes the Client, then the runtime. Idempotent.
        void shutdown()
        {
            closing->store(true);
            if (fake)
            {
                fake->releaseHeld(); // Nothing may wait on a response the test never released.
            }
            if (client)
            {
                client->requestClose();
                client->awaitClosed(std::chrono::steady_clock::now() + 3s);
                client.reset();
            }
            if (runtimeStarted)
            {
                indexer_client::RuntimeOwner::beginShutdown(std::chrono::steady_clock::now() + 5s);
                indexer_client::RuntimeOwner::shutdown();
                runtimeStarted = false;
            }
            fake.reset(); // The fake outlives the runtime.
        }

        std::shared_ptr<indexer_client::testing::FakeIndexer> fake;
        std::shared_ptr<indexer_client::testing::BulkResponder> bulk;
        indexer_client::RuntimeRef ref;
        bool runtimeStarted {false};
        std::string startError;
        std::shared_ptr<indexer_client::Client> client;
        std::shared_ptr<std::atomic<bool>> closing {std::make_shared<std::atomic<bool>>(false)};
    };

} // namespace invsync::test

#endif // _INVSYNC_TEST_REAL_INDEXER_HPP
