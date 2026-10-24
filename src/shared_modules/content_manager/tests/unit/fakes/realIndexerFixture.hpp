/*
 * Wazuh content manager - unit test fakes
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _REAL_INDEXER_FIXTURE_HPP
#define _REAL_INDEXER_FIXTURE_HPP

// A REAL indexer_client runtime served by the client library's in-process fake indexer (IC/tests/fake), with the
// Client a host would hand to makeContentIndexer(). The fake keeps no documents: PitResponder synthesizes documents
// 1..N (`{"_source":{"n":k},"sort":[k]}`, sliced by (k - 1) % max; it ignores `query` and `sort`), so the oracles of
// these tests read the wire (paths, bodies, request counts). Only the `indexer_client` shared library is linked
// (never `indexer_client_testing`), so the process holds a single runtime, shared with the library under test.

#include "contentIndexerAdapters.hpp"

#include <indexer_client/client.hpp>
#include <indexer_client/keyValueConfigSource.hpp>
#include <indexer_client/runtime.hpp>

#include "fakeIndexer.hpp"
#include "healthRules.hpp"
#include "pitResponder.hpp"

#include <json.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace cmtest
{
    using namespace std::chrono_literals;

    inline constexpr const char* CONSUMER_NAME {"content_manager"};

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

    /// The sort the content cycle sends (PitSession::docSort()).
    inline nlohmann::json docSort()
    {
        return nlohmann::json::array({nlohmann::json {{"_doc", "asc"}}, nlohmann::json {{"_id", "asc"}}});
    }

    inline nlohmann::json matchAll()
    {
        return nlohmann::json {{"match_all", nlohmann::json::object()}};
    }

    /// The `n` of every hit of a `hits` object, in order.
    inline std::vector<std::int64_t> numbersOf(const nlohmann::json& hits)
    {
        std::vector<std::int64_t> numbers;
        for (const auto& hit : hits.at("hits"))
        {
            numbers.push_back(hit.at("_source").at("n").get<std::int64_t>());
        }
        return numbers;
    }

    /// An IClient whose query() is null, as a closed Client's is.
    class NullQueryClient final : public indexer_client::IClient
    {
    public:
        std::shared_ptr<indexer_client::IWriter> writer(std::string_view) override
        {
            return nullptr;
        }

        std::shared_ptr<indexer_client::IQuery> query() override
        {
            return nullptr;
        }

        indexer_client::HealthView health() const override
        {
            return {};
        }

        void requestClose() override {}

        indexer_client::Outcome<indexer_client::CloseReport> awaitClosed(indexer_client::Deadline) override
        {
            return indexer_client::Outcome<indexer_client::CloseReport>::success({});
        }

        indexer_client::ClientMetrics metrics() const override
        {
            return {};
        }
    };

    struct RealIndexerOptions
    {
        /// Documents the PIT responder serves (1..N).
        std::int64_t documents {300};
        /// What the fake answers to the health probe.
        indexer_client::testing::Rule health {indexer_client::testing::healthRule("green")};
    };

    /**
     * @brief A real runtime and Client over a fake indexer.
     *
     * Lifecycle: construct (the fake is up and answers the health probe), add rules of your own with `fake->addRule`
     * (they precede the defaults) and/or `pits->intercept`, startRuntime(), makeClient(), adapter(). The destructor
     * closes everything in order; declare the fixture before anything that holds the Client.
     */
    class RealIndexer
    {
    public:
        explicit RealIndexer(RealIndexerOptions options = {})
            : pits(std::make_shared<indexer_client::testing::PitResponder>(options.documents))
        {
            indexer_client::testing::FakeIndexerOptions fakeOptions;
            fakeOptions.recordBodies = true;
            fake = std::make_shared<indexer_client::testing::FakeIndexer>(fakeOptions);
            fake->addRule(std::move(options.health));
            fake->start();
        }

        ~RealIndexer()
        {
            shutdown();
        }

        RealIndexer(const RealIndexer&) = delete;
        RealIndexer& operator=(const RealIndexer&) = delete;

        /// Adds the default rules (PIT routes, an empty answer for a search on an index) and starts the runtime.
        void startRuntime(const std::string& extraOptions = "")
        {
            indexer_client::testing::Rule searchIndex;
            searchIndex.method = "POST";
            searchIndex.pathRegex = "/[^/]+/_search";
            searchIndex.body = R"({"took":1,"timed_out":false,"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}})";
            fake->addRule(std::move(searchIndex));
            for (auto& rule : pits->rules())
            {
                fake->addRule(std::move(rule));
            }

            const std::string text = "wazuh_modules.indexer_client_network_threads=1\n"
                                     "wazuh_modules.indexer_client_cpu_threads=2\n"
                                     "wazuh_modules.indexer_client_probe_interval_ms=200\n" +
                                     extraOptions;
            startError = startWith(fake->baseUrl(), text);
        }

        /// Starts the runtime on @p url. Returns the reason when it fails, empty otherwise.
        std::string startWith(const std::string& url, const std::string& text)
        {
            const std::string json = "{\"hosts\":[\"" + url + "\"]}";
            auto source =
                indexer_client::KeyValueConfigSource::parse(text, json, indexer_client::Credentials {"admin", "admin"});
            if (!source.ok())
            {
                return source.reason;
            }
            auto started = indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Modulesd, source.value);
            if (!started.ok())
            {
                return std::string {indexer_client::toString(started.cause)} + ": " + started.reason;
            }
            ref = started.value;
            runtimeStarted = true;
            return {};
        }

        /// The host's Client; with @p waitUsable, once a node is not Down. False (and a reason) when refused.
        bool makeClient(bool waitUsable = true)
        {
            auto outcome = ref.client(CONSUMER_NAME, {});
            if (!outcome.ok())
            {
                startError = std::string {indexer_client::toString(outcome.cause)} + ": " + outcome.reason;
                return false;
            }
            client = outcome.value;
            return !waitUsable || waitUntil([this] { return client->health().anyUsable(); });
        }

        /// The adapter under test, over the host's Client.
        std::shared_ptr<content_manager::IContentIndexer> adapter(content_manager::ContentIndexerOptions options = {})
        {
            std::shared_ptr<indexer_client::IClient> base = client;
            return content_manager::makeContentIndexer(std::move(base), options);
        }

        /// `POST /_search` requests received, in arrival order (the PIT searches).
        std::vector<indexer_client::testing::RecordedRequest> searchRequests() const
        {
            std::vector<indexer_client::testing::RecordedRequest> result;
            for (auto& request : fake->requests())
            {
                if (request.method == "POST" && request.path == "/_search")
                {
                    result.push_back(std::move(request));
                }
            }
            return result;
        }

        /// The PIT creations received (`POST /<indices>/_search/point_in_time`).
        std::vector<indexer_client::testing::RecordedRequest> createRequests() const
        {
            std::vector<indexer_client::testing::RecordedRequest> result;
            for (auto& request : fake->requests())
            {
                const auto& path = request.path;
                static constexpr std::string_view SUFFIX {"/_search/point_in_time"};
                if (request.method == "POST" && path.size() > SUFFIX.size() &&
                    path.compare(path.size() - SUFFIX.size(), SUFFIX.size(), SUFFIX) == 0)
                {
                    result.push_back(std::move(request));
                }
            }
            return result;
        }

        /// Requests that are not health probes: what the library sent for the consumer.
        std::size_t nonProbeRequests() const
        {
            std::size_t count {0};
            for (const auto& request : fake->requests())
            {
                count += indexer_client::testing::isProbe(request) ? 0 : 1;
            }
            return count;
        }

        /// The parsed body of @p request.
        static nlohmann::json bodyOf(const indexer_client::testing::RecordedRequest& request)
        {
            return nlohmann::json::parse(request.body, nullptr, false);
        }

        /// Waits (bounded) for @p count DELETEs to reach the fake: the library deletes a PIT in the background.
        bool waitDeletes(std::size_t count, std::chrono::milliseconds timeout = 2000ms) const
        {
            return waitUntil([&] { return pits->requests(indexer_client::testing::PitCall::Delete) >= count; },
                             timeout);
        }

        std::size_t searches() const
        {
            return pits->requests(indexer_client::testing::PitCall::Search);
        }

        /// Closes the Client, then the runtime. Idempotent.
        void shutdown()
        {
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
        std::shared_ptr<indexer_client::testing::PitResponder> pits;
        indexer_client::RuntimeRef ref;
        bool runtimeStarted {false};
        std::string startError;
        std::shared_ptr<indexer_client::Client> client;
    };
} // namespace cmtest

#endif // _REAL_INDEXER_FIXTURE_HPP
