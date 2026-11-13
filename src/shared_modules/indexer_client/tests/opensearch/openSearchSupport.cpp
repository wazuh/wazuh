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

#include "openSearchSupport.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string_view>
#include <thread>

#include <unistd.h>

#include "httplib.h"

using namespace std::chrono_literals;

namespace indexer_client::opensearch
{
    namespace
    {
        httplib::Client makeHttp(const std::string& url)
        {
            httplib::Client http(url);
            http.set_connection_timeout(2s);
            http.set_read_timeout(120s);
            http.set_write_timeout(120s);
            http.set_decompress(false);
            http.set_keep_alive(false);
            return http;
        }

        /// One probe of /_cluster/health: empty on success, else why it failed.
        std::string probeOnce(const std::string& url)
        {
            auto http = makeHttp(url);
            http.set_connection_timeout(1s);
            http.set_read_timeout(5s);
            const auto result = http.Get("/_cluster/health");
            if (!result)
            {
                return "no answer: " + httplib::to_string(result.error());
            }
            if (result->status != 200)
            {
                return "HTTP " + std::to_string(result->status) + ": " + result->body.substr(0, 256);
            }
            const auto health = nlohmann::json::parse(result->body, nullptr, false);
            if (health.is_discarded() || !health.contains("status"))
            {
                return "unparsable health: " + result->body.substr(0, 256);
            }
            if (health["status"] == "red")
            {
                return "cluster red";
            }
            return {};
        }

        /// URLs that already failed their wait in this process, with the last probe's answer.
        std::map<std::string, std::string> g_unreachable;

        /// Global environment: wipes the suite's indices left by an earlier run before the first case.
        class SuiteEnvironment final : public ::testing::Environment
        {
        public:
            void SetUp() override
            {
                const auto url = clusterUrl();
                if (url.empty())
                {
                    return;
                }
                // The wait is the cases' budget: a cluster that did not answer here fails every case at once, so
                // the run fails within one budget instead of one per case.
                if (const auto reason = waitForCluster(url, testing::scaled(120s)); !reason.empty())
                {
                    g_unreachable[url] = reason;
                    return;
                }
                deleteIndices(std::string(INDEX_PREFIX) + "*");
                // The node of the 413 case (a small http.max_content_length), when there is one and it answers.
                if (const auto small = variable(SMALL_URL_ENV); !small.empty())
                {
                    if (const auto reason = waitForCluster(small, testing::scaled(120s)); !reason.empty())
                    {
                        g_unreachable[small] = reason;
                        return;
                    }
                    deleteIndices(std::string(INDEX_PREFIX) + "*", small);
                }
            }
        };

        [[maybe_unused]] const auto* const ENVIRONMENT = ::testing::AddGlobalTestEnvironment(new SuiteEnvironment);
    } // namespace

    std::string waitForCluster(const std::string& url, std::chrono::milliseconds budget)
    {
        const auto end = std::chrono::steady_clock::now() + budget;
        while (true)
        {
            auto last = probeOnce(url);
            const auto now = std::chrono::steady_clock::now();
            if (last.empty() || now >= end)
            {
                return last;
            }
            std::this_thread::sleep_for(std::min<std::chrono::steady_clock::duration>(500ms, end - now));
        }
    }

    std::string clusterUrl()
    {
        return variable(URL_ENV);
    }

    std::string variable(const char* env)
    {
        const char* value = std::getenv(env);
        return value == nullptr ? std::string() : std::string(value);
    }

    void requireVariable(const char* env)
    {
        if (variable(env).empty())
        {
            if (std::getenv("GITHUB_ACTIONS") != nullptr)
            {
                FAIL() << env << " is not set under GITHUB_ACTIONS: the OpenSearch suite must not be skipped in CI";
            }
            GTEST_SKIP() << env << " is not set";
        }
    }

    void requireCluster(const char* url, std::chrono::milliseconds budget, const char* env)
    {
        if (url == nullptr || *url == '\0')
        {
            requireVariable(env);
            return;
        }
        if (const auto known = g_unreachable.find(url); known != g_unreachable.end())
        {
            FAIL() << "OpenSearch at " << url
                   << " did not answer /_cluster/health earlier in this run: " << known->second;
        }
        if (const auto last = waitForCluster(url, budget); !last.empty())
        {
            g_unreachable[url] = last;
            FAIL() << "OpenSearch at " << url << " did not answer /_cluster/health within " << budget.count()
                   << " ms: " << last;
        }
    }

    RawResponse raw(const std::string& method,
                    const std::string& path,
                    const std::string& body,
                    const std::string& contentType,
                    const std::map<std::string, std::string>& headers)
    {
        return rawAt(clusterUrl(), method, path, body, contentType, headers);
    }

    RawResponse rawAt(const std::string& url,
                      const std::string& method,
                      const std::string& path,
                      const std::string& body,
                      const std::string& contentType,
                      const std::map<std::string, std::string>& headers)
    {
        auto http = makeHttp(url);
        httplib::Headers hdrs;
        for (const auto& [name, value] : headers)
        {
            hdrs.emplace(name, value);
        }
        httplib::Result result;
        if (method == "GET")
        {
            result = http.Get(path, hdrs);
        }
        else if (method == "POST")
        {
            result = http.Post(path, hdrs, body, contentType);
        }
        else if (method == "PUT")
        {
            result = http.Put(path, hdrs, body, contentType);
        }
        else if (method == "DELETE")
        {
            result = body.empty() ? http.Delete(path, hdrs) : http.Delete(path, hdrs, body, contentType);
        }
        RawResponse response;
        if (!result)
        {
            response.error = httplib::to_string(result.error());
            return response;
        }
        response.status = result->status;
        response.body = result->body;
        response.contentEncoding = result->get_header_value("Content-Encoding");
        return response;
    }

    std::optional<nlohmann::json> getSource(const std::string& index, const std::string& id, std::int64_t* version)
    {
        const auto response = raw("GET", "/" + index + "/_doc/" + id);
        if (response.status != 200)
        {
            return std::nullopt;
        }
        const auto doc = nlohmann::json::parse(response.body);
        if (version != nullptr)
        {
            *version = doc.at("_version").get<std::int64_t>();
        }
        return doc.at("_source");
    }

    std::vector<std::string> listPits()
    {
        std::vector<std::string> ids;
        const auto response = raw("GET", "/_search/point_in_time/_all");
        if (response.status != 200)
        {
            return ids;
        }
        const auto body = nlohmann::json::parse(response.body, nullptr, false);
        if (body.is_discarded() || !body.contains("pits"))
        {
            return ids;
        }
        for (const auto& pit : body["pits"])
        {
            ids.push_back(pit.at("pit_id").get<std::string>());
        }
        return ids;
    }

    std::string caseIndex()
    {
        std::string name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
        std::transform(
            name.begin(), name.end(), name.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return std::string(INDEX_PREFIX) + name + "-" + std::to_string(::getpid());
    }

    std::int64_t countDocuments(const std::string& url, const std::string& index)
    {
        if (rawAt(url, "POST", "/" + index + "/_refresh").status != 200)
        {
            return -1;
        }
        const auto counted = rawAt(url, "GET", "/" + index + "/_count");
        const auto body = nlohmann::json::parse(counted.body, nullptr, false);
        if (counted.status != 200 || !body.is_object() || !body.contains("count"))
        {
            return -1;
        }
        return body["count"].get<std::int64_t>();
    }

    void deleteIndices(const std::string& pattern, const std::string& url)
    {
        // By name: a wildcard DELETE depends on action.destructive_requires_name.
        const auto listed = rawAt(url, "GET", "/_cat/indices/" + pattern + "?h=index&format=json&expand_wildcards=all");
        if (listed.status != 200)
        {
            return;
        }
        const auto indices = nlohmann::json::parse(listed.body, nullptr, false);
        if (!indices.is_array())
        {
            return;
        }
        for (const auto& entry : indices)
        {
            rawAt(url, "DELETE", "/" + entry.at("index").get<std::string>());
        }
    }

    OpenSearchSource::OpenSearchSource(std::string url, std::map<std::string, std::string> options)
        : m_url(std::move(url))
    {
        for (auto& [name, value] : options)
        {
            m_options.emplace(RuntimeConfig::prefixFor(ProcessId::Standalone) + name, std::move(value));
        }
    }

    std::optional<std::string> OpenSearchSource::raw(std::string_view key) const
    {
        const auto it = m_options.find(key);
        return it == m_options.end() ? std::nullopt : std::optional<std::string>(it->second);
    }

    std::vector<std::string> OpenSearchSource::keysWithPrefix(std::string_view prefix) const
    {
        std::vector<std::string> keys;
        for (const auto& [key, value] : m_options)
        {
            if (key.compare(0, prefix.size(), prefix) == 0)
            {
                keys.push_back(key);
            }
        }
        return keys;
    }

    std::string OpenSearchSource::indexerSectionJson() const
    {
        return nlohmann::json {{"hosts", nlohmann::json::array({m_url})}}.dump();
    }

    Credentials OpenSearchSource::credentials() const
    {
        // Security is off in the suite's cluster: the Authorization header is ignored, but the library requires both.
        return {"admin", "admin"};
    }

    BucketSpec quickBucket(const std::string& name)
    {
        BucketSpec spec;
        spec.name = name;
        spec.bulk.maxAge = Duration {20};
        spec.retry.base = Duration {50};
        spec.retry.cap = Duration {500};
        return spec;
    }

    void OpenSearchTest::SetUp()
    {
        // The URL_ENV node always gates (the suite's own), then the case's node when it is another one.
        requireCluster(std::getenv(URL_ENV), testing::scaled(120s));
        if (HasFatalFailure() || IsSkipped())
        {
            return;
        }
        const char* env = urlVariable();
        if (std::string_view(env) != URL_ENV)
        {
            requireCluster(std::getenv(env), testing::scaled(120s), env);
            if (HasFatalFailure() || IsSkipped())
            {
                return;
            }
        }
        m_url = variable(env);
        m_index = caseIndex();
        deleteIndices(m_index, m_url);
        auto started = RuntimeOwner::start(ProcessId::Standalone, OpenSearchSource(m_url, runtimeOptions()));
        ASSERT_TRUE(started.ok()) << started.reason;
        m_started = true;
        m_ref = started.value;
    }

    void OpenSearchTest::TearDown()
    {
        for (auto& client : m_clients)
        {
            client->requestClose();
        }
        for (auto& client : m_clients)
        {
            client->awaitClosed(after(testing::scaled(30s)));
        }
        m_clients.clear();
        if (m_started)
        {
            RuntimeOwner::beginShutdown(std::chrono::steady_clock::now() + testing::scaled(10s));
            RuntimeOwner::shutdown();
            m_started = false;
        }
        if (!m_index.empty())
        {
            deleteIndices(m_index, m_url);
        }
    }

    const char* OpenSearchTest::urlVariable() const
    {
        return URL_ENV;
    }

    std::map<std::string, std::string> OpenSearchTest::runtimeOptions() const
    {
        return {{"network_threads", "1"}, {"cpu_threads", "2"}, {"probe_interval_ms", "1000"}};
    }

    std::shared_ptr<Client> OpenSearchTest::makeClient(const std::string& consumer, std::vector<BucketSpec> buckets)
    {
        auto client = m_ref.client(consumer, std::move(buckets));
        EXPECT_TRUE(client.ok()) << client.reason;
        if (!client.ok())
        {
            return nullptr;
        }
        m_clients.push_back(client.value);
        waitAvailable(*client.value);
        return client.value;
    }

    void OpenSearchTest::waitAvailable(const Client& client)
    {
        const auto end = after(testing::scaled(30s));
        while (!client.health().anyAvailable() && std::chrono::steady_clock::now() < end)
        {
            std::this_thread::sleep_for(50ms);
        }
        ASSERT_TRUE(client.health().anyAvailable()) << "no node Available after the first probe rounds";
    }

    OpResult submitAndWait(IWriter& writer, Op op)
    {
        auto submit = writer.submit(std::move(op));
        EXPECT_TRUE(submit.accepted) << toString(submit.cause) << ": " << submit.reason;
        if (!submit.accepted)
        {
            OpResult refused;
            refused.status = Status::Failed;
            refused.cause = submit.cause;
            return refused;
        }
        const auto result = submit.ticket.wait(after(testing::scaled(60s)));
        EXPECT_TRUE(result.ok()) << toString(result.cause) << ": " << result.reason;
        return result.value;
    }

    Deadline after(std::chrono::milliseconds bound)
    {
        return std::chrono::steady_clock::now() + bound;
    }
} // namespace indexer_client::opensearch
