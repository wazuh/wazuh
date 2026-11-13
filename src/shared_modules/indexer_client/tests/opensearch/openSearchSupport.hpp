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

#ifndef _INDEXER_CLIENT_TESTS_OPENSEARCH_SUPPORT_HPP
#define _INDEXER_CLIENT_TESTS_OPENSEARCH_SUPPORT_HPP

// Suite against a real OpenSearch. Gate: without INDEXER_CLIENT_OPENSEARCH_URL every case is
// skipped, except under GITHUB_ACTIONS, where a missing URL fails (the workflow must never go green by skipping).
// With the URL, requireCluster() polls /_cluster/health and fails when the cluster does not answer in the budget (once
// per run: later cases fail at once). The global setup DELETES every `ic-ostest-*` index left by an earlier run; never
// point two concurrent runs at the same cluster.
// The library is driven through its public API (RuntimeOwner, Client, writers, queries, PITs); only what the library
// cannot express (an `"upsert":{}` line written by hand, response sizes with and without gzip, out-of-band PIT
// deletes, reading `_source` back) goes through cpp-httplib. Measures are printed with the fixed prefix IC-MEASURE.
// Two cases need more than the node of URL_ENV (each gated like the URL, skipped locally and failed
// under GITHUB_ACTIONS when its variable is missing): SMALL_URL_ENV, a second node started with a low static
// `http.max_content_length` (the 413 split), and CONTAINER_ENV, the docker container of the URL_ENV node, which the
// outage case stops and starts again (and always leaves started).

#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "indexer_client/runtime.hpp"
#include "testTimeScale.hpp"

namespace indexer_client::opensearch
{
    constexpr const char* URL_ENV = "INDEXER_CLIENT_OPENSEARCH_URL";
    constexpr const char* INDEX_PREFIX = "ic-ostest-";
    constexpr const char* MEASURE = "IC-MEASURE ";
    /// A node whose `http.max_content_length` is low (CI and README: 16kb).
    constexpr const char* SMALL_URL_ENV = "INDEXER_CLIENT_OPENSEARCH_SMALL_URL";
    /// The docker container (name or id) of the URL_ENV node; never the e2e `wazuh-indexer`.
    constexpr const char* CONTAINER_ENV = "INDEXER_CLIENT_OPENSEARCH_CONTAINER";

    /// The gate and the probe. `url` null or empty ⇒ GTEST_SKIP, or FAIL when GITHUB_ACTIONS is set (`env` names the
    /// variable in the message); otherwise polls `<url>/_cluster/health` until it answers 200 with a status other than
    /// red, and FAILs when `budget` runs out.
    void requireCluster(const char* url, std::chrono::milliseconds budget, const char* env = URL_ENV);

    /// Polls `<url>/_cluster/health` until it answers 200 with a status other than red or `budget` runs out: empty on
    /// success, else the last answer. Unlike requireCluster it remembers nothing (the outage case waits for its node
    /// to come back).
    std::string waitForCluster(const std::string& url, std::chrono::milliseconds budget);

    /// The gate of a variable that is not a URL: unset or empty ⇒ GTEST_SKIP, or FAIL when GITHUB_ACTIONS is set.
    void requireVariable(const char* env);

    /// The URL of the environment, or empty.
    std::string clusterUrl();

    /// The value of `env`, or empty.
    std::string variable(const char* env);

    struct RawResponse final
    {
        int status {0}; ///< 0 when the request got no HTTP answer.
        std::string body;
        std::string contentEncoding;
        std::string error; ///< cpp-httplib's error when status is 0.
    };

    /// One request with cpp-httplib (no decompression: the body is the bytes on the wire). `headers` are added as is.
    RawResponse raw(const std::string& method,
                    const std::string& path,
                    const std::string& body = {},
                    const std::string& contentType = "application/json",
                    const std::map<std::string, std::string>& headers = {});

    /// raw() against another node (`url`).
    RawResponse rawAt(const std::string& url,
                      const std::string& method,
                      const std::string& path,
                      const std::string& body = {},
                      const std::string& contentType = "application/json",
                      const std::map<std::string, std::string>& headers = {});

    /// Documents of `index` on `url` after a refresh, or -1 when the node does not answer.
    std::int64_t countDocuments(const std::string& url, const std::string& index);

    /// `_source` of a document (realtime GET), or nullopt when it does not exist; `version` receives `_version`.
    std::optional<nlohmann::json> getSource(const std::string& index, const std::string& id, std::int64_t* version);

    /// Ids of every PIT the cluster holds (GET /_search/point_in_time/_all).
    std::vector<std::string> listPits();

    /// Index of the current case: ic-ostest-<case in lowercase>-<pid>.
    std::string caseIndex();

    /// Deletes every index matching `pattern` on `url` (the suite's global environment and each case's teardown use
    /// it).
    void deleteIndices(const std::string& pattern, const std::string& url = clusterUrl());

    /// Configuration of the runtime: the URL as the only host, test credentials and the given internal options
    /// (names after the `analysisd.indexer_client_` prefix).
    class OpenSearchSource final : public IConfigSource
    {
    public:
        OpenSearchSource(std::string url, std::map<std::string, std::string> options);
        std::optional<std::string> raw(std::string_view key) const override;
        std::vector<std::string> keysWithPrefix(std::string_view prefix) const override;
        std::string indexerSectionJson() const override;
        Credentials credentials() const override;

    private:
        std::string m_url;
        std::map<std::string, std::string, std::less<>> m_options;
    };

    /// A bucket with the thresholds the cases want: small bulks that leave quickly.
    BucketSpec quickBucket(const std::string& name);

    /// Fixture of every case that needs the library: gate + probe, a runtime per case (the owner thread is the test's)
    /// and the case's index, deleted before and after.
    class OpenSearchTest : public ::testing::Test
    {
    protected:
        void SetUp() override;
        void TearDown() override;

        /// Internal options of the runtime of this case; override to change them.
        virtual std::map<std::string, std::string> runtimeOptions() const;

        /// The variable holding the URL of the node this case writes to (its gate, its runtime's only host and its
        /// index); override to use another node.
        virtual const char* urlVariable() const;

        std::shared_ptr<Client> makeClient(const std::string& consumer, std::vector<BucketSpec> buckets);
        /// Waits until a node of `client` is Available (the first probe round).
        void waitAvailable(const Client& client);

        std::string m_url;
        std::string m_index;
        RuntimeRef m_ref;
        std::vector<std::shared_ptr<Client>> m_clients;
        bool m_started {false};
    };

    /// Submits `op` and waits for its result (the wait itself must succeed).
    OpResult submitAndWait(IWriter& writer, Op op);

    Deadline after(std::chrono::milliseconds bound);
} // namespace indexer_client::opensearch

#endif // _INDEXER_CLIENT_TESTS_OPENSEARCH_SUPPORT_HPP
