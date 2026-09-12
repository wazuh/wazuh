/*
 * Wazuh remoted module - GET /cacerts endpoint unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Exercises the handler's own decision table -- file present/missing/garbage, the coherence
 * verdict it is handed, what it ignores in the request -- and that every answer lands in both
 * metric families (remoted.cacerts.* = why, remoted.http.cacerts.responses.* = what). The
 * transport's evaluation behind `status` is faked here; cacertsE2E_test.cpp drives the real one
 * over TLS.
 */

#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unistd.h>

#include <gtest/gtest.h>

#include "common/requestOutcomeMetrics.hpp"
#include "endpoints/cacertsEndpoint.hpp"
#include "endpoints/cacertsMetrics.hpp"

#include <wazuh_metrics/manager.hpp>

using namespace remoted::endpoints::cacerts;
using remoted::http::CaCertificateSnapshot;
using remoted::http::HttpRequest;
using remoted::http::HttpResponse;
using remoted::http::IHttpResponder;
using remoted::http::Method;
using namespace std::chrono_literals;

namespace
{
    class CapturingResponder : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            std::lock_guard<std::mutex> lock(m_mu);
            if (m_done)
            {
                return;
            }
            m_response = std::move(response);
            m_done = true;
            m_cv.notify_all();
        }

        HttpResponse wait(std::chrono::milliseconds timeout = 2s)
        {
            std::unique_lock<std::mutex> lock(m_mu);
            EXPECT_TRUE(m_cv.wait_for(lock, timeout, [&] { return m_done; })) << "responder never called";
            return m_response;
        }

    private:
        std::mutex m_mu;
        std::condition_variable m_cv;
        bool m_done {false};
        HttpResponse m_response;
    };

    // Not a real certificate on purpose: the handler serves the FILE and only looks for the
    // CERTIFICATE marker -- whether the bytes parse is the transport's evaluation's business.
    constexpr auto kPem = "-----BEGIN CERTIFICATE-----\nMIIBfakeCAbytes==\n-----END CERTIFICATE-----\n";

    std::string scratchPath(const char* name)
    {
        return "/tmp/cacertsEndpointTest_" + std::string {name} + "_" + std::to_string(::getpid()) + ".pem";
    }

    class ScratchFile
    {
    public:
        ScratchFile(const char* name, const std::string& contents)
            : m_path {scratchPath(name)}
        {
            std::ofstream out {m_path, std::ios::binary};
            out << contents;
        }
        ~ScratchFile()
        {
            std::remove(m_path.c_str());
        }
        const std::string& path() const
        {
            return m_path;
        }

    private:
        std::string m_path;
    };

    // Case-insensitive lookup over a RESPONSE's header list (a vector, unlike the request's map that
    // http_server/headerUtils.hpp serves). Empty when absent.
    std::string responseHeader(const HttpResponse& response, std::string_view name)
    {
        for (const auto& [key, value] : response.headers)
        {
            if (key.size() == name.size() &&
                std::equal(key.begin(),
                           key.end(),
                           name.begin(),
                           [](unsigned char a, unsigned char b) { return std::tolower(a) == std::tolower(b); }))
            {
                return value;
            }
        }
        return {};
    }

    /// What the transport hands the handler: certificates already parsed and re-serialised, plus
    /// the verdict about them. The file-level behaviour (parsing, caching, invalidation) belongs to
    /// CaCertificateSource and is tested in caCertificateSource_test.cpp.
    CaCertificateSnapshot snapshotOf(std::optional<bool> matchesLeaf, std::string pem = std::string {kPem})
    {
        CaCertificateSnapshot snapshot;
        snapshot.certificates = pem.empty() ? 0U : 1U;
        snapshot.pem = std::move(pem);
        snapshot.matchesLeaf = matchesLeaf;
        snapshot.subjects = "/CN=Test CA";
        return snapshot;
    }

    HttpRequest getRequest()
    {
        HttpRequest request;
        request.method = Method::Get;
        request.target = "/cacerts";
        return request;
    }

    // One real registry per test so the counters can be read back through the same structs the
    // handler counts on (statsEndpoint_test.cpp's pattern).
    struct Fixture
    {
        wazuh::metrics::Manager manager;
        CacertsMetrics metrics {makeCacertsMetrics(manager)};
        remoted::metrics::EndpointHttpMetrics http {
            remoted::metrics::makeEndpointHttpMetrics(manager, "cacerts", /*withLatency=*/false, "GET")};

        HttpResponse run(std::function<CaCertificateSnapshot()> snapshot, const HttpRequest& request = getRequest())
        {
            auto handler = makeHandler(std::move(snapshot), metrics, &http);
            auto responder = std::make_shared<CapturingResponder>();
            handler(std::make_shared<const HttpRequest>(request), responder);
            return responder->wait();
        }

        HttpResponse run(CaCertificateSnapshot snapshot, const HttpRequest& request = getRequest())
        {
            return run([snapshot = std::move(snapshot)] { return snapshot; }, request);
        }
    };
} // namespace

TEST(CacertsEndpoint, ServesTheSnapshotPemWithPemContentType)
{
    Fixture f;

    const auto response = f.run(snapshotOf(true));

    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(responseHeader(response, "content-type"), PEM_CONTENT_TYPE);
    EXPECT_EQ(response.body, kPem); // what the source serialised, not a file the handler read
    EXPECT_EQ(f.metrics.served->get(), 1U);
    EXPECT_EQ(f.metrics.notFound->get(), 0U);
    EXPECT_EQ(f.metrics.caMismatch->get(), 0U);
    EXPECT_EQ(f.http.responses.c2xx->get(), 1U);
    EXPECT_EQ(f.http.responses.other->get(), 0U);
    EXPECT_EQ(f.http.latency, nullptr); // no histogram for a snapshot read
}

TEST(CacertsEndpoint, EmptySnapshotAnswers404NotFound)
{
    Fixture f;

    // Missing, unreadable, too large, no certificate or unparsable: the source collapses them all
    // into "nothing to serve", and the handler answers the same 404 to every one of them.
    const auto response = f.run(CaCertificateSnapshot {});

    EXPECT_EQ(response.status, 404);
    EXPECT_EQ(response.body, R"({"error":"not_found"})"); // same body as the transport's unknown-route 404
    EXPECT_EQ(responseHeader(response, "content-type"), "application/json");
    EXPECT_EQ(f.metrics.notFound->get(), 1U);
    EXPECT_EQ(f.metrics.served->get(), 0U);
    EXPECT_EQ(f.http.responses.other->get(), 1U); // 404 is outside the closed status set
    EXPECT_EQ(f.http.responses.c2xx->get(), 0U);
}

TEST(CacertsEndpoint, SnapshotWithCountButNoPemAnswers404)
{
    Fixture f;

    // Defence in depth: a snapshot that counts certificates but carries no bytes (a serialisation
    // that failed) must not answer 200 with an empty body.
    CaCertificateSnapshot broken;
    broken.certificates = 2;
    broken.matchesLeaf = true;

    EXPECT_EQ(f.run(broken).status, 404);
    EXPECT_EQ(f.metrics.notFound->get(), 1U);
}

TEST(CacertsEndpoint, CaMismatchAnswers503)
{
    Fixture f;

    // Certificates are there; they do not sign the served leaf: refuse, don't serve.
    const auto response = f.run(snapshotOf(false));

    EXPECT_EQ(response.status, 503);
    EXPECT_EQ(response.body, R"({"error":"ca_mismatch"})");
    EXPECT_EQ(responseHeader(response, "content-type"), "application/json");
    EXPECT_EQ(f.metrics.caMismatch->get(), 1U);
    EXPECT_EQ(f.metrics.served->get(), 0U);
    EXPECT_EQ(f.http.responses.c503->get(), 1U);
    EXPECT_EQ(f.http.responses.c2xx->get(), 0U);
}

TEST(CacertsEndpoint, UnverifiedSnapshotStillServes)
{
    Fixture f;

    // nullopt: there are certificates but no leaf to check them against yet. Unknown is not
    // mismatch -- refusing there would turn a listener that has not evaluated into an outage.
    EXPECT_EQ(f.run(snapshotOf(std::nullopt)).status, 200);
    EXPECT_EQ(f.metrics.served->get(), 1U);
    EXPECT_EQ(f.http.responses.c2xx->get(), 1U);
}

TEST(CacertsEndpoint, NoSnapshotFunctionAnswers404)
{
    Fixture f;

    // The facade's weak_ptr no longer locks (the server is gone): there is no CA to publish, and
    // a 404 says so. Before this endpoint took its bytes from the transport it would have read
    // the file itself and answered 200 with an unknown verdict.
    EXPECT_EQ(f.run(std::function<CaCertificateSnapshot()> {}).status, 404);
    EXPECT_EQ(f.metrics.notFound->get(), 1U);
}

TEST(CacertsEndpoint, IgnoresBodyAndAuthorizationHeader)
{
    Fixture f;

    // A trust-bootstrap route has nothing to verify a credential against, and takes no input:
    // whatever the caller sends besides the target is irrelevant to the answer.
    auto request = getRequest();
    request.body = R"({"unexpected":"body"})";
    request.headers.emplace("Authorization", "Bearer x");
    request.headers.emplace("protocol-version", "1");
    request.headers.emplace("Content-Type", "application/json");

    const auto response = f.run(snapshotOf(true), request);
    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(response.body, kPem);
    EXPECT_EQ(f.metrics.served->get(), 1U);
}

TEST(CacertsEndpoint, NullMetricsCountNothing)
{
    // The null-object contract every metric struct in the module honours: a default-constructed
    // set and a null http family must not crash and must not count.
    auto handler = makeHandler([] { return snapshotOf(true); }, CacertsMetrics {}, nullptr);
    auto responder = std::make_shared<CapturingResponder>();
    handler(std::make_shared<const HttpRequest>(getRequest()), responder);
    EXPECT_EQ(responder->wait().status, 200);

    auto missing = makeHandler([] { return CaCertificateSnapshot {}; }, CacertsMetrics {}, nullptr);
    auto responder2 = std::make_shared<CapturingResponder>();
    missing(std::make_shared<const HttpRequest>(getRequest()), responder2);
    EXPECT_EQ(responder2->wait().status, 404);
}
