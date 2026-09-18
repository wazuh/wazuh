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
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

#include <gtest/gtest.h>

#include "ca_bundle/ca_bundle.hpp"
#include "common/requestOutcomeMetrics.hpp"
#include "endpoints/cacertsEndpoint.hpp"
#include "endpoints/cacertsMetrics.hpp"
#include "http_server/caCertificateSource.hpp"
#include "http_server/caPublicationRecord.hpp"
#include "http_server/caRecordEvents.hpp"
#include "http_server/fileRead.hpp"
#include "testTlsServer.hpp"

#include <wazuh_metrics/manager.hpp>

using namespace remoted::endpoints::cacerts;
using remoted::http::CaCertificateSnapshot;
using remoted::http::HttpRequest;
using remoted::http::HttpResponse;
using remoted::http::IHttpResponder;
using remoted::http::Method;
using remoted::http::ReadFailure;
using remoted::http::ReadStatus;
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

    // ---- Helpers for the deliverCaRecordEvents() tests below (issue #39319, C21b) ----

    /// Records the ORDER "delivered"/"responded" land in, for
    /// DeliversRecordEventsBeforeRespondingOnAllThreePaths: unlike CapturingResponder, its send()
    /// itself appends to the shared trace instead of just capturing the response.
    class OrderRecordingResponder : public IHttpResponder
    {
    public:
        explicit OrderRecordingResponder(std::vector<std::string>& order)
            : m_order {order}
        {
        }

        void send(HttpResponse response) override
        {
            std::lock_guard<std::mutex> lock {m_mu};
            if (m_done)
            {
                return;
            }
            m_order.push_back("responded");
            m_response = std::move(response);
            m_done = true;
            m_cv.notify_all();
        }

        HttpResponse wait(std::chrono::milliseconds timeout = 2s)
        {
            std::unique_lock<std::mutex> lock {m_mu};
            EXPECT_TRUE(m_cv.wait_for(lock, timeout, [&] { return m_done; })) << "responder never called";
            return m_response;
        }

    private:
        std::vector<std::string>& m_order;
        std::mutex m_mu;
        std::condition_variable m_cv;
        bool m_done {false};
        HttpResponse m_response;
    };

    std::string readAll(const std::string& path)
    {
        std::ifstream in {path, std::ios::binary};
        return {std::istreambuf_iterator<char> {in}, std::istreambuf_iterator<char> {}};
    }

    void write(const std::string& path, const std::string& contents)
    {
        std::ofstream out {path, std::ios::binary | std::ios::trunc};
        out << contents;
    }

    /// Throwaway directory for a publication record (same mold as downloadEndpoint_test.cpp's
    /// TempDir: mkdtemp for per-instance/per-process uniqueness, std::filesystem for teardown,
    /// since CaPublicationRecord writes names this file does not predict).
    class TempDir
    {
    public:
        TempDir()
        {
            std::string tmpl = "/tmp/wazuh-cacerts-endpoint-test-XXXXXX";
            std::vector<char> buffer(tmpl.begin(), tmpl.end());
            buffer.push_back('\0');

            const char* created = ::mkdtemp(buffer.data());
            if (created == nullptr)
            {
                throw std::runtime_error("mkdtemp failed for the cacerts endpoint test's scratch directory");
            }
            m_path = created;
        }

        ~TempDir()
        {
            std::error_code ignored;
            std::filesystem::remove_all(m_path, ignored);
        }

        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;

        const std::string& path() const
        {
            return m_path;
        }

    private:
        std::string m_path;
    };

    /// The document `wazuh-manager-certs` would leave behind: the block, then the certificates it
    /// describes. Duplicated from caCertificateSource_test.cpp's sealedDocument() -- this file
    /// tests the ENDPOINT's use of the record, not the source, and pulls in ca_bundle for nothing
    /// else.
    std::string sealBundle(const std::vector<remoted::http::X509Ptr>& certificates,
                           std::int64_t publication,
                           const std::string& contentSha256Override = {})
    {
        ca_bundle::PublicationBlock block;
        block.publication = publication;
        block.contentSha256 =
            contentSha256Override.empty() ? ca_bundle::contentSha256(certificates) : contentSha256Override;
        block.updated = "2026-09-18T00:00:00Z";
        block.writtenBy = "cacertsEndpoint_test";
        return ca_bundle::renderBlock(block) + remoted::http::serializeCertificates(certificates);
    }
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

TEST(CacertsEndpoint, ServesThePreviousSnapshotOnReadFailure)
{
    Fixture f;

    // The source kept the last good bundle through a read that failed (issue #39318): the handler
    // must still answer from it -- 200, exactly as a snapshot with no failure would -- and not let
    // a transient read error turn into a spurious 404 for every agent bootstrapping trust.
    auto snapshot = snapshotOf(true);
    snapshot.lastReadFailure = ReadFailure {ReadStatus::ReadError, EIO, 3};

    const auto response = f.run(snapshot);

    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(response.body, kPem);
    EXPECT_EQ(f.metrics.served->get(), 1U);
    EXPECT_EQ(f.http.responses.c2xx->get(), 1U);
    EXPECT_EQ(f.metrics.notFound->get(), 0U);
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

TEST(CacertsEndpoint, NotFoundOnReadFailureStaysNotFound)
{
    Fixture f;

    // Nothing was ever served from this file and it cannot be read now: still the plain 404, not a
    // new outcome -- the failure only changes what gets logged, not the status code or metric.
    CaCertificateSnapshot snapshot;
    snapshot.lastReadFailure = ReadFailure {ReadStatus::CannotOpen, ENOENT, 1};

    const auto response = f.run(snapshot);

    EXPECT_EQ(response.status, 404);
    EXPECT_EQ(response.body, R"({"error":"not_found"})");
    EXPECT_EQ(f.metrics.notFound->get(), 1U);
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

TEST(CacertsEndpoint, ChainValidDoesNotDecideTheAnswer)
{
    // The chain verdict is information for the logs (issue #39318), never the 503 decision: a CA
    // that signs the leaf but whose chain does not validate must still serve, and a CA that does
    // not sign the leaf must still be refused even when the chain happens to validate through it.
    {
        Fixture f;
        auto matches = snapshotOf(true);
        matches.chainValid = false;
        matches.chainError = "certificate has expired";

        const auto response = f.run(matches);
        EXPECT_EQ(response.status, 200);
        EXPECT_EQ(f.metrics.served->get(), 1U);
    }
    {
        Fixture f;
        auto mismatches = snapshotOf(false);
        mismatches.chainValid = true;

        const auto response = f.run(mismatches);
        EXPECT_EQ(response.status, 503);
        EXPECT_EQ(f.metrics.caMismatch->get(), 1U);
    }
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

// ---------------------------------------------------------------------------
// Wazuh-CA-Generation (issue #39319, RF-4): the header every 200 carries, so an agent that
// refreshes over an already-verified channel learns which generation the bundle it just received
// is published under without a second round trip. 0 is deliberately the SAME wire value whether
// nobody ever stamped the bundle or a guard refused it -- an agent cannot and need not tell those
// apart. 404 and 503 carry no such header at all: there is no bundle being handed out to attach a
// generation to.
// ---------------------------------------------------------------------------

TEST(CacertsEndpoint, PublishedBundleAddsCaGenerationHeader)
{
    Fixture f;
    auto snapshot = snapshotOf(true);
    snapshot.publication = 1758000000;

    const auto response = f.run(snapshot);

    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(responseHeader(response, CA_GENERATION_HEADER), "1758000000");
}

TEST(CacertsEndpoint, UnpublishedBundleAddsZeroCaGenerationHeader)
{
    Fixture f;
    // snapshotOf() leaves publication at CaCertificateSnapshot's own default (0): a bundle nobody
    // ever stamped and one a guard refused both look like this on the wire (design §2.4).
    const auto response = f.run(snapshotOf(true));

    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(responseHeader(response, CA_GENERATION_HEADER), "0");
}

TEST(CacertsEndpoint, NotFoundAnswerCarriesNoCaGenerationHeader)
{
    Fixture f;

    const auto response = f.run(CaCertificateSnapshot {});

    EXPECT_EQ(response.status, 404);
    EXPECT_TRUE(responseHeader(response, CA_GENERATION_HEADER).empty());
}

TEST(CacertsEndpoint, CaMismatchAnswerCarriesNoCaGenerationHeader)
{
    Fixture f;

    const auto response = f.run(snapshotOf(false));

    EXPECT_EQ(response.status, 503);
    EXPECT_TRUE(responseHeader(response, CA_GENERATION_HEADER).empty());
}

TEST(CacertsEndpoint, NeverEmitsAHashHeader)
{
    // The published and the unpublished 200 from above: not one header on either answer names a
    // hash -- only the generation ever leaves this endpoint, never a digest of the file or of the
    // certificates it carries (CA-9).
    Fixture f;
    auto published = snapshotOf(true);
    published.publication = 1758000000;

    for (const auto& response : {f.run(published), f.run(snapshotOf(true))})
    {
        for (const auto& [key, value] : response.headers)
        {
            std::string lowered = key;
            std::transform(
                lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) { return std::tolower(c); });
            EXPECT_EQ(lowered.find("sha"), std::string::npos) << key;
            EXPECT_EQ(lowered.find("hash"), std::string::npos) << key;
        }
    }
}

// ---------------------------------------------------------------------------
// deliverCaRecordEvents(): the collaborator that says out loud, and persists, what the read just
// above noticed about the bundle's publication (issue #39319, C21b). The first test below stays
// with the file's usual canned snapshots (only the ORDER matters); the other two need a REAL
// CaCertificateSource so there is something genuine to drain.
// ---------------------------------------------------------------------------

TEST(CacertsEndpoint, DeliversRecordEventsBeforeRespondingOnAllThreePaths)
{
    Fixture f;
    struct Case
    {
        const char* name;
        CaCertificateSnapshot snapshot;
        int expectedStatus;
    };
    const std::vector<Case> cases = {
        {"200", snapshotOf(true), 200},
        {"404", CaCertificateSnapshot {}, 404},
        {"503", snapshotOf(false), 503},
    };

    for (const auto& testCase : cases)
    {
        std::vector<std::string> order;
        std::function<void()> deliver = [&order]
        {
            order.push_back("delivered");
        };
        auto handler = makeHandler([snapshot = testCase.snapshot] { return snapshot; }, f.metrics, &f.http, deliver);
        auto responder = std::make_shared<OrderRecordingResponder>(order);
        handler(std::make_shared<const HttpRequest>(getRequest()), responder);
        const auto response = responder->wait();

        EXPECT_EQ(response.status, testCase.expectedStatus) << testCase.name;
        ASSERT_EQ(order.size(), 2U) << testCase.name;
        EXPECT_EQ(order[0], "delivered") << testCase.name;
        EXPECT_EQ(order[1], "responded") << testCase.name;
    }
}

TEST(CacertsEndpoint, HandlerAndTickEmitExactlyOnce)
{
    auto pki = remoted::test::generateCaSignedCertificate("cacerts-endpoint-once");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files()};

    auto leafCerts = ca_bundle::parseBundle(readAll(pki->certPath)).certificates;
    ASSERT_EQ(leafCerts.size(), 1U);

    TempDir dir;
    auto record = std::make_shared<remoted::http::CaPublicationRecord>(dir.path() + "/record.json");
    auto mailbox = std::make_shared<remoted::http::CaRecordEventMailbox>();
    // An ordinary CA file (no publication block): the first read announces first_time_unpublished.
    remoted::http::CaCertificateSource source {pki->caCertPath,
                                               leafCerts.front().get(),
                                               remoted::http::readFileBounded,
                                               std::chrono::steady_clock::now,
                                               record->load(pki->caCertPath),
                                               record,
                                               mailbox};

    Fixture f;
    std::vector<remoted::http::CaRecordEvent> handlerDrained;
    std::function<void()> deliver = [&source, &handlerDrained]
    {
        auto events = source.drainRecordEvents();
        handlerDrained.insert(handlerDrained.end(), events.begin(), events.end());
        source.flushPendingRecord();
    };
    auto handler = makeHandler([&source] { return source.snapshot(); }, f.metrics, &f.http, deliver);
    auto responder = std::make_shared<CapturingResponder>();
    handler(std::make_shared<const HttpRequest>(getRequest()), responder);
    EXPECT_EQ(responder->wait().status, 200);

    ASSERT_EQ(handlerDrained.size(), 1U);
    EXPECT_EQ(handlerDrained[0].kind, remoted::http::RecordEvent::first_time_unpublished);

    // A tick right after the request must see nothing: the request already drained the mailbox --
    // an event comes out of exactly one of the two callers, never both (C21b).
    EXPECT_TRUE(source.drainRecordEvents().empty());
}

TEST(CacertsEndpoint, GuardFailureIsLoggedOnTheNextRequestNotAtTheTick)
{
    auto pki = remoted::test::generateCaSignedCertificate("cacerts-endpoint-guardtick");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files()};

    auto leafCerts = ca_bundle::parseBundle(readAll(pki->certPath)).certificates;
    ASSERT_EQ(leafCerts.size(), 1U);
    auto caCerts = ca_bundle::parseBundle(readAll(pki->caCertPath)).certificates;
    ASSERT_EQ(caCerts.size(), 1U);

    TempDir dir;
    auto record = std::make_shared<remoted::http::CaPublicationRecord>(dir.path() + "/record.json");
    auto mailbox = std::make_shared<remoted::http::CaRecordEventMailbox>();
    remoted::http::CaCertificateSource source {pki->caCertPath,
                                               leafCerts.front().get(),
                                               remoted::http::readFileBounded,
                                               std::chrono::steady_clock::now,
                                               record->load(pki->caCertPath),
                                               record,
                                               mailbox};

    // "Tick 0": the start-time evaluation, drained and persisted exactly like the real transport.
    source.snapshot();
    source.drainRecordEvents();
    source.flushPendingRecord();

    // Between two ticks (the 24h cadence does not matter here: a guard is re-evaluated on the
    // next READ, whoever makes it), the bundle is edited by hand into a hash mismatch.
    write(pki->caCertPath, sealBundle(caCerts, 1789000000, std::string(64, 'a')));

    // The very next request drains it -- not a tick.
    Fixture f;
    std::vector<remoted::http::CaRecordEvent> handlerDrained;
    std::function<void()> deliver = [&source, &handlerDrained]
    {
        auto events = source.drainRecordEvents();
        handlerDrained.insert(handlerDrained.end(), events.begin(), events.end());
        source.flushPendingRecord();
    };
    auto handler = makeHandler([&source] { return source.snapshot(); }, f.metrics, &f.http, deliver);
    auto responder = std::make_shared<CapturingResponder>();
    handler(std::make_shared<const HttpRequest>(getRequest()), responder);
    responder->wait();

    ASSERT_EQ(handlerDrained.size(), 1U);
    EXPECT_EQ(handlerDrained[0].kind, remoted::http::RecordEvent::guard_failed);
    EXPECT_EQ(handlerDrained[0].guard, ca_bundle::GuardFailure::hash_mismatch);

    // A tick simulated right after sees nothing: the request already said it.
    EXPECT_TRUE(source.drainRecordEvents().empty());
}
