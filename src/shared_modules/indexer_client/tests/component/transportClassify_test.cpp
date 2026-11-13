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

// What a finished transfer is classified as: the curl → cause table on
// real failures, a multi error, and the response cap.

#include <atomic>

#include <curl/curl.h>

#include "componentFixture.hpp"
#include "fakeIndexer.hpp"
#include "rawTcpServer.hpp"

using namespace component;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::FakeIndexerOptions;
using indexer_client::testing::Framing;
using indexer_client::testing::Rule;
using indexer_client::testing::SilentServer;
namespace hooks = indexer_client::testing_hooks;

namespace
{
    struct Expected final
    {
        const char* what;
        TransportCause cause;
        int curlCode;
        bool nodeAttributable;
        long status;
    };

    void expectClassified(const std::optional<HttpResult>& result, const Expected& expected)
    {
        ASSERT_TRUE(result.has_value()) << expected.what;
        EXPECT_EQ(result->cause, expected.cause)
            << expected.what << ": " << indexer_client::detail::toString(result->cause) << " (curl " << result->curlCode
            << ")";
        EXPECT_EQ(result->curlCode, expected.curlCode) << expected.what;
        EXPECT_EQ(result->nodeAttributable, expected.nodeAttributable) << expected.what;
        EXPECT_EQ(result->status, expected.status) << expected.what;
    }
} // namespace

// Each real failure gets its exact cause and nodeAttributable: refused connection, timeout, a connection the
// server closes without answering, a body cut short (Content-Length and chunked), and a complete response with no
// body.
TEST_F(TransportTest, ClassifiesExactly)
{
    FakeIndexer fake;
    Rule held;
    held.pathRegex = "/held";
    held.hold = true;
    fake.addRule(held);
    Rule truncated;
    truncated.pathRegex = "/truncated";
    truncated.bodySize = 100000;
    truncated.cutAfter = 1000;
    fake.addRule(truncated);
    Rule truncatedChunked;
    truncatedChunked.pathRegex = "/truncated-chunked";
    truncatedChunked.bodySize = 100000;
    truncatedChunked.framing = Framing::Chunked;
    truncatedChunked.chunkSize = 1000;
    truncatedChunked.cutAfter = 3000;
    fake.addRule(truncatedChunked);
    Rule empty;
    empty.pathRegex = "/empty";
    empty.body = "";
    fake.addRule(empty);
    fake.start();
    SilentServer closing;
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto refused =
        submitTo(*transport,
                 collector,
                 request(HttpMethod::Get, "http://127.0.0.1:" + std::to_string(closedPort()) + "/refused"));
    const auto timeout =
        submitTo(*transport,
                 collector,
                 request(HttpMethod::Get, fake.baseUrl() + "/held", nullptr, indexer_client::Duration {300}));
    const auto cut = submitTo(*transport, collector, request(HttpMethod::Get, closing.baseUrl() + "/cut"));
    const auto partial = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/truncated"));
    const auto partialChunked =
        submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/truncated-chunked"));
    const auto noBody = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/empty"));
    for (const auto* one : {&refused, &timeout, &cut, &partial, &partialChunked, &noBody})
    {
        ASSERT_TRUE(one->admission.admitted);
    }

    // The silent server read the request; closing it now closes the connection before any response byte.
    ASSERT_TRUE(
        eventually([&] { return closing.acceptedCount() == 1 && closing.connections()[0].bytesRead > 0; }, 10s));
    closing.stop();

    ASSERT_TRUE(collector->waitTotal(6, 10s));
    expectClassified(collector->result(refused.key),
                     {"refused", TransportCause::Connect, CURLE_COULDNT_CONNECT, true, 0});
    expectClassified(collector->result(timeout.key),
                     {"timeout", TransportCause::Timeout, CURLE_OPERATION_TIMEDOUT, true, 0});
    expectClassified(collector->result(cut.key), {"cut", TransportCause::RecvError, CURLE_GOT_NOTHING, true, 0});
    expectClassified(collector->result(partial.key),
                     {"truncated", TransportCause::PartialResponse, CURLE_PARTIAL_FILE, true, 200});
    expectClassified(collector->result(partialChunked.key),
                     {"truncated chunked", TransportCause::PartialResponse, CURLE_PARTIAL_FILE, true, 200});
    expectClassified(collector->result(noBody.key), {"no body", TransportCause::None, CURLE_OK, false, 200});
    EXPECT_TRUE(collector->result(noBody.key)->body.empty());
    fake.releaseHeld();
}

// A failed curl_multi_socket_action is the library's problem, never the node's: every transfer of the multi
// (the one that triggered it and one already in flight) fails once as LocalError, and the loop keeps working.
TEST_F(TransportTest, MultiErrorIsLocal)
{
    FakeIndexer fake;
    Rule held;
    held.pathRegex = "/held";
    held.hold = true;
    fake.addRule(held);
    fake.start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto inFlight = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/held"));
    ASSERT_TRUE(fake.waitHeld(1, 10s));

    auto injected = std::make_shared<std::atomic<int>>(0);
    hooks::setInjectMultiError(
        [injected](int rc)
        {
            int expected = 0;
            return injected->compare_exchange_strong(expected, 1) ? static_cast<int>(CURLM_INTERNAL_ERROR) : rc;
        });
    const auto trigger = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/trigger"));
    ASSERT_TRUE(collector->waitTotal(2, 10s));
    EXPECT_EQ(injected->load(), 1) << "the multi error was never injected";

    for (const auto* one : {&inFlight, &trigger})
    {
        const auto result = collector->result(one->key);
        EXPECT_EQ(result->cause, TransportCause::LocalError) << indexer_client::detail::toString(result->cause);
        EXPECT_FALSE(result->nodeAttributable);
        EXPECT_EQ(result->curlCode, CURLE_FAILED_INIT);
        EXPECT_EQ(collector->count(one->key), 1);
    }
    EXPECT_EQ(sumOf(transport->stats().inFlightPerLoop), 0u);
    fake.releaseHeld();

    const auto next = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/next"));
    ASSERT_TRUE(collector->waitKey(next.key, 10s));
    EXPECT_EQ(collector->result(next.key)->cause, TransportCause::None);
    EXPECT_EQ(collector->result(next.key)->status, 200);
}

namespace
{
    constexpr std::size_t CAP = 64 * 1024;

    /// One transfer against a fake that serves `size` filler bytes framed as `framing`, with max_response_bytes = CAP.
    std::optional<HttpResult>
    fetchWithCap(const std::function<std::shared_ptr<Transport>()>& start, std::size_t size, Framing framing)
    {
        FakeIndexer fake;
        Rule rule;
        rule.bodySize = size;
        rule.framing = framing;
        rule.chunkSize = 4096;
        fake.addRule(rule);
        fake.start();
        auto transport = start();
        if (!transport)
        {
            return std::nullopt;
        }
        auto collector = Collector::create();
        const auto one = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/big"));
        if (!one.admission.admitted || !collector->waitKey(one.key, 10s))
        {
            return std::nullopt;
        }
        return collector->result(one.key);
    }
} // namespace

// A response of exactly max_response_bytes is delivered whole.
TEST_F(TransportTest, ResponseCapAtLimit)
{
    const auto result =
        fetchWithCap([this] { return startRuntime(1, 2, {{"max_response_bytes", std::to_string(CAP)}}); },
                     CAP,
                     Framing::ContentLength);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->cause, TransportCause::None) << indexer_client::detail::toString(result->cause);
    EXPECT_EQ(result->status, 200);
    EXPECT_EQ(result->body.size(), CAP);
}

// One byte over the cap, chunked (no length known up front): ResponseTooLarge, never a body over the cap.
TEST_F(TransportTest, ResponseCapOverLimitChunked)
{
    const auto result =
        fetchWithCap([this] { return startRuntime(1, 2, {{"max_response_bytes", std::to_string(CAP)}}); },
                     CAP + 1,
                     Framing::Chunked);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->cause, TransportCause::ResponseTooLarge) << indexer_client::detail::toString(result->cause);
    EXPECT_EQ(result->curlCode, CURLE_WRITE_ERROR);
    EXPECT_FALSE(result->nodeAttributable);
    EXPECT_LE(result->body.size(), CAP);
}

// One byte over the cap with a Content-Length: ResponseTooLarge as well (the cap lives in the write callback only).
TEST_F(TransportTest, ResponseCapOverLimitContentLength)
{
    const auto result =
        fetchWithCap([this] { return startRuntime(1, 2, {{"max_response_bytes", std::to_string(CAP)}}); },
                     CAP + 1,
                     Framing::ContentLength);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->cause, TransportCause::ResponseTooLarge) << indexer_client::detail::toString(result->cause);
    EXPECT_EQ(result->curlCode, CURLE_WRITE_ERROR);
    EXPECT_FALSE(result->nodeAttributable);
    EXPECT_LE(result->body.size(), CAP);
}
