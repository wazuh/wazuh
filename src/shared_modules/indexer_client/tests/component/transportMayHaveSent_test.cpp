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

// HttpResult::mayHaveSent The flag is "CURLOPT_PREREQFUNCTION ran": the connection
// was ready and the request was about to be written. It is not "bytes were uploaded" (a GET or a HEAD uploads no
// body) and it is reset on every use of an easy handle.

#include <atomic>

#include <curl/curl.h>

#include "componentFixture.hpp"
#include "fakeIndexer.hpp"
#include "rawTcpServer.hpp"

using namespace component;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::Rule;
using indexer_client::testing::SilentServer;
using indexer_client::testing::StalledUploadServer;
namespace hooks = indexer_client::testing_hooks;

// The openSocket seam refuses the socket: the connection never completes, so nothing may have been sent.
TEST_F(TransportTest, MayHaveSentConnectNeverCompletesFalse)
{
    FakeIndexer fake;
    fake.start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    auto opened = std::make_shared<std::atomic<int>>(0);
    hooks::setOpenSocket(
        [opened]() -> std::optional<int>
        {
            opened->fetch_add(1);
            return CURL_SOCKET_BAD;
        });
    const auto one = submitTo(*transport, collector, request(HttpMethod::Post, fake.baseUrl() + "/x"));
    ASSERT_TRUE(one.admission.admitted);
    ASSERT_TRUE(collector->waitKey(one.key, 10s));
    const auto result = collector->result(one.key);
    EXPECT_GE(opened->load(), 1) << "the seam was not consulted: the forced connect failure did not happen";
    EXPECT_EQ(result->cause, TransportCause::Connect) << indexer_client::detail::toString(result->cause);
    EXPECT_EQ(result->curlCode, CURLE_COULDNT_CONNECT);
    EXPECT_TRUE(result->nodeAttributable);
    EXPECT_FALSE(result->mayHaveSent);
    EXPECT_EQ(result->uploadedBytes, 0u);
    EXPECT_EQ(result->status, 0);
    EXPECT_FALSE(fake.waitForRequests(1, 200ms)) << "nothing reached the server";
}

// A server that accepts, reads the request and never answers: the request was written (true), although a GET
// uploads no body.
TEST_F(TransportTest, MayHaveSentSilentServerTrue)
{
    SilentServer silent;
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto one =
        submitTo(*transport,
                 collector,
                 request(HttpMethod::Get, silent.baseUrl() + "/mute", nullptr, indexer_client::Duration {300}));
    ASSERT_TRUE(one.admission.admitted);
    ASSERT_TRUE(collector->waitKey(one.key, 10s));
    const auto result = collector->result(one.key);
    EXPECT_EQ(result->cause, TransportCause::Timeout) << indexer_client::detail::toString(result->cause);
    EXPECT_EQ(result->curlCode, CURLE_OPERATION_TIMEDOUT);
    EXPECT_TRUE(result->nodeAttributable);
    EXPECT_TRUE(result->mayHaveSent);
    EXPECT_EQ(result->uploadedBytes, 0u) << "a GET uploads no body";
    ASSERT_EQ(silent.acceptedCount(), 1u);
    EXPECT_GT(silent.connections()[0].bytesRead, 0u) << "the request did reach the server";
}

// A POST whose body stalls against a server that does not read: part of the body went out, then the timeout.
TEST_F(TransportTest, MayHaveSentPostPartialTrue)
{
    constexpr std::size_t BODY = 16 * 1024 * 1024;
    StalledUploadServer stalled(64 * 1024);
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto body = std::make_shared<const std::string>(BODY, 'p');
    const auto one =
        submitTo(*transport,
                 collector,
                 // Past curl's 1 s wait for `100 Continue`, so part of the body goes out before the timeout.
                 request(HttpMethod::Post, stalled.baseUrl() + "/_bulk", body, indexer_client::Duration {2000}));
    ASSERT_TRUE(one.admission.admitted);
    ASSERT_TRUE(collector->waitKey(one.key, 10s));
    const auto result = collector->result(one.key);
    EXPECT_EQ(result->cause, TransportCause::Timeout) << indexer_client::detail::toString(result->cause);
    EXPECT_TRUE(result->nodeAttributable);
    EXPECT_TRUE(result->mayHaveSent);
    EXPECT_GT(result->uploadedBytes, 0u) << "part of the body went out";
    EXPECT_LT(result->uploadedBytes, BODY) << "the upload had stalled";
    stalled.resumeReading();
}

// A body over 1 MiB waits for `100 Continue`; a timeout inside that wait (the silent server never answers) sent
// the headers but no body byte: Timeout, node-attributable, mayHaveSent (the request was ready to go), 0 bytes
// uploaded.
TEST_F(TransportTest, MayHaveSentPostDuringExpectWaitTrue)
{
    constexpr std::size_t BODY = 4 * 1024 * 1024;
    StalledUploadServer stalled(64 * 1024);
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto body = std::make_shared<const std::string>(BODY, 'e');
    const auto one =
        submitTo(*transport,
                 collector,
                 // Inside curl's 1 s wait for `100 Continue` (CURLOPT_EXPECT_100_TIMEOUT_MS).
                 request(HttpMethod::Post, stalled.baseUrl() + "/_bulk", body, indexer_client::Duration {500}));
    ASSERT_TRUE(one.admission.admitted);
    ASSERT_TRUE(collector->waitKey(one.key, 10s));
    const auto result = collector->result(one.key);
    EXPECT_EQ(result->cause, TransportCause::Timeout) << indexer_client::detail::toString(result->cause);
    EXPECT_TRUE(result->nodeAttributable);
    EXPECT_TRUE(result->mayHaveSent);
    EXPECT_EQ(result->uploadedBytes, 0u) << "no body byte leaves before 100 Continue";
    stalled.resumeReading();
}

// HEAD: the fake confirms it received the request and holds the answer; the transfer times out. Nothing of a body
// was uploaded (uploadedBytes == 0), yet the request was written: true.
TEST_F(TransportTest, MayHaveSentHeadReceivedThenTimeoutTrue)
{
    FakeIndexer fake;
    Rule hold;
    hold.hold = true;
    fake.addRule(hold);
    fake.start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto one =
        submitTo(*transport,
                 collector,
                 request(HttpMethod::Head, fake.baseUrl() + "/probe", nullptr, indexer_client::Duration {400}));
    ASSERT_TRUE(one.admission.admitted);
    ASSERT_TRUE(fake.waitForRequests(1, 10s)) << "the fake never received the HEAD";
    EXPECT_EQ(fake.requests()[0].method, "HEAD");
    ASSERT_TRUE(collector->waitKey(one.key, 10s));
    const auto result = collector->result(one.key);
    EXPECT_EQ(result->cause, TransportCause::Timeout) << indexer_client::detail::toString(result->cause);
    EXPECT_EQ(result->uploadedBytes, 0u);
    EXPECT_TRUE(result->mayHaveSent) << "received by the server, so it may have been sent";
    fake.releaseHeld();
}

// An easy handle that already sent a request (its transfer had mayHaveSent = true) is reused by a transfer that is
// cancelled after it entered the multi but before curl ever ran it: false, the flag is not inherited.
TEST_F(TransportTest, MayHaveSentReuseThenCancelBeforeStartFalse)
{
    FakeIndexer fake;
    fake.start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto first = submitTo(*transport, collector, request(HttpMethod::Post, fake.baseUrl() + "/first"));
    ASSERT_TRUE(collector->waitKey(first.key, 10s));
    ASSERT_EQ(collector->result(first.key)->status, 200);
    ASSERT_TRUE(collector->result(first.key)->mayHaveSent) << "the easy handle's previous use did send";

    // Counts the starts that reach curl_multi_add_handle (the seam sits right before it).
    auto added = std::make_shared<std::atomic<int>>(0);
    hooks::setThrowOnAdd([added]() { added->fetch_add(1); });
    const auto easyBefore = easyHandlesCreated();

    // Start and cancel queue behind a busy loop, in that order: the start puts the easy into the multi and arms a
    // 0 ms timer whose handler comes after the cancel, so curl never runs the transfer.
    auto blocker = Blocker::create();
    ReleaseOnExit releaseBlocker(blocker);
    ASSERT_TRUE(indexer_client::detail::testing::postToIoLoop(blocker->task(), 0));
    ASSERT_TRUE(blocker->waitStarted(1, 5s));
    const auto second = submitTo(*transport, collector, request(HttpMethod::Post, fake.baseUrl() + "/second"));
    ASSERT_TRUE(second.admission.admitted);
    ASSERT_TRUE(transport->cancel(second.admission.id));
    blocker->release();

    ASSERT_TRUE(collector->waitKey(second.key, 10s));
    const auto result = collector->result(second.key);
    EXPECT_EQ(added->load(), 1) << "the cancelled transfer never entered the multi: the race was not exercised";
    EXPECT_EQ(easyHandlesCreated() - easyBefore, 0u) << "the transfer did not reuse the first one's easy handle";
    EXPECT_EQ(result->cause, TransportCause::Cancelled);
    EXPECT_FALSE(result->mayHaveSent) << "inherited from the easy handle's previous use";
    EXPECT_EQ(result->uploadedBytes, 0u);
    EXPECT_FALSE(fake.waitForRequests(2, 200ms)) << "the cancelled request reached the server";
}
