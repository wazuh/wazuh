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

// cancel(id) (the contract's cancel).

#include <iostream>
#include <limits>

#include "componentFixture.hpp"
#include "fakeIndexer.hpp"
#include "rawTcpServer.hpp"
#include "testTimeScale.hpp"

using namespace component;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::Rule;
using indexer_client::testing::scaled;
using indexer_client::testing::SilentServer;
using indexer_client::testing::StalledUploadServer;
namespace hooks = indexer_client::testing_hooks;

namespace
{
    std::uint64_t inFlight(const Transport& transport)
    {
        return sumOf(transport.stats().inFlightPerLoop);
    }

    FakeIndexer& holdAll(FakeIndexer& fake)
    {
        Rule hold;
        hold.hold = true;
        fake.addRule(hold);
        return fake;
    }
} // namespace

// Cancelled while its start is still queued behind a busy loop: nothing reaches the server.
TEST_F(TransportTest, CancelRacesBeforeStart)
{
    FakeIndexer fake;
    fake.start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    auto blocker = Blocker::create();
    ReleaseOnExit releaseBlocker(blocker);
    ASSERT_TRUE(indexer_client::detail::testing::postToIoLoop(blocker->task(), 0));
    ASSERT_TRUE(blocker->waitStarted(1, 5s));
    const auto rejectedBefore = hooks::postsRejected();
    const auto one = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/before"));
    ASSERT_TRUE(one.admission.admitted);
    EXPECT_TRUE(transport->cancel(one.admission.id)) << "a pending transfer is cancellable";
    blocker->release();

    ASSERT_TRUE(collector->waitKey(one.key, 10s));
    const auto result = collector->result(one.key);
    EXPECT_EQ(result->cause, TransportCause::Cancelled);
    EXPECT_FALSE(result->nodeAttributable);
    EXPECT_FALSE(result->mayHaveSent);
    EXPECT_EQ(result->uploadedBytes, 0u);
    EXPECT_EQ(inFlight(*transport), 0u);
    EXPECT_FALSE(fake.waitForRequests(1, 300ms)) << "a transfer cancelled before its start never reaches the server";
    EXPECT_FALSE(transport->cancel(one.admission.id)) << "already resolved";
    EXPECT_EQ(collector->count(one.key), 1);
    EXPECT_EQ(hooks::postsRejected(), rejectedBefore);
    EXPECT_EQ(transport->stats().cancelled, 1u);
}

// Cancelled while the server holds the response: out of the multi before the result, one result.
TEST_F(TransportTest, CancelRacesDuringTransfer)
{
    FakeIndexer fake;
    holdAll(fake).start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto one = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/during"));
    ASSERT_TRUE(one.admission.admitted);
    ASSERT_TRUE(fake.waitHeld(1, 10s));
    EXPECT_EQ(inFlight(*transport), 1u);
    EXPECT_TRUE(transport->cancel(one.admission.id));

    ASSERT_TRUE(collector->waitKey(one.key, 10s));
    const auto result = collector->result(one.key);
    EXPECT_EQ(result->cause, TransportCause::Cancelled);
    EXPECT_TRUE(result->mayHaveSent) << "the request had been written";
    EXPECT_EQ(result->status, 0);
    EXPECT_EQ(inFlight(*transport), 0u) << "removed from the multi before the result";
    EXPECT_FALSE(transport->cancel(one.admission.id));
    fake.releaseHeld();

    // Same loop, next transfer: unaffected.
    const auto next = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/after"));
    ASSERT_TRUE(collector->waitKey(next.key, 10s));
    EXPECT_EQ(collector->result(next.key)->status, 200);
    EXPECT_EQ(collector->count(one.key), 1);
}

// cancel() against the transfer's own completion, at staggered delays: whichever event touches the state first wins,
// exactly one result per id; a Cancelled result always comes from a cancel() that returned true. Both outcomes must
// occur (the race was really run).
TEST_F(TransportTest, CancelRacesVsCompletion)
{
    FakeIndexer fake;
    fake.start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    constexpr int ROUNDS = 300;
    std::size_t cancelledWins = 0;
    std::size_t completionWins = 0;
    std::size_t lostCancels = 0; // cancel() returned true but the completion had already won on the loop.
    std::vector<std::uint64_t> keys;
    for (int round = 0; round < ROUNDS; ++round)
    {
        const auto one = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/race"));
        ASSERT_TRUE(one.admission.admitted);
        keys.push_back(one.key);
        // Staggered delay (the measured variable of this race): 0 .. scaled(3 ms), so that the completion still wins
        // the longer delays where every transfer is slower.
        const auto delay = std::chrono::duration_cast<std::chrono::microseconds>(scaled(3ms)) * (round % 31) / 30;
        const auto until = std::chrono::steady_clock::now() + delay;
        while (std::chrono::steady_clock::now() < until)
        {
            std::this_thread::yield();
        }
        const bool accepted = transport->cancel(one.admission.id);
        ASSERT_TRUE(collector->waitKey(one.key, 10s));
        const auto result = collector->result(one.key);
        if (result->cause == TransportCause::Cancelled)
        {
            ++cancelledWins;
            EXPECT_TRUE(accepted) << "a Cancelled result needs a cancel() that returned true";
        }
        else
        {
            ++completionWins;
            EXPECT_EQ(result->cause, TransportCause::None);
            EXPECT_EQ(result->status, 200);
            if (accepted)
            {
                ++lostCancels;
            }
        }
    }
    EXPECT_GT(cancelledWins, 0u) << "cancel never won: the race was not run";
    EXPECT_GT(completionWins, 0u) << "completion never won: the race was not run";
    std::cout << "[ INFO     ] cancel won " << cancelledWins << ", completion won " << completionWins << " (of which "
              << lostCancels << " after an accepted cancel)" << std::endl;

    ASSERT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);
    for (const auto key : keys)
    {
        EXPECT_EQ(collector->count(key), 1) << "key " << key;
    }
}

// cancel() while the stop is in progress: the owning loop is closed (its teardown is queued behind a task), so the
// cancel's post is refused and counted, cancel() returns false, and the transfer gets its single result from the
// stop (Shutdown). A throwaway transfer on the same loop probes the moment the loop starts refusing posts.
TEST_F(TransportTest, CancelRacesVsStop)
{
    FakeIndexer fake;
    holdAll(fake).start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto target = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/target"));
    const auto probe = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/probe"));
    ASSERT_TRUE(target.admission.admitted);
    ASSERT_TRUE(probe.admission.admitted);
    ASSERT_TRUE(fake.waitHeld(2, 10s));

    auto blocker = Blocker::create();
    ASSERT_TRUE(indexer_client::detail::testing::postToIoLoop(blocker->task(), 0));
    ASSERT_TRUE(blocker->waitStarted(1, 5s));
    AsyncCall stop([transport]() { transport->stop(std::chrono::steady_clock::now() + 30s); });
    ReleaseOnExit releaseBlocker(blocker);

    // While the loop accepts posts, cancel(probe) is posted (it runs later, before the teardown); the first refusal
    // proves the loop is closed.
    const auto statsBefore = transport->stats().postsRejected;
    const auto hookBefore = hooks::postsRejected();
    std::size_t probeAccepted = 0;
    const bool closed = eventually(
        [&]
        {
            if (!transport->cancel(probe.admission.id))
            {
                return true;
            }
            ++probeAccepted;
            return false;
        },
        5s);
    ASSERT_TRUE(closed) << "the loop never refused a post after stop() began (" << probeAccepted << " accepted)";
    ASSERT_EQ(hooks::postsRejected() - hookBefore, 1u) << "the probe's refusal is counted";

    EXPECT_FALSE(transport->cancel(target.admission.id)) << "a closed loop refuses the cancel";
    EXPECT_EQ(hooks::postsRejected() - hookBefore, 2u) << "onPostRejected counts it";
    EXPECT_EQ(transport->stats().postsRejected - statsBefore, 2u);
    EXPECT_FALSE(stop.done());

    blocker->release();
    ASSERT_TRUE(stop.wait(10s));
    ASSERT_TRUE(collector->waitTotal(2, 10s));
    EXPECT_EQ(collector->result(target.key)->cause, TransportCause::Shutdown);
    EXPECT_EQ(collector->count(target.key), 1);
    EXPECT_EQ(collector->count(probe.key), 1);
    const auto probeCause = collector->result(probe.key)->cause;
    EXPECT_TRUE(probeCause == TransportCause::Cancelled || probeCause == TransportCause::Shutdown);
    EXPECT_EQ(hooks::postsRejected() - hookBefore, 2u) << "nothing else was posted to the closed loop";
    EXPECT_FALSE(blocker->expired());
}

TEST_F(TransportTest, CancelRacesUnknownId)
{
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    const auto before = transport->stats();
    const auto hookBefore = hooks::postsRejected();
    EXPECT_FALSE(transport->cancel(0));
    EXPECT_FALSE(transport->cancel(12345));
    EXPECT_FALSE(transport->cancel(std::numeric_limits<std::uint64_t>::max()));
    const auto after = transport->stats();
    EXPECT_EQ(after.cancelled, before.cancelled);
    EXPECT_EQ(after.postsRejected, before.postsRejected);
    EXPECT_EQ(hooks::postsRejected(), hookBefore);
}

TEST_F(TransportTest, CancelRacesAfterResolved)
{
    FakeIndexer fake;
    fake.start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();
    const auto hookBefore = hooks::postsRejected();

    const auto one = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/done"));
    ASSERT_TRUE(collector->waitKey(one.key, 10s));
    EXPECT_EQ(collector->result(one.key)->status, 200);
    EXPECT_FALSE(transport->cancel(one.admission.id)) << "already resolved";

    // A later round trip on the same loop: any stray handler for the first id would have run before it.
    const auto next = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/next"));
    ASSERT_TRUE(collector->waitKey(next.key, 10s));
    EXPECT_EQ(collector->count(one.key), 1);
    EXPECT_EQ(transport->stats().cancelled, 0u);
    EXPECT_EQ(hooks::postsRejected(), hookBefore);
}

// Cancelling a transfer to a server that accepted and never answers closes its connection at once.
TEST_F(TransportTest, CancelWhileServerSilent)
{
    SilentServer silent;
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto one =
        submitTo(*transport,
                 collector,
                 request(HttpMethod::Get, silent.baseUrl() + "/silent", nullptr, indexer_client::Duration {20000}));
    ASSERT_TRUE(one.admission.admitted);
    ASSERT_TRUE(silent.waitForAccepted(1, 10s));
    ASSERT_TRUE(eventually([&] { return silent.connections()[0].bytesRead > 0; }, 5s)) << "the request was sent";
    EXPECT_EQ(inFlight(*transport), 1u);

    const auto cancelledAt = std::chrono::steady_clock::now();
    ASSERT_TRUE(transport->cancel(one.admission.id));
    ASSERT_TRUE(collector->waitKey(one.key, 10s));
    const auto result = collector->result(one.key);
    EXPECT_EQ(result->cause, TransportCause::Cancelled);
    EXPECT_FALSE(result->nodeAttributable);
    EXPECT_TRUE(result->mayHaveSent);
    // The contract fills the timings also for Cancelled (read before the easy leaves the multi): the TCP connection
    // was made and time went by.
    EXPECT_GT(result->timings.connect.count(), 0);
    EXPECT_GT(result->timings.total.count(), 0);
    EXPECT_EQ(inFlight(*transport), 0u) << "inFlightEasies";

    const auto eof = silent.waitForEof(0, 2s);
    ASSERT_TRUE(eof.has_value()) << "the silent server never saw the connection close";
    EXPECT_LE(*eof - cancelledAt, scaled(100ms))
        << "EOF " << std::chrono::duration_cast<std::chrono::milliseconds>(*eof - cancelledAt).count()
        << " ms after cancel()";
}

// Cancelling a POST whose 64 MiB body is stuck against a server that does not read: the upload had stopped
// short of the body, the connection closes at once, and the loop keeps serving another transfer meanwhile and after.
TEST_F(TransportTest, CancelDuringStalledUpload)
{
    constexpr std::size_t BODY = 64 * 1024 * 1024;
    StalledUploadServer stalled(64 * 1024);
    FakeIndexer fake;
    fake.start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto body = std::make_shared<const std::string>(BODY, 'x');
    const auto upload =
        submitTo(*transport,
                 collector,
                 request(HttpMethod::Post, stalled.baseUrl() + "/_bulk", body, indexer_client::Duration {60000}));
    ASSERT_TRUE(upload.admission.admitted);
    ASSERT_TRUE(stalled.waitForAccepted(1, 10s));

    // The same loop serves another transfer while the upload is stuck (and gives the upload time to fill the
    // socket buffers).
    const auto during = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/during"));
    ASSERT_TRUE(collector->waitKey(during.key, 10s));
    EXPECT_EQ(collector->result(during.key)->status, 200);
    // curl sends `Expect: 100-continue` and waits up to 1 s (CURLOPT_EXPECT_100_TIMEOUT_MS) for an answer the silent
    // server never gives before it sends the body; measured: the upload is stalled well before 1.5 s (scaled()).
    std::this_thread::sleep_for(scaled(1500ms));
    EXPECT_EQ(collector->count(upload.key), 0);
    EXPECT_EQ(inFlight(*transport), 1u);

    ASSERT_TRUE(transport->cancel(upload.admission.id));
    stalled.resumeReading(); // The FIN queues behind the unread bytes: read them so the EOF shows.
    const auto resumedAt = std::chrono::steady_clock::now();
    ASSERT_TRUE(collector->waitKey(upload.key, 10s));
    const auto result = collector->result(upload.key);
    EXPECT_EQ(result->cause, TransportCause::Cancelled);
    EXPECT_TRUE(result->mayHaveSent);
    EXPECT_GT(result->uploadedBytes, 0u);
    EXPECT_LT(result->uploadedBytes, BODY) << "the upload had stalled when it was cancelled";
    EXPECT_EQ(inFlight(*transport), 0u) << "inFlightEasies";

    const auto eof = stalled.waitForEof(0, 2s);
    ASSERT_TRUE(eof.has_value()) << "the stalled server never saw the connection close";
    EXPECT_LE(*eof - resumedAt, scaled(100ms))
        << "EOF " << std::chrono::duration_cast<std::chrono::milliseconds>(*eof - resumedAt).count()
        << " ms after cancel() + resumeReading()";
    EXPECT_LT(stalled.connections()[0].bytesRead, BODY);

    const auto after = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/after"));
    ASSERT_TRUE(collector->waitKey(after.key, 10s));
    EXPECT_EQ(collector->result(after.key)->status, 200);
}
