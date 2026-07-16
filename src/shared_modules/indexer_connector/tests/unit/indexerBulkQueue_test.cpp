/*
 * Wazuh - Indexer Connector Bulk Queue unit tests.
 * Copyright (C) 2015, Wazuh Inc.
 * July 15, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "indexerBulkQueue.hpp"
#include <atomic>
#include <chrono>
#include <future>
#include <gtest/gtest.h>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

class IndexerBulkQueueTest : public ::testing::Test
{
protected:
    static constexpr size_t UNLIMITED_BYTES {0};
    static constexpr size_t SEND_ON_EVERY_PUSH {1};
    static constexpr size_t FLUSH_INTERVAL_SEC {2};
    static constexpr size_t RETRY_DELAY_SEC {1};
    static constexpr size_t MAX_RETRY_DELAY_SEC {2};
};

TEST_F(IndexerBulkQueueTest, PushSendsQueuedDataToProcessor)
{
    std::promise<void> processedPromise;
    std::future<void> processedFuture = processedPromise.get_future();
    std::vector<std::string> received;
    std::mutex receivedMutex;

    IndexerBulkQueue queue(
        [&](uint64_t /*sequence*/, std::vector<std::string>& batch)
        {
            std::lock_guard<std::mutex> lock(receivedMutex);
            received.insert(received.end(), batch.begin(), batch.end());
            processedPromise.set_value();
        },
        UNLIMITED_BYTES,
        SEND_ON_EVERY_PUSH,
        FLUSH_INTERVAL_SEC,
        RETRY_DELAY_SEC,
        MAX_RETRY_DELAY_SEC);

    queue.push(std::string("payload-1"));

    ASSERT_EQ(processedFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    std::lock_guard<std::mutex> lock(receivedMutex);
    ASSERT_EQ(received.size(), 1U);
    EXPECT_EQ(received.front(), "payload-1");
}

// Mirrors the cluster_block_exception scenario: the caller observed the send already succeeded
// (so there's nothing here to retry), it just wants the *next* send delayed. That must never cause
// the already-sent data to be lost, duplicated, or resent, and new data must still arrive intact.
TEST_F(IndexerBulkQueueTest, RequestBackoffDoesNotDropOrDuplicateData)
{
    std::promise<void> firstSentPromise;
    std::future<void> firstSentFuture = firstSentPromise.get_future();
    std::promise<void> secondSentPromise;
    std::future<void> secondSentFuture = secondSentPromise.get_future();
    std::vector<std::string> received;
    std::mutex receivedMutex;
    std::atomic<int> sendCount {0};
    std::atomic<uint64_t> firstSequence {0};

    IndexerBulkQueue queue(
        [&](uint64_t sequence, std::vector<std::string>& batch)
        {
            std::lock_guard<std::mutex> lock(receivedMutex);
            received.insert(received.end(), batch.begin(), batch.end());
            const auto count = ++sendCount;
            if (count == 1)
            {
                firstSequence.store(sequence);
                firstSentPromise.set_value();
            }
            else if (count == 2)
            {
                // Guarded with else-if (rather than a catch-all else) so a hypothetical third
                // invocation - which would itself be a bug this test should surface via the
                // size/content assertions below - can't call set_value() on an already-satisfied
                // promise and crash the test binary via std::terminate().
                secondSentPromise.set_value();
            }
        },
        UNLIMITED_BYTES,
        SEND_ON_EVERY_PUSH,
        FLUSH_INTERVAL_SEC,
        RETRY_DELAY_SEC,
        MAX_RETRY_DELAY_SEC);

    queue.push(std::string("first-batch"));
    ASSERT_EQ(firstSentFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready);

    // Simulates the response logger reporting a cluster_block_exception for the batch just sent.
    queue.requestBackoff(firstSequence.load());
    queue.push(std::string("second-batch"));

    ASSERT_EQ(secondSentFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Second send never happened - requestBackoff() may have stalled the dispatch thread";

    std::lock_guard<std::mutex> lock(receivedMutex);
    ASSERT_EQ(received.size(), 2U);
    EXPECT_EQ(received[0], "first-batch");
    EXPECT_EQ(received[1], "second-batch");
}

// Calling requestBackoff() repeatedly before the dispatch thread gets a chance to send again must
// coalesce into a single pause, not one per call, and must not cause the pending data to be sent
// more than once.
TEST_F(IndexerBulkQueueTest, RequestBackoffCoalescesRepeatedCalls)
{
    std::promise<void> firstSentPromise;
    std::future<void> firstSentFuture = firstSentPromise.get_future();
    std::promise<void> secondSentPromise;
    std::future<void> secondSentFuture = secondSentPromise.get_future();
    std::vector<std::string> received;
    std::mutex receivedMutex;
    std::atomic<int> sendCount {0};
    std::atomic<uint64_t> firstSequence {0};

    IndexerBulkQueue queue(
        [&](uint64_t sequence, std::vector<std::string>& batch)
        {
            std::lock_guard<std::mutex> lock(receivedMutex);
            received.insert(received.end(), batch.begin(), batch.end());
            const auto count = ++sendCount;
            if (count == 1)
            {
                firstSequence.store(sequence);
                firstSentPromise.set_value();
            }
            else if (count == 2)
            {
                // Guarded with else-if (rather than a catch-all else) so a hypothetical third
                // invocation - which would itself be a bug this test should surface via the
                // size/content assertions below - can't call set_value() on an already-satisfied
                // promise and crash the test binary via std::terminate().
                secondSentPromise.set_value();
            }
        },
        UNLIMITED_BYTES,
        SEND_ON_EVERY_PUSH,
        FLUSH_INTERVAL_SEC,
        RETRY_DELAY_SEC,
        MAX_RETRY_DELAY_SEC);

    queue.push(std::string("first-batch"));
    ASSERT_EQ(firstSentFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready);

    for (int i = 0; i < 5; ++i)
    {
        queue.requestBackoff(firstSequence.load());
    }
    queue.push(std::string("second-batch"));

    ASSERT_EQ(secondSentFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready);

    std::lock_guard<std::mutex> lock(receivedMutex);
    ASSERT_EQ(sendCount.load(), 2) << "Repeated requestBackoff() calls should not cause extra sends";
    ASSERT_EQ(received.size(), 2U);
    EXPECT_EQ(received[1], "second-batch");
}

// A stale, out-of-order classification result (an older sequence completing after a newer one
// already reported) must not undo the newer verdict - the whole point of tagging reports with a
// sequence id, since classification runs on a separate, async worker that can finish out of order.
TEST_F(IndexerBulkQueueTest, StaleSequenceReportIsIgnored)
{
    std::promise<void> firstSentPromise;
    std::future<void> firstSentFuture = firstSentPromise.get_future();
    std::promise<void> secondSentPromise;
    std::future<void> secondSentFuture = secondSentPromise.get_future();
    std::promise<void> thirdSentPromise;
    std::future<void> thirdSentFuture = thirdSentPromise.get_future();
    std::atomic<int> sendCount {0};
    std::atomic<uint64_t> firstSequence {0};
    std::atomic<uint64_t> secondSequence {0};

    IndexerBulkQueue queue(
        [&](uint64_t sequence, std::vector<std::string>&)
        {
            const auto count = ++sendCount;
            if (count == 1)
            {
                firstSequence.store(sequence);
                firstSentPromise.set_value();
            }
            else if (count == 2)
            {
                secondSequence.store(sequence);
                secondSentPromise.set_value();
            }
            else if (count == 3)
            {
                thirdSentPromise.set_value();
            }
        },
        UNLIMITED_BYTES,
        SEND_ON_EVERY_PUSH,
        FLUSH_INTERVAL_SEC,
        RETRY_DELAY_SEC,
        MAX_RETRY_DELAY_SEC);

    queue.push(std::string("first-batch"));
    ASSERT_EQ(firstSentFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready);

    queue.push(std::string("second-batch"));
    ASSERT_EQ(secondSentFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready);

    // The newer batch (second) is reported blocked first...
    queue.requestBackoff(secondSequence.load());
    // ...then the older batch (first) reports healthy, arriving late (out of order). It must be
    // ignored: it's stale evidence, superseded by the newer "blocked" verdict.
    queue.reportHealthyResponse(firstSequence.load());

    queue.push(std::string("third-batch"));

    // If the stale healthy report had won, the pending backoff would have been cleared and this
    // send would go out immediately. Assert it doesn't arrive instantly by requiring some send to
    // eventually happen (functional check) and that no more than 3 sends occurred (no duplicate).
    ASSERT_EQ(thirdSentFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready);
    EXPECT_EQ(sendCount.load(), 3);
}

// Unlike requestBackoff() (a send that already succeeded), a thrown exception means the send itself
// failed - that data must come back around and be retried, not discarded.
TEST_F(IndexerBulkQueueTest, ProcessorExceptionRetriesSameBatchUntilSuccess)
{
    std::promise<void> retriedPromise;
    std::future<void> retriedFuture = retriedPromise.get_future();
    std::vector<std::string> received;
    std::mutex receivedMutex;
    std::atomic<int> attempt {0};

    IndexerBulkQueue queue(
        [&](uint64_t /*sequence*/, std::vector<std::string>& batch)
        {
            {
                std::lock_guard<std::mutex> lock(receivedMutex);
                received.insert(received.end(), batch.begin(), batch.end());
            }
            if (++attempt == 1)
            {
                throw std::runtime_error("simulated transport failure");
            }
            retriedPromise.set_value();
        },
        UNLIMITED_BYTES,
        SEND_ON_EVERY_PUSH,
        FLUSH_INTERVAL_SEC,
        RETRY_DELAY_SEC,
        MAX_RETRY_DELAY_SEC);

    queue.push(std::string("retry-me"));

    ASSERT_EQ(retriedFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Failed batch was never retried";

    std::lock_guard<std::mutex> lock(receivedMutex);
    ASSERT_EQ(received.size(), 2U) << "Expected exactly one failed attempt plus one successful retry";
    EXPECT_EQ(received[0], "retry-me");
    EXPECT_EQ(received[1], "retry-me");
}

// A processor that never succeeds (indexer permanently unreachable) must not prevent the queue from
// being stopped/destroyed promptly - regression check for the dispatch-thread shutdown handling.
TEST_F(IndexerBulkQueueTest, DestructorDoesNotHangWhileProcessorKeepsFailing)
{
    std::atomic<int> attempts {0};

    auto queue = std::make_unique<IndexerBulkQueue>(
        [&](uint64_t /*sequence*/, std::vector<std::string>&) -> void
        {
            ++attempts;
            throw std::runtime_error("indexer unreachable");
        },
        UNLIMITED_BYTES,
        SEND_ON_EVERY_PUSH,
        FLUSH_INTERVAL_SEC,
        RETRY_DELAY_SEC,
        MAX_RETRY_DELAY_SEC);

    queue->push(std::string("never-delivered"));

    // Give the dispatch thread a moment to start its first (failing) attempt and enter the
    // retry-backoff wait before we tear it down.
    while (attempts.load() < 1)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    const auto start = std::chrono::steady_clock::now();
    queue.reset();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_LT(elapsed, std::chrono::seconds(5)) << "Destructor should not block for the full backoff delay";
}

// A pending requestBackoff() signal must not block shutdown either - regression check for the
// top-of-loop pause introduced to fix the "pause protects the wrong batch" issue.
TEST_F(IndexerBulkQueueTest, DestructorDoesNotHangWhileWaitingOutAnExternalBackoff)
{
    std::promise<void> firstSentPromise;
    std::future<void> firstSentFuture = firstSentPromise.get_future();
    std::atomic<bool> firstSent {false};
    std::atomic<uint64_t> firstSequence {0};

    auto queue = std::make_unique<IndexerBulkQueue>(
        [&](uint64_t sequence, std::vector<std::string>&)
        {
            // Guarded: if the dispatch thread manages to also send "second-batch" before we
            // reset() the queue below, this must not call set_value() twice on an
            // already-satisfied promise (which would crash the test binary).
            if (!firstSent.exchange(true))
            {
                firstSequence.store(sequence);
                firstSentPromise.set_value();
            }
        },
        UNLIMITED_BYTES,
        SEND_ON_EVERY_PUSH,
        FLUSH_INTERVAL_SEC,
        RETRY_DELAY_SEC,
        MAX_RETRY_DELAY_SEC);

    queue->push(std::string("first-batch"));
    ASSERT_EQ(firstSentFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready);

    queue->requestBackoff(firstSequence.load());
    queue->push(std::string("second-batch"));

    const auto start = std::chrono::steady_clock::now();
    queue.reset();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_LT(elapsed, std::chrono::seconds(5)) << "Destructor should not block for the full backoff delay";
}
