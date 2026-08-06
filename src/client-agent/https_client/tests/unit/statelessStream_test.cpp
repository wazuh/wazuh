/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fakeSysSeams.hpp"
#include "mockCallbackSink.hpp"
#include "mockHttpPerformer.hpp"
#include "statelessStream.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <string>
#include <vector>

using ::testing::_;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;

namespace
{
    HttpResponse response(TransportStatus status, long code, long retryAfter = 0)
    {
        HttpResponse value;
        value.status = status;
        value.httpCode = code;
        value.retryAfterSeconds = retryAfter;
        return value;
    }

    class StatelessStreamTest : public ::testing::Test
    {
        protected:
            StatelessStreamTest()
                : m_signer("001", m_keyProvider)
                , m_config(makeConfig())
                , m_authGate(m_sink, [] {})
            , m_stream(m_config, m_performer, m_signer, m_clock, m_random, m_sink, m_authGate)
            {
            }

            static ModuleConfig makeConfig()
            {
                hc_config_t config {};
                std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
                std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
                config.verify_mode = HC_VERIFY_NONE;
                // 35-byte H line + 16 bytes available for E lines.
                config.batch_size_bytes = 51;
                config.batch_interval_ms = 5000;
                config.buffer_cap_multiplier = 4;
                return ModuleConfig::fromC(config);
            }

            StatelessStream::SubmissionResult submitResult(const std::string& frame)
            {
                return m_stream.submit(reinterpret_cast<const uint8_t*>(frame.data()), frame.size());
            }

            bool submit(const std::string& frame)
            {
                return submitResult(frame).accepted;
            }

            ConfigKeyProvider m_keyProvider {"000102030405060708090a0b0c0d0e0f"};
            CmacSigner m_signer;
            ModuleConfig m_config;
            FakeClock m_clock;
            ScriptedRandom m_random {{0.0}}; // Zero jitter keeps deferrals deterministic.
            NiceMock<MockCallbackSink> m_sink;
            MockHttpPerformer m_performer;
            AuthGate m_authGate;
            FakeWaiter m_waiter;
            StatelessStream m_stream;
    };
} // namespace

TEST_F(StatelessStreamTest, NoFlushWhenEmpty)
{
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    m_stream.tick(m_waiter, false);
}

TEST_F(StatelessStreamTest, FlushOnSizeThresholdSendsHeaderAndEvents)
{
    std::string sentBody;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        sentBody.assign(reinterpret_cast<const char*>(spec.body), spec.bodyLength);
        EXPECT_EQ("/stateless", spec.target);
        return response(TransportStatus::Ok, 200);
    }));

    EXPECT_FALSE(submitResult("event-aaaa").shouldWakeSender);
    EXPECT_TRUE(submitResult("event-bbbb").shouldWakeSender);
    m_stream.tick(m_waiter, false);

    // The configured limit includes the 35-byte H line. The remaining
    // 16-byte event budget caps this POST to the first whole event.
    EXPECT_EQ(0u, sentBody.find("H {\"wazuh\":{\"agent\":{\"id\":\"001\"}}}\n"));
    EXPECT_NE(std::string::npos, sentBody.find("E event-aaaa\n"));
    EXPECT_EQ(std::string::npos, sentBody.find("E event-bbbb\n"));
    EXPECT_LE(sentBody.size(), m_config.batchSizeBytes);
}

TEST_F(StatelessStreamTest, TheHeaderLineEscapesTheAgentId)
{
    // The H line is JSON: an id carrying a quote must not be able to close the
    // string it sits in and rewrite the rest of the object.
    hc_config_t raw {};
    std::strncpy(raw.server_host, "127.0.0.1", sizeof(raw.server_host) - 1);
    std::strncpy(raw.agent_id, R"(0"01)", sizeof(raw.agent_id) - 1);
    raw.verify_mode = HC_VERIFY_NONE;
    const ModuleConfig config = ModuleConfig::fromC(raw);
    StatelessStream stream {config,   m_performer, m_signer, m_clock,
                            m_random, m_sink,      m_authGate};

    std::string sentBody;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        sentBody.assign(reinterpret_cast<const char*>(spec.body), spec.bodyLength);
        return response(TransportStatus::Ok, 200);
    }));

    const std::string frame = "1:/loc:escaped";
    stream.submit(reinterpret_cast<const uint8_t*>(frame.data()), frame.size());
    stream.tick(m_waiter, true);

    EXPECT_EQ(0u, sentBody.find(R"(H {"wazuh":{"agent":{"id":"0\"01"}}})"));
}

TEST_F(StatelessStreamTest, SuccessConsumesTheSentPrefix)
{
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 200)));
    submit("event-aaaa");
    submit("event-bbbb");
    m_stream.tick(m_waiter, false);
    // The remaining event is below the threshold, so a second immediate tick
    // does not resend the consumed prefix or flush the retained tail early.
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    m_stream.tick(m_waiter, false);
}

TEST_F(StatelessStreamTest, ForceFlushesEvenBelowThreshold)
{
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 200)));
    submit("tiny"); // Well under the 16-byte event budget.
    m_stream.tick(m_waiter, true);
}

TEST_F(StatelessStreamTest, PayloadTooLargeKeepsEventsInOrderAndHalves)
{
    // 413 must NOT drop a multi-event batch (#37835): the events stay, in
    // order, and the effective payload halves so the next flush is smaller.
    std::vector<std::string> bodies;
    EXPECT_CALL(m_performer, perform(_))
    .WillRepeatedly(Invoke(
                        [&](const HttpRequestSpec & spec)
    {
        bodies.emplace_back(reinterpret_cast<const char*>(spec.body), spec.bodyLength);
        // First send (full 16-byte event budget) 413s; smaller retries succeed.
        return response(TransportStatus::Ok, bodies.size() == 1 ? 413 : 200);
    }));

    submit("aaaa"); // "E aaaa\n" = 7 bytes.
    submit("bbbb"); // + 7 = 14 bytes; two events in the batch.
    m_stream.tick(m_waiter, true); // 413: batch retained, payload halves to 8.
    m_stream.tick(m_waiter, true); // Smaller batch (fits 8): first event.
    m_stream.tick(m_waiter, true); // Remaining event.

    ASSERT_GE(bodies.size(), 3u);
    // Nothing lost, order preserved across the split sends.
    EXPECT_NE(std::string::npos, bodies[1].find("E aaaa\n"));
    EXPECT_NE(std::string::npos, bodies[2].find("E bbbb\n"));

    // All delivered: a further tick sends nothing.
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    m_stream.tick(m_waiter, true);
}

TEST_F(StatelessStreamTest, SuccessRampsThePayloadBackUp)
{
    // After a 413 halves the payload, successful sends double it back, so the
    // batch grows again toward the configured max.
    int calls = 0;
    std::vector<size_t> bodySizes;
    EXPECT_CALL(m_performer, perform(_))
    .WillRepeatedly(Invoke(
                        [&](const HttpRequestSpec & spec)
    {
        bodySizes.push_back(spec.bodyLength);
        return response(TransportStatus::Ok, ++calls == 1 ? 413 : 200);
    }));

    for (int index = 0; index < 6; index++)
    {
        submit("cccc");
    }

    for (int tick = 0; tick < 6; tick++)
    {
        m_stream.tick(m_waiter, true);
    }

    // The post-413 batches start small and grow as the payload ramps back.
    ASSERT_GE(bodySizes.size(), 3u);
    EXPECT_LT(bodySizes[1], bodySizes[2]); // Second success carries more than the first.
}

TEST_F(StatelessStreamTest, SingleOversizedEventIs413DroppedAndCounted)
{
    // A lone event that 413s cannot be split: drop it (only unsalvageable
    // case) so the stream is not wedged.
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 413)));
    submit("only-one-event");
    m_stream.tick(m_waiter, true); // 413 on a single-event batch: dropped.

    EXPECT_EQ(1u, m_stream.droppedEvents());
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    m_stream.tick(m_waiter, true); // Nothing left.
}

TEST_F(StatelessStreamTest, ASingleOversized413DoesNotShrinkTheBudget)
{
    // The batch size was not what the manager rejected -- one event was simply
    // too big. Halving here would only cost a round trip before the next event
    // is tried, so the budget must survive the drop.
    hc_config_t raw {};
    std::strncpy(raw.server_host, "127.0.0.1", sizeof(raw.server_host) - 1);
    std::strncpy(raw.agent_id, "001", sizeof(raw.agent_id) - 1);
    raw.verify_mode = HC_VERIFY_NONE;
    raw.batch_size_bytes = 200; // 35-byte H line + 165 bytes of E lines.
    raw.batch_interval_ms = 5000;
    raw.buffer_cap_multiplier = 4;
    const ModuleConfig config = ModuleConfig::fromC(raw);
    StatelessStream stream {config,   m_performer, m_signer, m_clock,
                            m_random, m_sink,      m_authGate};

    const auto push = [&stream](const std::string & frame)
    {
        stream.submit(reinterpret_cast<const uint8_t*>(frame.data()), frame.size());
    };

    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 413)));
    push("only-one-event");
    stream.tick(m_waiter, true);
    EXPECT_EQ(1u, stream.droppedEvents());

    // 12 x 13 bytes = 156, inside the untouched 165-byte event budget. A halved
    // budget (100 - 35 = 65) would have cut this to five events.
    std::string sentBody;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        sentBody.assign(reinterpret_cast<const char*>(spec.body), spec.bodyLength);
        return response(TransportStatus::Ok, 200);
    }));

    for (int index = 0; index < 12; index++)
    {
        push("event-1234");
    }

    stream.tick(m_waiter, true);
    EXPECT_EQ(12u, std::count(sentBody.begin(), sentBody.end(), '\n') - 1); // Minus the H line.
}

TEST_F(StatelessStreamTest, PausedGateHoldsEventsWithoutSending)
{
    m_authGate.reportAuthFailure(); // 401 elsewhere: pause.
    submit("event-aaaa");
    submit("event-bbbb");
    EXPECT_CALL(m_performer, perform(_)).Times(0); // No send while paused.
    m_stream.tick(m_waiter, true);

    // Once released, the retained events flush.
    m_authGate.release();
    EXPECT_CALL(m_performer, perform(_)).WillRepeatedly(Return(response(TransportStatus::Ok, 200)));
    m_stream.tick(m_waiter, true);
    m_stream.tick(m_waiter, true);
}

TEST_F(StatelessStreamTest, Non413PermanentStillDropsTheBatch)
{
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 400)));
    submit("event-aaaa");
    submit("event-bbbb");
    m_stream.tick(m_waiter, false);
    // 400: retrying identical bytes cannot help, so the batch is dropped.
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    m_stream.tick(m_waiter, false);
}

TEST_F(StatelessStreamTest, RetryableKeepsTheBatch)
{
    EXPECT_CALL(m_performer, perform(_))
    .WillRepeatedly(Return(response(TransportStatus::Timeout, 0)));
    submit("event-aaaa");
    submit("event-bbbb");
    m_stream.tick(m_waiter, true); // force; the batch stays after failure.

    // A later forced tick still has the batch to send.
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 200)));
    m_stream.tick(m_waiter, true);
}

TEST_F(StatelessStreamTest, BackPressureKeepsTheBatchForALaterTick)
{
    // RetrySender owns the Retry-After wait; with the waiter unscripted the
    // send returns without success, so the batch survives for a later flush.
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 503, 2)));
    submit("event-aaaa");
    submit("event-bbbb");
    m_stream.tick(m_waiter, false);

    // The batch is still present: a later tick can send it successfully.
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 200)));
    m_stream.tick(m_waiter, true);
}

TEST_F(StatelessStreamTest, BackPressureIsRetriedInsideOneFlushWhenWaiterAllows)
{
    // With the waiter scripted to keep running, one flush waits out the
    // Retry-After and retries within the same tick.
    m_waiter.script({true});
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 503, 2)))
    .WillOnce(Return(response(TransportStatus::Ok, 200)));
    submit("event-aaaa");
    submit("event-bbbb");
    m_stream.tick(m_waiter, false);

    // Consumed on success: nothing left to send.
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    m_stream.tick(m_waiter, false);
}

TEST_F(StatelessStreamTest, BufferLevelWalksTheLegacyLadder)
{
    // cap = 51 * 4 = 204 bytes; "E event-1234\n" is 13 bytes, so each event is
    // ~6%. The default ladder warns at 90% (184 bytes = the 15th event) and
    // reports FULL on the first drop-newest rejection (the 16th would need 208).
    ::testing::InSequence sequence;
    EXPECT_CALL(m_sink, onBufferLevel(HC_BUFFER_WARNING)).Times(1);
    EXPECT_CALL(m_sink, onBufferLevel(HC_BUFFER_FULL)).Times(1);

    for (int index = 0; index < 16; index++)
    {
        submit("event-1234");
    }

    EXPECT_EQ(HC_BUFFER_FULL, m_stream.level());
}

TEST_F(StatelessStreamTest, BufferLevelHoldsWarningUntilTheNormalMark)
{
    // 15 events = 195 bytes = 95% -> WARNING. Draining to 12 events (156 bytes,
    // 76%) is under the warn mark but above normal_level (70%), so the legacy
    // ladder stays in WARNING without announcing anything.
    EXPECT_CALL(m_sink, onBufferLevel(HC_BUFFER_WARNING)).Times(1);
    EXPECT_CALL(m_sink, onBufferLevel(HC_BUFFER_NORMAL)).Times(0);

    for (int index = 0; index < 15; index++)
    {
        submit("event-1234");
    }

    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 200)));
    m_stream.tick(m_waiter, true); // Sends one event: 14 left = 182 bytes = 89%.
    EXPECT_EQ(HC_BUFFER_WARNING, m_stream.level());
}

TEST_F(StatelessStreamTest, FloodOnlyAfterFullHoldsForTheTolerance)
{
    ::testing::InSequence sequence;
    EXPECT_CALL(m_sink, onBufferLevel(HC_BUFFER_WARNING)).Times(1);
    EXPECT_CALL(m_sink, onBufferLevel(HC_BUFFER_FULL)).Times(1);
    EXPECT_CALL(m_sink, onBufferLevel(HC_BUFFER_FLOOD)).Times(1);

    for (int index = 0; index < 16; index++) // Fills, then the first drop.
    {
        submit("event-1234");
    }

    submit("event-1234"); // Still dropping, but inside the tolerance window.
    m_clock.advance(std::chrono::seconds {15});
    submit("event-1234"); // Full for 15 s: flooded.
    EXPECT_EQ(HC_BUFFER_FLOOD, m_stream.level());
}

TEST_F(StatelessStreamTest, KeepsDrainingWhileTheBacklogStaysAboveTheThreshold)
{
    // The size condition is edge-triggered at submit(), so a tick that leaves
    // the buffer above the threshold must ask to run again immediately --
    // otherwise a full buffer gives up a whole interval per request.
    EXPECT_CALL(m_performer, perform(_)).WillRepeatedly(Return(response(TransportStatus::Ok, 200)));

    for (int index = 0; index < 6; index++)
    {
        submit("event-1234");
    }

    EXPECT_EQ(std::chrono::milliseconds::zero(), m_stream.tick(m_waiter, false));

    // Drain the rest; the last flush empties the buffer, so the stream goes
    // back to waiting out the batch interval.
    std::chrono::milliseconds delay {0};

    for (int index = 0; index < 6 && delay == std::chrono::milliseconds::zero(); index++)
    {
        delay = m_stream.tick(m_waiter, false);
    }

    EXPECT_EQ(std::chrono::milliseconds {m_config.batchIntervalMs}, delay);
}

TEST_F(StatelessStreamTest, AFailedFlushFallsBackToTheBatchInterval)
{
    // Never loop back-to-back on failure: that would hammer a manager that is
    // rejecting or backing off.
    EXPECT_CALL(m_performer, perform(_))
    .WillRepeatedly(Return(response(TransportStatus::Timeout, 0)));

    for (int index = 0; index < 6; index++)
    {
        submit("event-1234");
    }

    EXPECT_EQ(std::chrono::milliseconds {m_config.batchIntervalMs}, m_stream.tick(m_waiter, false));
}

TEST_F(StatelessStreamTest, DrainUsesASingleAttemptWithinTheDrainWindow)
{
    // The drain runs on the stop path with a waiter that is never stopped, so
    // it must not walk the retry ladder: one attempt per batch, bounded by the
    // drain window, exactly like ControlStream::drainStep.
    uint32_t attempts = 0;
    EXPECT_CALL(m_performer, perform(_))
    .WillRepeatedly(Invoke(
                        [&](const HttpRequestSpec & spec)
    {
        attempts++;
        EXPECT_EQ(m_config.drainTimeoutMs, spec.timeoutMs);
        return response(TransportStatus::Timeout, 0);
    }));

    m_waiter.script({true, true, true, true, true}); // Would allow retries.
    submit("event-aaaa");
    m_stream.drain(m_waiter);
    EXPECT_EQ(1u, attempts);
}

TEST_F(StatelessStreamTest, DrainStopsAtTheIterationBound)
{
    // A manager that keeps accepting must not let the drain run forever either.
    uint32_t attempts = 0;
    EXPECT_CALL(m_performer, perform(_))
    .WillRepeatedly(Invoke(
                        [&](const HttpRequestSpec&)
    {
        attempts++;
        return response(TransportStatus::Ok, 200);
    }));

    for (int index = 0; index < 15; index++)
    {
        submit("event-1234");
    }

    m_stream.drain(m_waiter);
    EXPECT_EQ(m_config.bufferCapMultiplier + 1, attempts);
}

TEST_F(StatelessStreamTest, DropNewestReturnsFalseAtCap)
{
    // cap = 204 bytes; fill it, then later appends are dropped and counted.
    uint64_t dropped = 0;

    for (int index = 0; index < 20; index++)
    {
        if (!submit("event-1234"))
        {
            dropped++;
        }
    }

    EXPECT_GT(dropped, 0u);
    EXPECT_EQ(dropped, m_stream.droppedEvents());
}
