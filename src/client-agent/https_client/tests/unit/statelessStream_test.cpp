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

#include <cstring>
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
                config.batch_size_bytes = 16; // Small so a couple of events trigger a flush.
                config.batch_interval_ms = 5000;
                config.buffer_cap_multiplier = 4;
                return ModuleConfig::fromC(config);
            }

            bool submit(const std::string& frame)
            {
                return m_stream.submit(reinterpret_cast<const uint8_t*>(frame.data()), frame.size());
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

    submit("event-aaaa");
    submit("event-bbbb"); // Pushes the buffer past the 16-byte max payload.
    m_stream.tick(m_waiter, false);

    // The 16-byte max payload caps one POST to the first whole event; the
    // second follows in the next flush.
    EXPECT_EQ(0u, sentBody.find("H {\"wazuh\":{\"agent\":{\"id\":\"001\"}}}\n"));
    EXPECT_NE(std::string::npos, sentBody.find("E event-aaaa\n"));
    EXPECT_EQ(std::string::npos, sentBody.find("E event-bbbb\n"));
}

TEST_F(StatelessStreamTest, SuccessConsumesTheBatch)
{
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 200)));
    submit("event-aaaa");
    submit("event-bbbb");
    m_stream.tick(m_waiter, false);
    // Nothing left: a second tick sends nothing.
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    m_stream.tick(m_waiter, false);
}

TEST_F(StatelessStreamTest, ForceFlushesEvenBelowThreshold)
{
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 200)));
    submit("tiny"); // Well under 16 bytes.
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
        // First send (full 16-byte budget) 413s; smaller retries succeed.
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

    EXPECT_CALL(m_performer, perform(_)).Times(0);
    m_stream.tick(m_waiter, true); // Nothing left.
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

TEST_F(StatelessStreamTest, BufferLevelEmittedOnlyOnChange)
{
    // cap = 16 * 4 = 64 bytes. Cross 50% (32 bytes) to reach WARNING.
    ::testing::InSequence sequence;
    EXPECT_CALL(m_sink, onBufferLevel(HC_BUFFER_WARNING)).Times(1);

    for (int index = 0; index < 3; index++) // 3 x 13-byte lines = 39 bytes.
    {
        submit("event-1234"); // "E event-1234\n" = 13 bytes.
    }
}

TEST_F(StatelessStreamTest, DropNewestReturnsFalseAtCap)
{
    // cap = 64 bytes; fill it, then the next append is dropped.
    bool anyDropped = false;

    for (int index = 0; index < 20; index++)
    {
        if (!submit("event-1234"))
        {
            anyDropped = true;
        }
    }

    EXPECT_TRUE(anyDropped);
}
