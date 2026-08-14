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
#include "mockFileCompressor.hpp"
#include "mockHttpPerformer.hpp"
#include "mockSpoolFactory.hpp"
#include "shared_modules/sync_protocol/include/sync_session_wire.hpp"
#include "statefulStream.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>
#include <fstream>

using ::testing::_;
using ::testing::ByMove;
using ::testing::Contains;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Not;
using ::testing::Return;

namespace
{
    HttpResponse response(TransportStatus status, long code, const std::string& body = {})
    {
        HttpResponse value;
        value.status = status;
        value.httpCode = code;
        value.body = body;
        return value;
    }

    bool fileExists(const std::string& path)
    {
        return std::ifstream {path}.good();
    }

    std::unique_ptr<SpoolFile> makeSpoolAt(const std::string& path, const std::string& contents)
    {
        std::ofstream file {path, std::ios::binary};
        file << contents;
        file.close();
        return std::make_unique<SpoolFile>(path);
    }

    class StatefulStreamTest : public ::testing::Test
    {
        protected:
            StatefulStreamTest()
                : m_signer("001", m_keyProvider)
                , m_config(makeConfig())
                , m_authGate(m_sink, [] {})
            , m_stream(m_config, m_performer, m_signer, m_clock, m_random, m_spoolFactory, m_sink,
                       m_authGate, m_compressionGate, m_fileCompressor)
            {
                // By default the spool factory writes the bytes to a unique temp
                // file (submit spools now, so every submit needs a real file).
                ON_CALL(m_spoolFactory, spool(_, _))
                .WillByDefault(Invoke([this](const uint8_t* buffer, size_t length)
                {
                    const std::string path =
                        ::testing::TempDir() + "hc_sf_" + std::to_string(m_spoolCounter++) + ".tmp";
                    return makeSpoolAt(path, std::string(reinterpret_cast<const char*>(buffer), length));
                }));
            }

            static ModuleConfig makeConfig()
            {
                hc_config_t config {};
                std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
                std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
                config.verify_mode = HC_VERIFY_NONE;
                return ModuleConfig::fromC(config);
            }

            bool submit(const std::string& id, const std::string& body)
            {
                return m_stream.submit(id, reinterpret_cast<const uint8_t*>(body.data()), body.size());
            }

            ConfigKeyProvider m_keyProvider {"000102030405060708090a0b0c0d0e0f"};
            CmacSigner m_signer;
            ModuleConfig m_config;
            FakeClock m_clock;
            ScriptedRandom m_random {{0.0}};
            NiceMock<MockSpoolFactory> m_spoolFactory;
            NiceMock<MockCallbackSink> m_sink;
            MockHttpPerformer m_performer;
            AuthGate m_authGate;
            CompressionGate m_compressionGate;
            NiceMock<MockFileCompressor> m_fileCompressor;
            FakeWaiter m_waiter;
            StatefulStream m_stream;
            int m_spoolCounter {0};

            void expectNoSend()
            {
                EXPECT_CALL(m_performer, perform(_)).Times(0);
            }
    };
} // namespace

TEST_F(StatefulStreamTest, StepWithoutPendingDoesNothing)
{
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    EXPECT_FALSE(m_stream.step(m_waiter));
}

TEST_F(StatefulStreamTest, PausedGateHoldsQueuedSessions)
{
    m_authGate.reportAuthFailure(); // 401 elsewhere: pause.
    EXPECT_TRUE(submit("sess-1", "FULLSESSION:fim:body"));
    expectNoSend();
    EXPECT_FALSE(m_stream.step(m_waiter)); // Paused: the session waits.

    // Released: the session is sent.
    m_authGate.release();
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 200, "{}")));
    EXPECT_TRUE(m_stream.step(m_waiter));
}

TEST_F(StatefulStreamTest, SessionIsSpooledAtSubmitAndStreamedWithSessionHeader)
{
    const std::string path = ::testing::TempDir() + "hc_stateful_1.tmp";
    // Spooling now happens during submit(), not during the send.
    EXPECT_CALL(m_spoolFactory, spool(_, 8u))
    .WillOnce(Return(ByMove(makeSpoolAt(path, "12345678"))));

    std::vector<std::string> headers;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        headers = spec.headers;
        EXPECT_EQ("/stateful", spec.target);
        EXPECT_EQ(path, spec.bodyFilePath); // Streamed from the spooled file.
        EXPECT_EQ(8u, spec.bodyFileSize);
        return response(TransportStatus::Ok, 200, R"({"itemsProcessed":42})");
    }));
    EXPECT_CALL(m_sink, onSyncResponse("sess-1", 200, R"({"itemsProcessed":42})"));

    ASSERT_TRUE(submit("sess-1", "12345678"));
    EXPECT_TRUE(m_stream.step(m_waiter));

    ASSERT_FALSE(headers.empty());
    EXPECT_NE(headers.end(), std::find(headers.begin(), headers.end(), "X-Session-Id: sess-1"));
    EXPECT_FALSE(fileExists(path)); // Deleted after the session was sent.
}

TEST_F(StatefulStreamTest, SubmitFileAdoptsAnAlreadySpooledSessionAndDeletesIt)
{
    // The intake streams a session off the local socket into this file; the
    // stream adopts it (no re-spool) and deletes it after sending.
    const std::string path = ::testing::TempDir() + "hc_intake_session.bin";
    {
        std::ofstream file {path, std::ios::binary};    // 200 KB > 64 KB
        file << std::string(200000, 'Z');
    }
    ASSERT_TRUE(fileExists(path));

    EXPECT_CALL(m_spoolFactory, spool(_, _)).Times(0); // submitFile never re-spools.
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ(path, spec.bodyFilePath);
        EXPECT_EQ(200000u, spec.bodyFileSize); // The full session, well past the 64 KB cap.
        return response(TransportStatus::Ok, 200, R"({"itemsProcessed":199975})");
    }));
    EXPECT_CALL(m_sink, onSyncResponse("intake-1", 200, _));

    ASSERT_TRUE(m_stream.submitFile("intake-1", path, 200000));
    EXPECT_TRUE(m_stream.step(m_waiter));
    EXPECT_FALSE(fileExists(path)); // Adopted file removed after send.
}

TEST_F(StatefulStreamTest, SameSessionIdAcrossRetries)
{
    const std::string path = ::testing::TempDir() + "hc_stateful_retry.tmp";
    EXPECT_CALL(m_spoolFactory, spool(_, _))
    .WillOnce(Return(ByMove(makeSpoolAt(path, "body"))));

    std::vector<std::string> firstHeaders;
    std::vector<std::string> secondHeaders;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        firstHeaders = spec.headers;
        return response(TransportStatus::Ok, 500);
    }))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        secondHeaders = spec.headers;
        return response(TransportStatus::Ok, 200);
    }));
    m_waiter.script({true});

    submit("sess-retry", "body");
    m_stream.step(m_waiter);

    auto sessionHeader = [](const std::vector<std::string>& headers)
    {
        for (const auto& header : headers)
        {
            if (header.rfind("X-Session-Id: ", 0) == 0)
            {
                return header;
            }
        }

        return std::string {};
    };
    EXPECT_EQ("X-Session-Id: sess-retry", sessionHeader(firstHeaders));
    EXPECT_EQ("X-Session-Id: sess-retry", sessionHeader(secondHeaders));
}

TEST_F(StatefulStreamTest, SpoolFailureAtSubmitIsRejectedAndNothingIsQueued)
{
    EXPECT_CALL(m_spoolFactory, spool(_, _)).WillOnce(Return(ByMove(nullptr)));
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    EXPECT_CALL(m_sink, onSyncResponse(_, _, _)).Times(0);

    EXPECT_FALSE(submit("sess-x", "body")); // Rejected up front.
    EXPECT_FALSE(m_stream.hasPending());
    EXPECT_FALSE(m_stream.step(m_waiter));
}

TEST_F(StatefulStreamTest, FailureOutcomeCrossesTheSink)
{
    const std::string path = ::testing::TempDir() + "hc_stateful_fail.tmp";
    EXPECT_CALL(m_spoolFactory, spool(_, _)).WillOnce(Return(ByMove(makeSpoolAt(path, "body"))));
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 413)));
    EXPECT_CALL(m_sink, onSyncResponse("sess-perm", 413, _));

    submit("sess-perm", "body");
    EXPECT_TRUE(m_stream.step(m_waiter));
}

TEST_F(StatefulStreamTest, QueueIsFifo)
{
    EXPECT_CALL(m_performer, perform(_)).WillRepeatedly(Return(response(TransportStatus::Ok, 200)));

    ::testing::InSequence sequence;
    EXPECT_CALL(m_sink, onSyncResponse("first", 200, _));
    EXPECT_CALL(m_sink, onSyncResponse("second", 200, _));

    submit("first", "a");
    submit("second", "bb");
    EXPECT_TRUE(m_stream.hasPending());
    m_stream.step(m_waiter);
    m_stream.step(m_waiter);
    EXPECT_FALSE(m_stream.hasPending());
}

TEST_F(StatefulStreamTest, BoundedQueueRejectsOverflow)
{
    // Fill the queue to its cap without stepping (default spool succeeds), then
    // the next submit is rejected.
    bool rejected = false;

    for (int index = 0; index < 200; index++)
    {
        if (!submit("sess-" + std::to_string(index), "x"))
        {
            rejected = true;
            break;
        }
    }

    EXPECT_TRUE(rejected);
}

TEST_F(StatefulStreamTest, SessionIdsThatCouldSplitTheHeaderAreRejected)
{
    // The id crosses a process boundary and then becomes X-Session-Id, so
    // anything that could break out of that header must never be queued.
    expectNoSend();
    EXPECT_CALL(m_spoolFactory, spool(_, _)).Times(0); // Rejected before spooling.

    EXPECT_FALSE(submit("sess\r\nX-Injected: 1", "body"));
    EXPECT_FALSE(submit("sess\ninjected", "body"));
    EXPECT_FALSE(submit("sess\rinjected", "body"));
    EXPECT_FALSE(submit(std::string {"sess\0hidden", 11}, "body"));
    EXPECT_FALSE(submit("sess with spaces", "body"));
    EXPECT_FALSE(submit("", "body"));
    EXPECT_FALSE(submit(std::string(SESSION_ID_MAX_LENGTH + 1, 'a'), "body"));
    EXPECT_FALSE(m_stream.hasPending());
}

TEST_F(StatefulStreamTest, TheSessionIdShapesProducersUseAreAccepted)
{
    // The guard must not be so tight that it rejects real ids: UUIDs and
    // "<module>.<phase>-<counter>" both pass.
    EXPECT_TRUE(submit("3f2504e0-4f89-11d3-9a0c-0305e82c3301", "body"));
    EXPECT_TRUE(submit("fim.full_sync-42", "body"));
    EXPECT_TRUE(m_stream.hasPending());
}

TEST_F(StatefulStreamTest, AdoptedSessionFilesAreIdCheckedToo)
{
    // submitFile() takes the same gate: the ABI can hand over a spooled file
    // with any id at all.
    EXPECT_FALSE(m_stream.submitFile("sess\r\nX-Injected: 1", "/tmp/hc_never_read", 4));
    EXPECT_FALSE(m_stream.hasPending());
    EXPECT_TRUE(m_stream.submitFile("adopted-1", "/tmp/hc_never_read", 4));
}

namespace
{
    ModuleConfig makeCompressingConfig()
    {
        hc_config_t config {};
        std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
        std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
        config.verify_mode = HC_VERIFY_NONE;
        config.https_compression_enabled = 1;
        return ModuleConfig::fromC(config);
    }
} // namespace

TEST_F(StatefulStreamTest, CompressionEnabledCompressesOnceAndCleansUpTheTempFile)
{
    // compressionEnabled is captured by RetrySender at construction time, so
    // this needs its own StatefulStream (the fixture's m_stream was built from
    // makeConfig()'s default-off config) -- same reason retrySender_test.cpp
    // constructs a separate RetrySender per compression test rather than
    // mutating the fixture's config after the fact.
    ModuleConfig compressingConfig = makeCompressingConfig();
    StatefulStream compressing {compressingConfig,  m_performer,        m_signer,
                                m_clock,            m_random,           m_spoolFactory,
                                m_sink,             m_authGate,         m_compressionGate,
                                m_fileCompressor};

    const std::string originalPath = ::testing::TempDir() + "hc_stateful_compress_src.tmp";
    EXPECT_CALL(m_spoolFactory, spool(_, 4u))
    .WillOnce(Return(ByMove(makeSpoolAt(originalPath, "body"))));

    const std::string compressedPath = ::testing::TempDir() + "hc_stateful_compress_out.tmp";
    {
        std::ofstream out {compressedPath, std::ios::binary};
        out << "Z"; // Placeholder compressed bytes; only the path/size matter to this test.
    }
    EXPECT_CALL(m_fileCompressor, compress(originalPath, 4u, _, _))
    .WillOnce(Return(ByMove(std::make_optional(
                                std::make_pair(std::make_unique<SpoolFile>(compressedPath), uint64_t {1})))));

    std::string seenBodyFilePath;
    std::vector<std::string> seenHeaders;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        seenBodyFilePath = spec.bodyFilePath;
        seenHeaders = spec.headers;
        return response(TransportStatus::Ok, 200, "{}");
    }));

    ASSERT_TRUE(compressing.submit("sess-1", reinterpret_cast<const uint8_t*>("body"), 4));
    EXPECT_TRUE(compressing.step(m_waiter));

    EXPECT_EQ(compressedPath, seenBodyFilePath); // Sent the compressed sibling, not the original.
    EXPECT_THAT(seenHeaders, Contains("Content-Encoding: zstd"));
    EXPECT_FALSE(fileExists(compressedPath)); // Cleaned up once sendSession() returned.
    EXPECT_FALSE(fileExists(originalPath));   // The session's own spool file too (normal cleanup).
}

TEST_F(StatefulStreamTest, CompressionFailureFallsBackToTheOriginalFileUncompressed)
{
    ModuleConfig compressingConfig = makeCompressingConfig();
    StatefulStream compressing {compressingConfig,  m_performer,        m_signer,
                                m_clock,            m_random,           m_spoolFactory,
                                m_sink,             m_authGate,         m_compressionGate,
                                m_fileCompressor};

    const std::string originalPath = ::testing::TempDir() + "hc_stateful_compress_fail.tmp";
    EXPECT_CALL(m_spoolFactory, spool(_, 4u))
    .WillOnce(Return(ByMove(makeSpoolAt(originalPath, "body"))));
    EXPECT_CALL(m_fileCompressor, compress(_, _, _, _)).WillOnce(Return(ByMove(std::nullopt)));

    std::string seenBodyFilePath;
    std::vector<std::string> seenHeaders;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        seenBodyFilePath = spec.bodyFilePath;
        seenHeaders = spec.headers;
        return response(TransportStatus::Ok, 200, "{}");
    }));

    ASSERT_TRUE(compressing.submit("sess-1", reinterpret_cast<const uint8_t*>("body"), 4));
    EXPECT_TRUE(compressing.step(m_waiter));

    EXPECT_EQ(originalPath, seenBodyFilePath);
    EXPECT_THAT(seenHeaders, Not(Contains("Content-Encoding: zstd")));
}

TEST_F(StatefulStreamTest, GateAlreadyDisabledSkipsCompressionEntirely)
{
    m_compressionGate.reportRejected(); // E.g. another stream already saw a 415.

    ModuleConfig compressingConfig = makeCompressingConfig();
    StatefulStream compressing {compressingConfig,  m_performer,        m_signer,
                                m_clock,            m_random,           m_spoolFactory,
                                m_sink,             m_authGate,         m_compressionGate,
                                m_fileCompressor};

    EXPECT_CALL(m_fileCompressor, compress(_, _, _, _)).Times(0);
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 200, "{}")));

    ASSERT_TRUE(compressing.submit("sess-1", reinterpret_cast<const uint8_t*>("body"), 4));
    EXPECT_TRUE(compressing.step(m_waiter));
}
