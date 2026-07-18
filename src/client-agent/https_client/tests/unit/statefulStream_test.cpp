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
#include "mockSpoolFactory.hpp"
#include "statefulStream.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>
#include <fstream>

using ::testing::_;
using ::testing::ByMove;
using ::testing::Invoke;
using ::testing::NiceMock;
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
            , m_stream(m_config, m_performer, m_signer, m_clock, m_random, m_spoolFactory, m_sink)
        {
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
        FakeWaiter m_waiter;
        StatefulStream m_stream;
    };
} // namespace

TEST_F(StatefulStreamTest, StepWithoutPendingDoesNothing)
{
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    EXPECT_FALSE(m_stream.step(m_waiter));
}

TEST_F(StatefulStreamTest, SessionIsSpooledAndStreamedWithSessionHeader)
{
    const std::string path = ::testing::TempDir() + "hc_stateful_1.tmp";
    EXPECT_CALL(m_spoolFactory, spool(_, 8u))
        .WillOnce(Return(ByMove(makeSpoolAt(path, "12345678"))));

    std::vector<std::string> headers;
    EXPECT_CALL(m_performer, perform(_))
        .WillOnce(Invoke(
            [&](const HttpRequestSpec& spec)
            {
                headers = spec.headers;
                EXPECT_EQ("/stateful", spec.target);
                EXPECT_EQ(path, spec.bodyFilePath);
                EXPECT_EQ(8u, spec.bodyFileSize);
                return response(TransportStatus::Ok, 200, R"({"itemsProcessed":42})");
            }));
    EXPECT_CALL(m_sink, onSyncResponse("sess-1", HC_OK, R"({"itemsProcessed":42})"));

    ASSERT_TRUE(submit("sess-1", "12345678"));
    EXPECT_TRUE(m_stream.step(m_waiter));

    ASSERT_FALSE(headers.empty());
    EXPECT_NE(headers.end(), std::find(headers.begin(), headers.end(), "X-Session-Id: sess-1"));
}

TEST_F(StatefulStreamTest, SameSessionIdAcrossRetries)
{
    const std::string path = ::testing::TempDir() + "hc_stateful_retry.tmp";
    // Two attempts inside one send: the spool factory is asked once, and the
    // session id header is identical on both performer calls.
    EXPECT_CALL(m_spoolFactory, spool(_, _))
        .WillOnce(Return(ByMove(makeSpoolAt(path, "body"))));

    std::vector<std::string> firstHeaders;
    std::vector<std::string> secondHeaders;
    EXPECT_CALL(m_performer, perform(_))
        .WillOnce(Invoke(
            [&](const HttpRequestSpec& spec)
            {
                firstHeaders = spec.headers;
                return response(TransportStatus::Ok, 500);
            }))
        .WillOnce(Invoke(
            [&](const HttpRequestSpec& spec)
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

TEST_F(StatefulStreamTest, SpoolFailureReportsErrorWithoutSending)
{
    EXPECT_CALL(m_spoolFactory, spool(_, _)).WillOnce(Return(ByMove(nullptr)));
    EXPECT_CALL(m_performer, perform(_)).Times(0);
    EXPECT_CALL(m_sink, onSyncResponse("sess-x", HC_ERROR, std::string {}));

    submit("sess-x", "body");
    EXPECT_TRUE(m_stream.step(m_waiter));
}

TEST_F(StatefulStreamTest, FailureOutcomeCrossesTheSink)
{
    const std::string path = ::testing::TempDir() + "hc_stateful_fail.tmp";
    EXPECT_CALL(m_spoolFactory, spool(_, _)).WillOnce(Return(ByMove(makeSpoolAt(path, "body"))));
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 413)));
    EXPECT_CALL(m_sink, onSyncResponse("sess-perm", HC_PERMANENT, _));

    submit("sess-perm", "body");
    EXPECT_TRUE(m_stream.step(m_waiter));
}

TEST_F(StatefulStreamTest, QueueIsFifo)
{
    const std::string path1 = ::testing::TempDir() + "hc_stateful_f1.tmp";
    const std::string path2 = ::testing::TempDir() + "hc_stateful_f2.tmp";
    EXPECT_CALL(m_spoolFactory, spool(_, _))
        .WillOnce(Return(ByMove(makeSpoolAt(path1, "a"))))
        .WillOnce(Return(ByMove(makeSpoolAt(path2, "bb"))));
    EXPECT_CALL(m_performer, perform(_)).WillRepeatedly(Return(response(TransportStatus::Ok, 200)));

    ::testing::InSequence sequence;
    EXPECT_CALL(m_sink, onSyncResponse("first", HC_OK, _));
    EXPECT_CALL(m_sink, onSyncResponse("second", HC_OK, _));

    submit("first", "a");
    submit("second", "bb");
    EXPECT_TRUE(m_stream.hasPending());
    m_stream.step(m_waiter);
    m_stream.step(m_waiter);
    EXPECT_FALSE(m_stream.hasPending());
}

TEST_F(StatefulStreamTest, BoundedQueueRejectsOverflow)
{
    // Fill the queue to its cap without stepping, then the next submit fails.
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
