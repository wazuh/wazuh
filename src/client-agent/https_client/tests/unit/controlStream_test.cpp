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

#include "controlStream.hpp"
#include "fakeSysSeams.hpp"
#include "mockCallbackSink.hpp"
#include "mockHttpPerformer.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>

using ::testing::_;
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

    std::string bodyOf(const HttpRequestSpec& spec)
    {
        return std::string {reinterpret_cast<const char*>(spec.body), spec.bodyLength};
    }

    class ControlStreamTest : public ::testing::Test
    {
        protected:
            ControlStreamTest()
                : m_signer("001", m_keyProvider)
                , m_config(makeConfig())
                , m_stream(m_config, m_performer, m_signer, m_clock, m_random, m_sink)
            {
            }

            static ModuleConfig makeConfig()
            {
                hc_config_t config {};
                std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
                std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
                std::strncpy(config.version, "5.1.0", sizeof(config.version) - 1);
                std::strncpy(config.config_checksum, "abc", sizeof(config.config_checksum) - 1);
                config.verify_mode = HC_VERIFY_NONE;
                return ModuleConfig::fromC(config);
            }

            ConfigKeyProvider m_keyProvider {"000102030405060708090a0b0c0d0e0f"};
            CmacSigner m_signer;
            ModuleConfig m_config;
            FakeClock m_clock;
            ScriptedRandom m_random {{0.0}};
            NiceMock<MockCallbackSink> m_sink;
            MockHttpPerformer m_performer;
            FakeWaiter m_waiter;
            ControlStream m_stream;
    };
} // namespace

TEST_F(ControlStreamTest, StartupBodyCarriesTypeAndVersionOnly)
{
    std::string sent;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        sent = bodyOf(spec);
        EXPECT_EQ("/control", spec.target);
        return response(TransportStatus::Ok, 200, R"({"limits":{}})");
    }));

    EXPECT_TRUE(m_stream.step(m_waiter));
    EXPECT_NE(std::string::npos, sent.find("\"type\":\"startup\""));
    EXPECT_NE(std::string::npos, sent.find("\"version\":\"5.1.0\""));
    // C.1: the config hash travels in Notify, never in the startup request.
    EXPECT_EQ(std::string::npos, sent.find("config_hash"));
    EXPECT_EQ(std::string::npos, sent.find("config_checksum"));
}

TEST_F(ControlStreamTest, StartupAcceptedRegistersAndDeliversHandshake)
{
    EXPECT_CALL(m_sink, onStateChange(HC_STATE_REGISTERED));
    EXPECT_CALL(m_sink, onStartupResult(true, R"({"limits":{"eps":0}})"));
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, R"({"limits":{"eps":0}})")));

    EXPECT_TRUE(m_stream.step(m_waiter));
    EXPECT_TRUE(m_stream.isRegistered());
    EXPECT_EQ(HC_STATE_REGISTERED, m_stream.connState());
}

TEST_F(ControlStreamTest, VersionRejectionGoesRejected)
{
    EXPECT_CALL(m_sink, onStateChange(HC_STATE_REJECTED));
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 426)));

    EXPECT_FALSE(m_stream.step(m_waiter));
    EXPECT_EQ(HC_STATE_REJECTED, m_stream.connState());
}

TEST_F(ControlStreamTest, PersistentAuthFailureGoesAuthError)
{
    EXPECT_CALL(m_sink, onStateChange(HC_STATE_AUTH_ERROR));
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 401)));

    EXPECT_FALSE(m_stream.step(m_waiter));
    EXPECT_EQ(HC_STATE_AUTH_ERROR, m_stream.connState());
}

TEST_F(ControlStreamTest, NotifyBodyNestsTheConfigHashUnderAgent)
{
    // First step registers; the second sends Notify.
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        const std::string body = bodyOf(spec);
        EXPECT_NE(std::string::npos, body.find("\"type\":\"notify\""));
        EXPECT_NE(std::string::npos, body.find("\"agent\":{\"config_hash\":\"abc\"}"));
        return response(TransportStatus::Ok, 200, "{}");
    }));

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Notify.
}

TEST_F(ControlStreamTest, NotifyOmitsTheConfigHashWhenChecksumIsEmpty)
{
    hc_config_t raw {};
    std::strncpy(raw.server_host, "127.0.0.1", sizeof(raw.server_host) - 1);
    std::strncpy(raw.agent_id, "001", sizeof(raw.agent_id) - 1);
    std::strncpy(raw.version, "5.1.0", sizeof(raw.version) - 1);
    raw.verify_mode = HC_VERIFY_NONE; // No config_checksum: no config yet.
    const ModuleConfig config = ModuleConfig::fromC(raw);
    ControlStream stream(config, m_performer, m_signer, m_clock, m_random, m_sink);

    std::string notifyBody;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        notifyBody = bodyOf(spec);
        return response(TransportStatus::Ok, 200, "{}");
    }));

    stream.step(m_waiter);
    stream.step(m_waiter);
    EXPECT_NE(std::string::npos, notifyBody.find("\"agent\":{}"));
    EXPECT_EQ(std::string::npos, notifyBody.find("config_hash"));
}

TEST_F(ControlStreamTest, NotifyTasksAreDispatchedAndDeduped)
{
    const std::string notifyResponse =
        R"({"status":"ok","tasks":[)"
        R"({"task_id":"t1","task_type":"active_response","payload":{"cmd":"x"}},)"
        R"({"task_id":"t2","task_type":"agent_restart","payload":{}}]})";
    const std::string repeatResponse =
        R"({"status":"ok","tasks":[)"
        R"({"task_id":"t1","task_type":"active_response","payload":{"cmd":"x"}}]})";

    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))  // Startup.
    .WillOnce(Return(response(TransportStatus::Ok, 200, notifyResponse)))
    .WillOnce(Return(response(TransportStatus::Ok, 200, repeatResponse)));

    // t1 and t2 dispatched once; the repeated t1 is dropped (at-least-once).
    EXPECT_CALL(m_sink, onTask("t1", "active_response", R"({"cmd":"x"})"));
    EXPECT_CALL(m_sink, onTask("t2", "agent_restart", "{}"));

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Notify -> t1, t2.
    m_stream.step(m_waiter); // Notify -> t1 duplicate dropped.
}

TEST_F(ControlStreamTest, EmptyNotifyBodyIsIgnored)
{
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))
    .WillOnce(Return(response(TransportStatus::Ok, 200, ""))); // Empty body.
    EXPECT_CALL(m_sink, onTask(_, _, _)).Times(0);

    m_stream.step(m_waiter);
    m_stream.step(m_waiter); // No dispatch, no crash.
}

TEST_F(ControlStreamTest, TaskMissingOptionalFieldsStillDispatches)
{
    // A task with only task_id: type/payload resolve to empty strings.
    const std::string body = R"({"tasks":[{"task_id":"only-id"}]})";
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))
    .WillOnce(Return(response(TransportStatus::Ok, 200, body)));
    EXPECT_CALL(m_sink, onTask("only-id", "", ""));

    m_stream.step(m_waiter);
    m_stream.step(m_waiter);
}

TEST_F(ControlStreamTest, MalformedNotifyBodyIsIgnored)
{
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "not-json{{")));
    EXPECT_CALL(m_sink, onTask(_, _, _)).Times(0);

    m_stream.step(m_waiter);
    m_stream.step(m_waiter); // No crash, no dispatch.
}

TEST_F(ControlStreamTest, QueuedTaskResultIsPostedInResponsePhase)
{
    std::string responseBody;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))  // Startup.
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))  // Notify.
    .WillOnce(Invoke(                                            // Response.
                  [&](const HttpRequestSpec & spec)
    {
        responseBody = bodyOf(spec);
        return response(TransportStatus::Ok, 200);
    }));

    m_stream.step(m_waiter); // Startup.
    m_stream.queueTaskResponse("t1", R"({"status":"completed","data":"Upgraded","error":null})");
    m_stream.step(m_waiter); // Notify + Response.

    // C.3: the queued result object crosses verbatim, plus the task id.
    EXPECT_NE(std::string::npos, responseBody.find("\"type\":\"response\""));
    EXPECT_NE(std::string::npos, responseBody.find("\"task_id\":\"t1\""));
    EXPECT_NE(std::string::npos, responseBody.find("\"status\":\"completed\""));
    EXPECT_NE(std::string::npos, responseBody.find("\"data\":\"Upgraded\""));
    EXPECT_NE(std::string::npos, responseBody.find("\"error\":null"));
}

TEST_F(ControlStreamTest, PlainStringResultIsWrappedAsCompletedData)
{
    std::string responseBody;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))  // Startup.
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))  // Notify.
    .WillOnce(Invoke(                                            // Response.
                  [&](const HttpRequestSpec & spec)
    {
        responseBody = bodyOf(spec);
        return response(TransportStatus::Ok, 200);
    }));

    m_stream.step(m_waiter);
    m_stream.queueTaskResponse("t2", "all good"); // Not a JSON object.
    m_stream.step(m_waiter);

    EXPECT_NE(std::string::npos, responseBody.find("\"task_id\":\"t2\""));
    EXPECT_NE(std::string::npos, responseBody.find("\"status\":\"completed\""));
    EXPECT_NE(std::string::npos, responseBody.find("\"data\":\"all good\""));
    EXPECT_NE(std::string::npos, responseBody.find("\"error\":null"));
}

TEST_F(ControlStreamTest, FailedResponseIsRequeued)
{
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))     // Startup.
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))     // Notify.
    .WillOnce(Return(response(TransportStatus::Timeout, 0)))        // Response fails.
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))     // Notify.
    .WillOnce(Invoke(                                              // Response retried.
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_NE(std::string::npos,
                  std::string(reinterpret_cast<const char*>(spec.body), spec.bodyLength)
                  .find("\"task_id\":\"t1\""));
        return response(TransportStatus::Ok, 200);
    }));

    m_stream.step(m_waiter);
    m_stream.queueTaskResponse("t1", R"({"status":"failed","data":null,"error":"boom"})");
    m_stream.step(m_waiter); // Response fails, re-queued.
    m_stream.step(m_waiter); // Response retried successfully.
}
