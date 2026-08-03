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
#include "digest.hpp"
#include "fakeSysSeams.hpp"
#include "fakeTaskIdStore.hpp"
#include "mockCallbackSink.hpp"
#include "mockHttpPerformer.hpp"

#include "external/nlohmann/json.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>
#include <fstream>
#include <memory>

using ::testing::_;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;

namespace
{
    HttpResponse response(TransportStatus status, long code, const std::string& body = {},
                          const std::string& localIp = {})
    {
        HttpResponse value;
        value.status = status;
        value.httpCode = code;
        value.body = body;
        value.localIp = localIp;
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
                , m_spoolFactory(::testing::TempDir())
                , m_configHash("abc")
                , m_authGate(m_sink, [] {})
            , m_stream(m_config, m_performer, m_signer, m_clock, m_random, m_sink,
                       m_spoolFactory, m_configHash, m_cluster, m_authGate, m_taskStore,
                       [this] { return m_hostJson; })
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
            TempSpoolFactory m_spoolFactory;
            ConfigHashState m_configHash;
            ClusterIdentity m_cluster;
            AuthGate m_authGate;
            FakeWaiter m_waiter;
            FakeTaskIdStore m_taskStore;
            std::string m_hostJson; ///< Injected Notify host block ("" -> omitted).
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

TEST_F(ControlStreamTest, StartupStoresManagerAuthoritativeClusterIdentity)
{
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200,
                              R"({"cluster":{"name":"prod","node":"node07"}})")));
    m_stream.step(m_waiter);
    EXPECT_EQ("prod", m_cluster.get().name);
    EXPECT_EQ("node07", m_cluster.get().node);
}

TEST_F(ControlStreamTest, StartupWithoutClusterOverwritesToEmpty)
{
    // A prior identity must not linger when the manager reports none.
    m_cluster.set("stale", "stale-node");
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, R"({"limits":{}})")));
    m_stream.step(m_waiter);
    EXPECT_TRUE(m_cluster.get().name.empty());
    EXPECT_TRUE(m_cluster.get().node.empty());
}

TEST_F(ControlStreamTest, SettingsRefreshStartupAlsoOverwritesCluster)
{
    const std::string startupV1 = R"({"limits":{"eps":0},"cluster":{"name":"c1","node":"n1"}})";
    const std::string startupV2 = R"({"limits":{"eps":9},"cluster":{"name":"c2","node":"n2"}})";
    const std::string notifyV2 =
        R"({"settings_hash":")" + sha256Hex(startupV2.data(), startupV2.size()) + R"("})";

    int calls = 0;
    EXPECT_CALL(m_performer, perform(_))
    .WillRepeatedly(Invoke(
                        [&](const HttpRequestSpec & spec)
    {
        const bool startup = bodyOf(spec).find("startup") != std::string::npos;
        calls++;

        if (calls == 1)
        {
            return response(TransportStatus::Ok, 200, startupV1);
        }

        return response(TransportStatus::Ok, 200, startup ? startupV2 : notifyV2);
    }));

    m_stream.step(m_waiter); // Startup v1.
    EXPECT_EQ("c1", m_cluster.get().name);
    m_stream.step(m_waiter); // Notify: settings mismatch -> arm refresh.
    m_stream.step(m_waiter); // Refresh startup v2.
    EXPECT_EQ("c2", m_cluster.get().name);
    EXPECT_EQ("n2", m_cluster.get().node);
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
    EXPECT_CALL(m_sink, onStartupResult(false, _)); // A rejected startup is reported to the consumer.
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 409)));

    EXPECT_FALSE(m_stream.step(m_waiter));
    EXPECT_EQ(HC_STATE_REJECTED, m_stream.connState());
}

TEST_F(ControlStreamTest, PersistentAuthFailureGoesAuthError)
{
    EXPECT_CALL(m_sink, onStateChange(HC_STATE_AUTH_ERROR));
    // A 401 gets one fresh-timestamp retry; a second 401 escalates to AUTH_ERROR.
    EXPECT_CALL(m_performer, perform(_))
    .Times(2)
    .WillRepeatedly(Return(response(TransportStatus::Ok, 401)));

    EXPECT_FALSE(m_stream.step(m_waiter));
    EXPECT_EQ(HC_STATE_AUTH_ERROR, m_stream.connState());
}

TEST_F(ControlStreamTest, PausedGateSkipsHttpAndReleaseResumesWithAFreshStartup)
{
    // First step: 401 startup engages the gate (via RetrySender) -> AUTH_ERROR.
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 401)))   // Startup -> 401.
    .WillOnce(Return(response(TransportStatus::Ok, 401)))   // One-shot auth retry -> 401 -> pause.
    .WillOnce(Invoke(                                       // Post-release startup.
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_NE(std::string::npos, bodyOf(spec).find("\"type\":\"startup\""));
        return response(TransportStatus::Ok, 200, R"({"limits":{}})");
    }));

    m_stream.step(m_waiter);
    EXPECT_TRUE(m_authGate.paused());
    EXPECT_EQ(HC_STATE_AUTH_ERROR, m_stream.connState());

    // While paused, a step performs NO HTTP and stays AUTH_ERROR.
    m_stream.step(m_waiter);
    EXPECT_EQ(HC_STATE_AUTH_ERROR, m_stream.connState());

    // A new key releases the gate; the next step re-registers.
    m_authGate.release();
    EXPECT_TRUE(m_stream.step(m_waiter));
    EXPECT_EQ(HC_STATE_REGISTERED, m_stream.connState());
}

TEST_F(ControlStreamTest, NotifyCarriesTypeVersionAndHost)
{
    // The collector supplies hostname/architecture/os; host.ip is injected by
    // the module from the connection's local IP (CURLINFO_LOCAL_IP), captured
    // on the preceding Startup response.
    m_hostJson = R"({"hostname":"ubuntu-test","architecture":"x86_64",)"
                 R"("os":{"name":"Ubuntu","version":"20.04","platform":"ubuntu","type":"linux"}})";

    std::string sent;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}", "192.168.1.100"))) // Startup: local IP.
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        sent = bodyOf(spec);
        return response(TransportStatus::Ok, 200, "{}");
    }));

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Notify.

    const auto body = nlohmann::json::parse(sent);
    EXPECT_EQ("notify", body.at("type"));
    EXPECT_EQ("5.1.0", body.at("agent").at("version"));
    EXPECT_EQ("ubuntu-test", body.at("host").at("hostname"));
    EXPECT_EQ("x86_64", body.at("host").at("architecture"));
    EXPECT_EQ("192.168.1.100", body.at("host").at("ip")); // From CURLINFO_LOCAL_IP.
    EXPECT_EQ("linux", body.at("host").at("os").at("type"));
}

TEST_F(ControlStreamTest, NotifyHostOmitsIpWhenLocalIpUnknown)
{
    // Host metadata is available but no connection has reported a local IP yet:
    // the host block is sent without the ip key rather than an empty one.
    m_hostJson = R"({"hostname":"h","os":{"type":"linux"}})";

    std::string sent;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}"))) // Startup: no local IP.
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        sent = bodyOf(spec);
        return response(TransportStatus::Ok, 200, "{}");
    }));

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Notify.

    const auto body = nlohmann::json::parse(sent);
    EXPECT_TRUE(body.at("host").is_object());
    EXPECT_FALSE(body.at("host").contains("ip"));
}

TEST_F(ControlStreamTest, NotifyOmitsHostWhenMetadataUnavailable)
{
    m_hostJson.clear(); // metadata_provider not ready yet.

    std::string sent;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        sent = bodyOf(spec);
        return response(TransportStatus::Ok, 200, "{}");
    }));

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Notify.

    const auto body = nlohmann::json::parse(sent);
    EXPECT_EQ("notify", body.at("type"));
    EXPECT_EQ("5.1.0", body.at("agent").at("version"));
    EXPECT_FALSE(body.contains("host"));
}

TEST_F(ControlStreamTest, SettingsMismatchTriggersOneStartupRefresh)
{
    const std::string startupV1 = R"({"limits":{"eps":0}})";
    const std::string startupV2 = R"({"limits":{"eps":100}})";
    const std::string hashV2 = sha256Hex(startupV2.data(), startupV2.size());
    const std::string notifyWithV2 =
        R"({"status":"ok","settings_hash":")" + hashV2 + R"("})";

    std::vector<std::string> requestTypes;
    EXPECT_CALL(m_performer, perform(_))
    .WillRepeatedly(Invoke(
                        [&](const HttpRequestSpec & spec)
    {
        const std::string body = bodyOf(spec);
        requestTypes.push_back(body.find("startup") != std::string::npos ? "startup"
                               : "notify");

        if (requestTypes.size() == 1)
        {
            return response(TransportStatus::Ok, 200, startupV1);
        }

        if (requestTypes.back() == "startup")
        {
            return response(TransportStatus::Ok, 200, startupV2);
        }

        return response(TransportStatus::Ok, 200, notifyWithV2);
    }));

    m_stream.step(m_waiter); // Startup (v1 baseline).
    m_stream.step(m_waiter); // Notify: settings_hash(v2) != sha256(v1) -> arm.
    m_stream.step(m_waiter); // Refresh Startup (returns v2, new baseline).
    m_stream.step(m_waiter); // Notify again: hash matches now, no re-arm.
    m_stream.step(m_waiter); // Still Notify.

    EXPECT_EQ((std::vector<std::string> {"startup", "notify", "startup", "notify", "notify"}),
              requestTypes);
}

TEST_F(ControlStreamTest, StaleSettingsHashDoesNotLoopStartups)
{
    // The refresh returns the SAME startup body, yet the manager keeps
    // reporting a different settings_hash (non-deterministic serialization).
    // The latch holds after one refresh: no startup storm.
    const std::string startupBody = R"({"limits":{"eps":0}})";
    const std::string staleNotify = R"({"status":"ok","settings_hash":"never-matching"})";

    std::vector<std::string> requestTypes;
    EXPECT_CALL(m_performer, perform(_))
    .WillRepeatedly(Invoke(
                        [&](const HttpRequestSpec & spec)
    {
        const bool isStartup = bodyOf(spec).find("startup") != std::string::npos;
        requestTypes.push_back(isStartup ? "startup" : "notify");
        return response(TransportStatus::Ok, 200, isStartup ? startupBody : staleNotify);
    }));

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Notify: mismatch -> arm (first and only refresh).
    m_stream.step(m_waiter); // Refresh Startup (same body).
    m_stream.step(m_waiter); // Notify: same stale hash -> latched, no re-arm.
    m_stream.step(m_waiter); // Notify.
    m_stream.step(m_waiter); // Notify.

    EXPECT_EQ((std::vector<std::string> {"startup", "notify", "startup", "notify", "notify",
                                         "notify"
                                        }),
              requestTypes);
}

TEST_F(ControlStreamTest, ConfigMismatchDownloadsVerifiesAndDelivers)
{
    // The manager reports a config_hash != local ("abc"): the client POSTs
    // /download with the reported group, the body lands in the response file,
    // its SHA-256 matches, the local hash updates and the file is delivered.
    const std::string blob = "merged-config-bytes";
    const std::string blobHash = sha256Hex(blob.data(), blob.size());
    const std::string notify =
        R"({"status":"ok","agent":{"groups":["web-servers"],"config_hash":")" + blobHash +
        R"("}})";

    std::string downloadBody;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))    // Startup.
    .WillOnce(Return(response(TransportStatus::Ok, 200, notify)))  // Notify.
    .WillOnce(Invoke(                                              // /download.
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ("/download", spec.target);
        EXPECT_EQ(m_config.statefulTimeoutMs, spec.timeoutMs);
        downloadBody = bodyOf(spec);
        std::ofstream file {spec.responseFilePath, std::ios::binary};
        file << blob;
        return response(TransportStatus::Ok, 200);
    }));

    std::shared_ptr<SpoolFile> delivered;
    EXPECT_CALL(m_sink, onConfigDownloaded(blobHash, _))
    .WillOnce(Invoke([&](const std::string&, std::shared_ptr<SpoolFile> file)
    {
        delivered = std::move(file);
    }));

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Notify -> download -> deliver.

    EXPECT_EQ(R"({"resource_type":"config","resource_id":"web-servers"})", downloadBody);
    EXPECT_EQ(blobHash, m_configHash.get()); // Optimistic update.
    ASSERT_NE(nullptr, delivered);
    std::ifstream file {delivered->path(), std::ios::binary};
    const std::string content {std::istreambuf_iterator<char>(file),
                               std::istreambuf_iterator<char>()};
    EXPECT_EQ(blob, content);
}

TEST_F(ControlStreamTest, MatchingConfigHashDoesNotDownload)
{
    // Local hash is "abc": a notify reporting "abc" triggers nothing, and
    // after a successful download+update, the same hash stays quiet (the
    // optimistic update prevents a re-download every notify).
    const std::string notify =
        R"({"status":"ok","agent":{"groups":["default"],"config_hash":"abc"}})";
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))
    .WillOnce(Return(response(TransportStatus::Ok, 200, notify)))
    .WillOnce(Return(response(TransportStatus::Ok, 200, notify)));
    EXPECT_CALL(m_sink, onConfigDownloaded(_, _)).Times(0);

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Notify: in sync, no download.
    m_stream.step(m_waiter); // Still in sync.
}

TEST_F(ControlStreamTest, ManagerConfigHashIsReportedEvenWhenItMatches)
{
    // The agent's startup hash gate waits on the manager-validated config, and
    // an agent already in sync never downloads, so the hash has to reach the
    // consumer on the notify itself or the gate never releases.
    const std::string notify =
        R"({"status":"ok","agent":{"groups":["default"],"config_hash":"abc"}})";
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))
    .WillOnce(Return(response(TransportStatus::Ok, 200, notify)));
    EXPECT_CALL(m_sink, onConfigDownloaded(_, _)).Times(0);
    EXPECT_CALL(m_sink, onManagerConfigHash("abc")).Times(1);

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Notify: in sync, still reported.
}

TEST_F(ControlStreamTest, ManagerConfigHashIsReportedBeforeADownload)
{
    // The diverging case reports too, so the gate can record what it is
    // waiting for before /download lands it.
    const std::string blob = "new-config-bytes";
    const std::string blobHash = sha256Hex(blob.data(), blob.size());
    const std::string notify =
        R"({"status":"ok","agent":{"groups":["default"],"config_hash":")" + blobHash + R"("}})";
    EXPECT_CALL(m_sink, onManagerConfigHash(blobHash)).Times(1);
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))
    .WillOnce(Return(response(TransportStatus::Ok, 200, notify)))
    .WillRepeatedly(Return(response(TransportStatus::Ok, 500)));

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Notify: reports, then attempts the download.
}

TEST_F(ControlStreamTest, HashMismatchOnTheDownloadedFileDiscardsIt)
{
    // The downloaded bytes do not match the advertised MD5: no delivery, no
    // local-hash update; the next notify triggers a fresh download attempt.
    const std::string notify =
        R"({"status":"ok","agent":{"groups":["default"],"config_hash":"1111111111111111)"
        R"(1111111111111111"}})";

    int downloads = 0;
    EXPECT_CALL(m_performer, perform(_))
    .WillRepeatedly(Invoke(
                        [&](const HttpRequestSpec & spec)
    {
        if (spec.target == "/download")
        {
            downloads++;
            std::ofstream file {spec.responseFilePath, std::ios::binary};
            file << "bytes-with-a-different-hash";
            return response(TransportStatus::Ok, 200);
        }

        if (bodyOf(spec).find("startup") != std::string::npos)
        {
            return response(TransportStatus::Ok, 200, "{}");
        }

        return response(TransportStatus::Ok, 200, notify);
    }));
    EXPECT_CALL(m_sink, onConfigDownloaded(_, _)).Times(0);

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Notify -> download (discarded).
    m_stream.step(m_waiter); // Notify -> retried (still mismatching).

    EXPECT_EQ(2, downloads);
    EXPECT_EQ("abc", m_configHash.get()); // Never updated.
}

TEST_F(ControlStreamTest, FailedDownloadRetriesOnTheNextNotify)
{
    const std::string notify =
        R"({"status":"ok","agent":{"groups":["default"],"config_hash":"ffff"}})";

    int downloads = 0;
    EXPECT_CALL(m_performer, perform(_))
    .WillRepeatedly(Invoke(
                        [&](const HttpRequestSpec & spec)
    {
        if (spec.target == "/download")
        {
            downloads++;
            return response(TransportStatus::ConnectFail, 0); // Transport down.
        }

        if (bodyOf(spec).find("startup") != std::string::npos)
        {
            return response(TransportStatus::Ok, 200, "{}");
        }

        return response(TransportStatus::Ok, 200, notify);
    }));
    EXPECT_CALL(m_sink, onConfigDownloaded(_, _)).Times(0);

    // One backoff wait happens between the two attempts of each failed
    // download; let both proceed (an unscripted FakeWaiter reads as stop).
    m_waiter.script({true, true});

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Notify -> download fails (2 attempts).
    m_stream.step(m_waiter); // Notify -> re-armed, fails again.

    EXPECT_EQ(4, downloads); // 2 notifies x DOWNLOAD_MAX_ATTEMPTS(2).
    EXPECT_EQ("abc", m_configHash.get());
}

TEST_F(ControlStreamTest, DrainStepSendsBareShutdown)
{
    // Even with a settings refresh armed and a task-bearing response, the
    // drain sends exactly {"type":"shutdown"}, dispatches nothing and
    // downloads nothing.
    const std::string armingNotify = R"({"status":"ok","settings_hash":"different"})";
    const std::string shutdownResponse =
        R"({"agent":{"groups":["default"],"config_hash":"drain-mismatch"},"tasks":[)"
        R"({"task_id":"late","task_type":"active_response","payload":{}}]})";

    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))            // Startup.
    .WillOnce(Return(response(TransportStatus::Ok, 200, armingNotify)))    // Arms refresh.
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ(R"({"type":"shutdown"})", bodyOf(spec));
        EXPECT_EQ(m_config.drainTimeoutMs, spec.timeoutMs); // Shutdown uses the drain window, not the request timeout.
        return response(TransportStatus::Ok, 200, shutdownResponse);
    }));
    EXPECT_CALL(m_sink, onTask(_, _, _)).Times(0);
    EXPECT_CALL(m_sink, onConfigDownloaded(_, _)).Times(0);

    m_stream.step(m_waiter);      // Startup.
    m_stream.step(m_waiter);      // Notify arms the refresh.
    m_stream.drainStep(m_waiter); // Drain: bare shutdown, no side actions.
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

    // t1 and t2 dispatched once; the repeated t1 is dropped (at-least-once),
    // per the injected durable store -- not an in-memory TTL anymore.
    EXPECT_CALL(m_sink, onTask("t1", "active_response", R"({"cmd":"x"})"));
    EXPECT_CALL(m_sink, onTask("t2", "agent_restart", "{}"));

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Notify -> t1, t2.
    m_stream.step(m_waiter); // Notify -> t1 duplicate dropped.

    EXPECT_THAT(m_taskStore.calls(), ::testing::ElementsAre("t1", "t2", "t1"));
}

TEST_F(ControlStreamTest, DurableStoreIsCheckedBeforeDispatchSoARejectionDropsTheTask)
{
    // Simulates the durable registry either already holding this task_id
    // (a genuine duplicate) or being unreachable (fail-closed): in
    // both cases checkAndRecord() returning false must drop the task before
    // any handler runs, never after.
    const std::string body =
        R"({"status":"ok","tasks":[)"
        R"({"task_id":"blocked","task_type":"active_response","payload":{}}]})";
    m_taskStore.forceDuplicate("blocked");

    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))
    .WillOnce(Return(response(TransportStatus::Ok, 200, body)));
    EXPECT_CALL(m_sink, onTask(_, _, _)).Times(0);

    m_stream.step(m_waiter);
    m_stream.step(m_waiter);
}

TEST_F(ControlStreamTest, TaskDispatchesAgainOnceTheDurableStoreForgetsIt)
{
    // From ControlStream's point of view, a restart (or a TTL expiry inside
    // agent-info) is opaque: it just asks the store again. This exercises
    // that a store reporting "new" again re-dispatches, matching the
    // at-least-once contract without ControlStream needing its own clock
    // logic (that lives in the durable registry now, tested separately).
    const std::string body =
        R"({"status":"ok","tasks":[)"
        R"({"task_id":"t-restart-sim","task_type":"active_response","payload":{}}]})";
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))
    .WillOnce(Return(response(TransportStatus::Ok, 200, body)))
    .WillOnce(Return(response(TransportStatus::Ok, 200, body)))
    .WillOnce(Return(response(TransportStatus::Ok, 200, body)));
    EXPECT_CALL(m_sink, onTask("t-restart-sim", "active_response", "{}")).Times(2);

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Dispatch #1.
    m_taskStore.forget("t-restart-sim"); // Simulated restart / TTL expiry.
    m_stream.step(m_waiter); // Dispatch #2 (store reports "new" again).
    m_stream.step(m_waiter); // Duplicate again: dropped.
}

TEST_F(ControlStreamTest, NotifyBatchIsPrioritizedAndCollapsedBeforeDispatch)
{
    // A shuffled batch: dispatch order is AR -> reload; the restart and the
    // upgrade (empty/malformed payload here, so it aborts without calling
    // the sink either way) are dropped by the planner as covered by the
    // upgrade. Because the durable check runs before the planner, the
    // dropped restart is recorded and its at-least-once redelivery on the
    // next Notify stays dropped.
    const std::string batch =
        R"({"status":"ok","tasks":[)"
        R"({"task_id":"t-restart","task_type":"agent_restart","payload":{}},)"
        R"({"task_id":"t-reload","task_type":"agent_reload","payload":{}},)"
        R"({"task_id":"t-up","task_type":"remote_upgrade","payload":{}},)"
        R"({"task_id":"t-ar","task_type":"active_response","payload":{}}]})";
    const std::string redelivery =
        R"({"status":"ok","tasks":[)"
        R"({"task_id":"t-restart","task_type":"agent_restart","payload":{}}]})";

    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))  // Startup.
    .WillOnce(Return(response(TransportStatus::Ok, 200, batch)))
    .WillOnce(Return(response(TransportStatus::Ok, 200, redelivery)));

    // restart + reload dropped (both covered by the upgrade); the upgrade
    // itself never reaches onTask (routed to onUpgradeReady instead) and its
    // malformed payload here means neither fires.
    EXPECT_CALL(m_sink, onTask("t-restart", _, _)).Times(0);
    EXPECT_CALL(m_sink, onTask("t-reload", _, _)).Times(0);
    EXPECT_CALL(m_sink, onTask("t-up", _, _)).Times(0);
    EXPECT_CALL(m_sink, onUpgradeReady(_, _, _, _)).Times(0);
    EXPECT_CALL(m_sink, onTaskFailed("t-up", "remote_upgrade", _)); // Empty payload: missing fields.
    EXPECT_CALL(m_sink, onTask("t-ar", "active_response", "{}"));

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Notify: planned dispatch in priority order.
    m_stream.step(m_waiter); // Redelivered restart: still dropped.
}

TEST_F(ControlStreamTest, RemoteUpgradeDownloadsVerifiesAndDeliversInsteadOfOnTask)
{
    // A remote_upgrade task is intercepted before the generic on_task
    // callback -- its WPK is downloaded via /download and sha1-verified here,
    // and only onUpgradeReady (never onTask) is called for it. The task_id is
    // already durably recorded by this point (checked in collectFreshTasks,
    // before planning/dispatch), so this is what makes the eventual installer
    // run idempotent across the restart it triggers.
    const std::string wpkBytes = "fake-wpk-bytes";
    const std::string wpkSha1 = sha1Hex(wpkBytes.data(), wpkBytes.size());
    const std::string notify =
        R"({"status":"ok","tasks":[{"task_id":"up-1","task_type":"remote_upgrade",)"
        R"("payload":{"wpk_file":"agent.wpk","wpk_sha1":")" + wpkSha1 +
        R"(","installer":"upgrade.sh"}}]})";

    std::string downloadBody;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}"))) // Startup.
    .WillOnce(Return(response(TransportStatus::Ok, 200, notify)))
    .WillOnce(Invoke( // /download.
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ("/download", spec.target);
        downloadBody = bodyOf(spec);
        std::ofstream file {spec.responseFilePath, std::ios::binary};
        file << wpkBytes;
        return response(TransportStatus::Ok, 200);
    }));
    EXPECT_CALL(m_sink, onTask("up-1", _, _)).Times(0);

    std::shared_ptr<SpoolFile> delivered;
    std::string deliveredInstaller;
    EXPECT_CALL(m_sink, onUpgradeReady("up-1", "agent.wpk", _, "upgrade.sh"))
    .WillOnce(Invoke([&](const std::string&, const std::string&, std::shared_ptr<SpoolFile> file,
                         const std::string & installer)
    {
        delivered = std::move(file);
        deliveredInstaller = installer;
    }));

    m_stream.step(m_waiter); // Startup.
    m_stream.step(m_waiter); // Notify -> spawns the download/verify/deliver worker thread.
    // The download/verify/deliver chain runs off the control thread (see
    // ControlStream::dispatchUpgradeTask()), so it must be explicitly waited for before
    // asserting on its side effects below -- step() itself returns as soon as the thread is
    // spawned.
    m_stream.joinUpgradeWork();

    EXPECT_EQ(R"({"resource_type":"wpk","resource_id":"agent.wpk"})", downloadBody);
    ASSERT_NE(nullptr, delivered);
    EXPECT_EQ("upgrade.sh", deliveredInstaller);
    std::ifstream file {delivered->path(), std::ios::binary};
    const std::string content {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    EXPECT_EQ(wpkBytes, content);
}

TEST_F(ControlStreamTest, RemoteUpgradeSha1MismatchAbortsWithoutDeliveringOrDispatching)
{
    // A sha1 mismatch aborts the upgrade
    // without installing (and, per the fire-and-forget contract, without any
    // /control response either -- there is nothing to send).
    const std::string wpkBytes = "fake-wpk-bytes";
    const std::string notify =
        R"({"status":"ok","tasks":[{"task_id":"up-bad","task_type":"remote_upgrade",)"
        R"("payload":{"wpk_file":"agent.wpk","wpk_sha1":"0000000000000000000000000000000000000",)"
        R"("installer":"upgrade.sh"}}]})";

    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))
    .WillOnce(Return(response(TransportStatus::Ok, 200, notify)))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        std::ofstream file {spec.responseFilePath, std::ios::binary};
        file << wpkBytes; // Downloaded bytes' real sha1 will not match.
        return response(TransportStatus::Ok, 200);
    }));
    EXPECT_CALL(m_sink, onUpgradeReady(_, _, _, _)).Times(0);
    EXPECT_CALL(m_sink, onTask(_, _, _)).Times(0);
    EXPECT_CALL(m_sink, onTaskFailed("up-bad", "remote_upgrade", _));

    m_stream.step(m_waiter);
    m_stream.step(m_waiter); // Spawns the download/verify worker thread.
    // Wait for the worker thread (download/verify happens off the control
    // thread) before the fixture tears down and gmock verifies the EXPECT_CALLs above.
    m_stream.joinUpgradeWork();
}

TEST_F(ControlStreamTest, RemoteUpgradeMissingPayloadFieldsAbortsWithoutDownloading)
{
    const std::string notify =
        R"({"status":"ok","tasks":[{"task_id":"up-missing","task_type":"remote_upgrade",)"
        R"("payload":{"wpk_file":"agent.wpk"}}]})"; // wpk_sha1/installer missing.

    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))
    .WillOnce(Return(response(TransportStatus::Ok, 200, notify))); // No /download call follows.
    EXPECT_CALL(m_sink, onUpgradeReady(_, _, _, _)).Times(0);
    EXPECT_CALL(m_sink, onTask(_, _, _)).Times(0);
    EXPECT_CALL(m_sink, onTaskFailed("up-missing", "remote_upgrade", _));

    m_stream.step(m_waiter);
    m_stream.step(m_waiter); // Aborts synchronously (no thread spawned): missing fields are
    // caught before the worker thread would start.
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

TEST_F(ControlStreamTest, TaskWithoutATaskIdIsSkippedAndTheRestOfTheBatchSurvives)
{
    // A task with no task_id cannot be deduped or identified, so it is
    // dropped (traced at debug). It must not take its batch-mates with it.
    const std::string body =
        R"({"tasks":[)"
        R"({"task_type":"active_response","payload":{}},)"
        R"({"task_id":"good","task_type":"active_response","payload":{}}]})";
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200, "{}")))
    .WillOnce(Return(response(TransportStatus::Ok, 200, body)));
    EXPECT_CALL(m_sink, onTask("good", "active_response", "{}"));

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

