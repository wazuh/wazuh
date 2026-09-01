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

#ifndef _HC_FAKE_MANAGER_HPP
#define _HC_FAKE_MANAGER_HPP

#include "digest.hpp"
#include "jwt/enrollKeyDerivation.hpp"
#include "jwt/jwtEnrollTokenVerifier.hpp"
#include "jwt/jwtKeyDecoder.hpp"
#include "jwt/jwtRequestTokenVerifier.hpp"
#include "jwt/secureBytes.hpp"
#include "keyProvider.hpp"

#include "external/cpp-httplib/httplib.h"
#include "external/nlohmann/json.hpp"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <zstd.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <sys/wait.h>
#include <unistd.h>

// The config_token every notify reports, and the only resource_id /download will serve.
// Deliberately NOT the group name, even though the real 5.0 manager currently mints the group
// selector (controlHandler.cpp's makeConfigToken): the token is opaque to the agent, so a
// value the agent could not have derived from agent.groups is what proves it really came
// through the notify rather than being reconstructed locally.
inline constexpr auto FAKE_MANAGER_CONFIG_TOKEN {"cfg-token-abc123"};

// Mirrors the real manager's HashCache::getSettingsHash() (remoted_module/src/
// control/hashCache.cpp) and the agent's ControlStream::computeSettingsHash():
// limits + cluster only, agent.groups excluded -- NOT a raw hash of the startup
// body's bytes, since nlohmann::json always dumps object keys alphabetically
// regardless of the literal source order.
inline std::string fakeManagerSettingsHash(const std::string& startupBody)
{
    const auto parsed = nlohmann::json::parse(startupBody);
    nlohmann::json envelope;

    if (parsed.contains("limits"))
    {
        envelope["limits"] = parsed.at("limits");
    }

    if (parsed.contains("cluster"))
    {
        envelope["cluster"] = parsed.at("cluster");
    }

    const std::string body = envelope.dump();
    return sha256Hex(body.data(), body.size());
}

/**
 * @brief Fork-based plaintext fake manager (the http-request component-test
 *        idiom). It validates the wazuh-agent+jwt bearer of every request server-side with
 *        the shared key, so a 200 proves real cross-implementation auth
 *        interop; a mismatch yields 401. It supports a one-shot 503 (back-
 *        pressure), a session LRU-of-one (dedup), and a 409 version-reject mode.
 *
 * The child process runs the server; the parent asserts on the responses it
 * receives (the two sides do not share memory).
 */
class FakeManager final
{
    public:
        /// settingsFlipAfter > 0: after that many notifies the served startup
        /// body (and the settings_hash reported by notify) switches to v2, so
        /// a client detects the change and refreshes its startup data.
        /// configBlob non-empty: /download serves it (chunked octet-stream)
        /// and every notify reports agent.config_hash = MD5(configBlob), so a
        /// client whose local hash differs downloads it. Those notifies also
        /// carry agent.config_token = FAKE_MANAGER_CONFIG_TOKEN, and /download
        /// serves nothing else, so the client must relay the token verbatim.
        /// statelessMaxBody > 0: a /stateless POST whose body exceeds it gets
        /// 413, so the client must split and resend smaller (#37835).
        /// rotateKeyAfterNotifies > 0 with rotatedKeyHex set: after that many
        /// notifies the server verifies ONLY against rotatedKeyHex, so the old
        /// key starts getting 401 (#37828 re-enrollment).
        /// statefulHoldFile set: /stateful does not answer while that path
        /// exists, so a test can hold one session open and watch the other
        /// endpoints carry on. The server forks and shares no memory with the
        /// test, so the file is the release signal (#37836 isolation).
        /// vdFeedOffset > 0: every notify additionally reports top-level
        /// "vd_feed_offset":N (issue #38204), so a real client detects the
        /// offset and issues a real /scan/vd request over the wire.
        /// scanVdRejectFirstNAttempts > 0: the first that many /scan/vd
        /// requests are answered 409 with {"error":"version_mismatch",
        /// "current_version":vdFeedOffset} (simulating a load-balanced hit on
        /// a manager node still on an older feed); subsequent attempts get 200.
        /// enrollPassword empty (default): /enroll accepts any request whose
        /// protocol-version header is present, no signature required (open
        /// mode, #38465 Q3). Non-empty: /enroll additionally requires an
        /// `Authorization: Bearer <wazuh-enroll+jwt>` header that verifies with the
        /// manager's own shared JwtEnrollTokenVerifier against the HKDF key of
        /// this password (jwt/enrollKeyDerivation.hpp -- the same construction
        /// remoted's PasswordKeySource runs; the frozen KAT lives in
        /// enrollSigner_test.cpp and jwt_vectors.json).
        /// enrollForcedStatus non-zero: /enroll always answers that status
        /// with a generic error body instead of running the real flow, so a
        /// test can drive the 400/401/403/409/500/503 mapping in
        /// w_enrollment_process_response() without needing five fake servers.
        FakeManager(uint16_t port,
                    const std::string& keyHex,
                    bool tls = false,
                    int settingsFlipAfter = 0,
                    std::string configBlob = {},
                    size_t statelessMaxBody = 0,
                    int rotateKeyAfterNotifies = 0,
                    std::string rotatedKeyHex = {},
                    std::string statefulHoldFile = {},
                    uint64_t vdFeedOffset = 0,
                    int scanVdRejectFirstNAttempts = 0,
                    std::string enrollPassword = {},
                    int enrollForcedStatus = 0)
            : m_port(port)
            , m_keyHex(keyHex)
            , m_tls(tls)
            , m_settingsFlipAfter(settingsFlipAfter)
            , m_configBlob(std::move(configBlob))
            , m_statelessMaxBody(statelessMaxBody)
            , m_rotateKeyAfterNotifies(rotateKeyAfterNotifies)
            , m_rotatedKeyHex(std::move(rotatedKeyHex))
            , m_statefulHoldFile(std::move(statefulHoldFile))
            , m_vdFeedOffset(vdFeedOffset)
            , m_scanVdRejectFirstNAttempts(scanVdRejectFirstNAttempts)
            , m_enrollPassword(std::move(enrollPassword))
            , m_enrollForcedStatus(enrollForcedStatus)
        {
            m_pid = fork();

            if (m_pid == 0)
            {
                runServer();
                _exit(0);
            }

            waitUntilReady();
        }

        ~FakeManager()
        {
            if (m_pid > 0)
            {
                kill(m_pid, SIGTERM);
                waitpid(m_pid, nullptr, 0);
            }
        }

        FakeManager(const FakeManager&) = delete;
        FakeManager& operator=(const FakeManager&) = delete;

    private:
        /// Authenticates one agent request exactly as the manager does: the SHARED
        /// wazuh-agent+jwt verifier (shared_modules/utils/jwt/) over the `Authorization:
        /// Bearer` header, keyed with the 32 bytes keyHex decodes to. Using the manager's own
        /// verifier is what makes this suite the C++<->C++ interoperability proof: a token the
        /// agent mints here IS what remoted accepts. The target plays no part (identity only).
        static bool verifyBearer(const std::string& keyHex, const std::string& /*target*/, const httplib::Request& request)
        {
            if (request.get_header_value("protocol-version") != "1")
            {
                return false;
            }

            const auto auth = request.get_header_value("Authorization");
            const std::string prefix = "Bearer ";

            if (auth.rfind(prefix, 0) != 0)
            {
                return false;
            }

            const auto key = jwt_profile::v1::JwtKeyDecoder::decode(keyHex);

            if (!key)
            {
                return false;
            }

            const auto result = jwt_profile::v1::JwtRequestTokenVerifier::verify(
                                    auth.substr(prefix.size()), *key, jwt_profile::v1::TimePolicy {}, std::chrono::system_clock::now());
            return result.ok();
        }

        template<typename ServerT>
        void registerEndpoints(ServerT& server)
        {
            const std::string keyHex = m_keyHex;
            const int settingsFlipAfter = m_settingsFlipAfter;
            const std::string configBlob = m_configBlob;
            const size_t statelessMaxBody = m_statelessMaxBody;
            const std::string holdFile = m_statefulHoldFile;
            const uint64_t vdFeedOffset = m_vdFeedOffset;
            const int scanVdRejectFirstNAttempts = m_scanVdRejectFirstNAttempts;
            const std::string configHash =
                configBlob.empty() ? std::string {} :
                sha256Hex(configBlob.data(), configBlob.size());
            auto backpressureArmed = std::make_shared<std::atomic<bool>>(true);
            auto lastSession = std::make_shared<std::string>();
            auto notifyCount = std::make_shared<std::atomic<int>>(0);

            // The key every endpoint verifies against: after the configured
            // notify count the server rotates to the new key, so requests
            // minted with the old key start getting 401 (#37828).
            const int rotateAfter = m_rotateKeyAfterNotifies;
            const std::string rotatedKey = m_rotatedKeyHex;
            const auto verify =
                [keyHex, rotatedKey, rotateAfter, notifyCount](const std::string & target, const httplib::Request & request)
            {
                const bool rotated = rotateAfter > 0 && !rotatedKey.empty() && notifyCount->load() >= rotateAfter;
                return verifyBearer(rotated ? rotatedKey : keyHex, target, request);
            };
            // Accumulates accepted /stateless bodies so the fork parent can
            // read them back via GET /peek/stateless (fork servers share no
            // memory; a peek endpoint is the observability channel).
            auto acceptedEvents = std::make_shared<std::string>();
            auto acceptedMutex = std::make_shared<std::mutex>();

            server.Post("/stateless",
                        [verify, backpressureArmed, statelessMaxBody, acceptedEvents, acceptedMutex](
                            const httplib::Request & request, httplib::Response & response)
            {
                if (!verify("/stateless", request))
                {
                    response.status = 401;
                    return;
                }

                if (request.has_header("X-Arm-Backpressure") && backpressureArmed->exchange(false))
                {
                    response.status = 503;
                    response.set_header("Retry-After", "1");
                    return;
                }

                if (statelessMaxBody > 0 && request.body.size() > statelessMaxBody)
                {
                    response.status = 413; // Payload too large: the client must split + resend.
                    return;
                }

                {
                    std::lock_guard<std::mutex> lock(*acceptedMutex);
                    *acceptedEvents += request.body; // Record the accepted batch.
                }

                response.status = 200;
                response.set_content(request.body, "text/plain"); // Echo for body assertions.
            });

            server.Get("/peek/stateless",
                       [acceptedEvents, acceptedMutex](const httplib::Request&, httplib::Response & response)
            {
                std::lock_guard<std::mutex> lock(*acceptedMutex);
                response.status = 200;
                response.set_content(*acceptedEvents, "text/plain");
            });

            // Same channel for the control plane: how many notifies landed.
            server.Get("/peek/notifies",
                       [notifyCount](const httplib::Request&, httplib::Response & response)
            {
                response.status = 200;
                response.set_content(std::to_string(notifyCount->load()), "text/plain");
            });

            // /stats and /config: verify + store the last body so the fork
            // parent can assert on it via GET /peek/{stats,config}.
            auto lastStats = std::make_shared<std::string>();
            auto lastConfig = std::make_shared<std::string>();

            for (const auto& kind :
                    {
                        std::string {"stats"}, std::string {"config"}
                    })
            {
                auto store = kind == "stats" ? lastStats : lastConfig;
                server.Post(
                    "/" + kind,
                    [verify, kind, store, acceptedMutex](const httplib::Request & request, httplib::Response & response)
                {
                    if (!verify("/" + kind, request))
                    {
                        response.status = 401;
                        return;
                    }

                    {
                        std::lock_guard<std::mutex> lock(*acceptedMutex);
                        *store = request.body;
                    }

                    response.set_content("{}", "application/json");
                });

                server.Get("/peek/" + kind,
                           [store, acceptedMutex](const httplib::Request&, httplib::Response & response)
                {
                    std::lock_guard<std::mutex> lock(*acceptedMutex);
                    response.status = store->empty() ? 204 : 200;
                    response.set_content(*store, "text/plain");
                });
            }

            // Size of the session as the manager would see it. Agent builds compile the fake
            // against cpp-httplib 0.10.9 (http-request's EXTERNAL_DEPS_VERSION=19 default), which
            // knows nothing about zstd and hands a `Content-Encoding: zstd` body over untouched;
            // the manager tree's 0.25.0 (+CPPHTTPLIB_ZSTD_SUPPORT) inflates it before the handler
            // runs. Inflate here whenever the body is still a zstd frame so the compression test
            // proves the same thing -- wire bytes back to the full session -- under both.
            const auto statefulBytes = [](const httplib::Request & request) -> std::size_t
            {
                const auto& body = request.body;
                const bool zstdFrame = body.size() >= 4 && static_cast<unsigned char>(body[0]) == 0x28 &&
                static_cast<unsigned char>(body[1]) == 0xB5 &&
                static_cast<unsigned char>(body[2]) == 0x2F &&
                static_cast<unsigned char>(body[3]) == 0xFD;

                if (request.get_header_value("Content-Encoding") != "zstd" || !zstdFrame)
                {
                    return body.size();
                }

                const auto expected = ZSTD_getFrameContentSize(body.data(), body.size());

                if (expected == ZSTD_CONTENTSIZE_ERROR || expected == ZSTD_CONTENTSIZE_UNKNOWN)
                {
                    return 0;
                }

                std::vector<char> inflated(static_cast<std::size_t>(expected));
                const auto produced = ZSTD_decompress(inflated.data(), inflated.size(), body.data(), body.size());
                return ZSTD_isError(produced) ? 0 : produced;
            };

            server.Post("/stateful",
                        [verify, lastSession, holdFile, statefulBytes](const httplib::Request & request,
                                                                       httplib::Response & response)
            {
                if (!verify("/stateful", request))
                {
                    response.status = 401;
                    return;
                }

                // Sit on the response until the test removes the file, with a
                // hard stop so a broken test cannot wedge the run. The cap sits
                // well above the test's own deadlines even when valgrind
                // stretches them tenfold, so it only fires on a real hang.
                for (int waited = 0;
                        !holdFile.empty() && waited < 120000 && access(holdFile.c_str(), F_OK) == 0;
                        waited += 20)
                {
                    usleep(20 * 1000);
                }

                const auto session = request.get_header_value("X-Session-Id");
                const bool cached = (*lastSession == session);
                *lastSession = session;
                response.status = 200;
                response.set_content(std::string {"{\"sessionId\":\""} + session +
                                     "\",\"cached\":" + (cached ? "true" : "false") +
                                     ",\"bytes\":" + std::to_string(statefulBytes(request)) + "}",
                                     "application/json");
            });

            server.Post(
                "/download",
                [verify, configBlob](const httplib::Request & request, httplib::Response & response)
            {
                if (!verify("/download", request))
                {
                    response.status = 401;
                    return;
                }

                if (configBlob.empty() || request.body.find("\"resource_type\":\"config\"") == std::string::npos)
                {
                    response.status = 404;
                    return;
                }

                // Only the token this manager handed out in its notify is served, exactly as
                // the real one resolves a resource_id it minted. An agent that derived the
                // selector itself instead of relaying config_token gets a 404 here, so the
                // E2E download tests fail rather than silently pass on a lucky guess.
                if (request.body.find(std::string {R"("resource_id":")"} +
                                      FAKE_MANAGER_CONFIG_TOKEN + R"(")") == std::string::npos)
                {
                    response.status = 404;
                    return;
                }

                // Chunked transfer on purpose (#37733 5.2.3): the client's
                // decode + stream-to-file path is exercised for real.
                response.status = 200;
                response.set_chunked_content_provider("application/octet-stream",
                                                      [configBlob](size_t offset, httplib::DataSink & sink)
                {
                    constexpr size_t CHUNK = 16 * 1024;
                    const size_t remaining = configBlob.size() - offset;
                    const size_t count = remaining < CHUNK ? remaining : CHUNK;

                    if (count > 0)
                    {
                        sink.write(configBlob.data() + offset, count);
                    }

                    if (offset + count >= configBlob.size())
                    {
                        sink.done();
                    }

                    return true;
                });
            });

            // Records every /control request TYPE the fork child actually saw
            // (not the full body -- just "startup"/"notify"/"shutdown"/
            // "unknown"), so the fork parent can assert on the conversation
            // shape via GET /peek/control (fork servers share no memory; this
            // is the same observability idiom as acceptedEvents/peek/stateless
            // above). Used to directly (not just by source reading) confirm
            // whether a graceful stop actually sends {"type":"shutdown"}.
            auto controlTypes = std::make_shared<std::string>();
            auto controlMutex = std::make_shared<std::mutex>();
            // The Content-Type each /control request advertised, so a test can
            // confirm the per-endpoint header survives the real curl path (the
            // unit test only proves CurlPerformer emits it). Same peek idiom.
            auto controlContentTypes = std::make_shared<std::string>();
            // The last Notify body, so a test can confirm the real host block
            // (including host.ip from the live connection) over the curl path.
            auto lastNotifyBody = std::make_shared<std::string>();

            server.Post(
                "/control",
                [verify,
                 settingsFlipAfter,
                 notifyCount,
                 configHash,
                 controlTypes,
                 controlContentTypes,
                 lastNotifyBody,
                 controlMutex,
                 vdFeedOffset](const httplib::Request & request, httplib::Response & response)
            {
                if (!verify("/control", request))
                {
                    response.status = 401;
                    return;
                }

                {
                    std::lock_guard<std::mutex> lock(*controlMutex);
                    *controlContentTypes += request.get_header_value("Content-Type");
                    *controlContentTypes += ";";
                }

                if (request.has_header("X-Reject-Version"))
                {
                    response.status = 409;
                    return;
                }

                {
                    std::lock_guard<std::mutex> lock(*controlMutex);
                    const char* type = "unknown";

                    if (request.body.find("\"type\":\"startup\"") != std::string::npos)
                    {
                        type = "startup";
                    }
                    else if (request.body.find("\"type\":\"notify\"") != std::string::npos)
                    {
                        type = "notify";
                    }
                    else if (request.body.find("\"type\":\"shutdown\"") != std::string::npos)
                    {
                        type = "shutdown";
                    }

                    *controlTypes += type;
                    *controlTypes += ";";
                }

                // #37733 5.1: startup answers the handshake metadata (v1 or
                // v2 after the settings flip); notify reports agent.groups
                // and the settings_hash of the CURRENT startup body; response
                // answers a plain ok.
                static const std::string startupV1 = R"({"limits":{"eps":0},"cluster":{"name":"fake"},)"
                                                     R"("agent":{"groups":["default"]}})";
                static const std::string startupV2 = R"({"limits":{"eps":100},"cluster":{"name":"fake"},)"
                                                     R"("agent":{"groups":["default"]}})";
                const bool flipped = settingsFlipAfter > 0 && notifyCount->load() >= settingsFlipAfter;
                const std::string& startupBody = flipped ? startupV2 : startupV1;
                response.status = 200;

                if (request.body.find("\"type\":\"startup\"") != std::string::npos)
                {
                    response.set_content(startupBody, "application/json");
                    return;
                }

                if (request.body.find("\"type\":\"notify\"") != std::string::npos)
                {
                    notifyCount->fetch_add(1);
                    {
                        std::lock_guard<std::mutex> lock(*controlMutex);
                        *lastNotifyBody = request.body;
                    }
                    const std::string agent = configHash.empty()
                                              ? std::string {R"({"groups":["default"]})"}
                                              :
                                              R"({"groups":["default"],"config_token":")" +
                                              std::string {FAKE_MANAGER_CONFIG_TOKEN} +
                                              R"(","config_hash":")" + configHash + R"("})";

                    const std::string vdFeedOffsetField =
                        vdFeedOffset > 0 ? R"(,"vd_feed_offset":)" + std::to_string(vdFeedOffset) : std::string {};
                    response.set_content(R"({"agent":)" + agent + R"(,"settings_hash":")" +
                                         fakeManagerSettingsHash(startupBody) + R"(")" + vdFeedOffsetField + "}",
                                         "application/json");
                    return;
                }

                if (request.body.find("\"type\":\"shutdown\"") != std::string::npos)
                {
                    response.set_content("{}", "application/json"); // Disconnect ack.
                    return;
                }

                // Unknown /control type (the response leg is gone): 400.
                response.status = 400;
                response.set_content(R"({"error":"unknown control type"})", "application/json");
            });

            server.Get("/peek/control",
                       [controlTypes, controlMutex](const httplib::Request&, httplib::Response & response)
            {
                std::lock_guard<std::mutex> lock(*controlMutex);
                response.status = 200;
                response.set_content(*controlTypes, "text/plain");
            });

            server.Get("/peek/control-content-type",
                       [controlContentTypes, controlMutex](const httplib::Request&, httplib::Response & response)
            {
                std::lock_guard<std::mutex> lock(*controlMutex);
                response.status = 200;
                response.set_content(*controlContentTypes, "text/plain");
            });

            server.Get("/peek/last-notify",
                       [lastNotifyBody, controlMutex](const httplib::Request&, httplib::Response & response)
            {
                std::lock_guard<std::mutex> lock(*controlMutex);
                response.status = 200;
                response.set_content(*lastNotifyBody, "text/plain");
            });

            // POST /scan/vd (issue #38204): the manager-side contract this
            // workspace's agent-side code is built against (manager itself out
            // of scope here -- see plan.md). Rejects the first
            // scanVdRejectFirstNAttempts attempts with 409 + current_version =
            // vdFeedOffset+1 (simulating a load-balanced hit on a node ALREADY
            // ahead of the one that answered notify -- genuinely higher, so a
            // real client's RescanRequester advances its offset and retries
            // rather than giving up), then accepts. Records every accepted
            // body's bytes via /peek/scan-vd, same peek idiom as /peek/last-notify.
            auto scanVdAttempts = std::make_shared<std::atomic<int>>(0);
            auto lastScanVdBody = std::make_shared<std::string>();
            auto scanVdMutex = std::make_shared<std::mutex>();

            server.Post("/scan/vd",
                        [verify, vdFeedOffset, scanVdRejectFirstNAttempts, scanVdAttempts, lastScanVdBody, scanVdMutex](
                            const httplib::Request & request, httplib::Response & response)
            {
                if (!verify("/scan/vd", request))
                {
                    response.status = 401;
                    return;
                }

                {
                    std::lock_guard<std::mutex> lock(*scanVdMutex);
                    *lastScanVdBody = request.body;
                }

                const int attempt = scanVdAttempts->fetch_add(1);

                if (attempt < scanVdRejectFirstNAttempts)
                {
                    response.status = 409;
                    response.set_content(R"({"error":"version_mismatch","current_version":)" +
                                         std::to_string(vdFeedOffset + 1) + "}",
                                         "application/json");
                    return;
                }

                response.status = 200;
                response.set_content("{}", "application/json");
            });

            server.Get("/peek/scan-vd",
                       [lastScanVdBody, scanVdMutex](const httplib::Request&, httplib::Response & response)
            {
                std::lock_guard<std::mutex> lock(*scanVdMutex);
                response.status = 200;
                response.set_content(*lastScanVdBody, "text/plain");
            });

            server.Get("/peek/scan-vd-attempts",
                       [scanVdAttempts](const httplib::Request&, httplib::Response & response)
            {
                response.status = 200;
                response.set_content(std::to_string(scanVdAttempts->load()), "text/plain");
            });

            // POST /enroll (#38465): the agent-side contract this workspace's
            // agent-side code is built against (manager itself, #38438, out of
            // scope here -- see plan.md). Records the last body via
            // /peek/enroll, same peek idiom as the other endpoints.
            const std::string enrollPassword = m_enrollPassword;
            const int enrollForcedStatus = m_enrollForcedStatus;
            auto lastEnrollBody = std::make_shared<std::string>();
            auto enrollMutex = std::make_shared<std::mutex>();
            auto verifyEnroll = [enrollPassword](const httplib::Request & request)
            {
                if (enrollPassword.empty())
                {
                    return true; // Open mode: no signature expected.
                }

                const auto auth = request.get_header_value("Authorization");
                const std::string prefix = "Bearer ";

                if (auth.rfind(prefix, 0) != 0)
                {
                    return false;
                }

                const auto key = jwt_profile::v1::enroll::deriveEnrollKey(enrollPassword);

                if (!key)
                {
                    return false; // LCOV_EXCL_LINE: HKDF cannot fail for a non-empty password.
                }

                return jwt_profile::v1::enroll::JwtEnrollTokenVerifier::verify(auth.substr(prefix.size()),
                                                                               *key,
                                                                               jwt_profile::v1::TimePolicy {},
                                                                               std::chrono::system_clock::now()) ==
                       jwt_profile::v1::VerifyError::None;
            };

            server.Post(
                "/enroll",
                [verifyEnroll, enrollForcedStatus, lastEnrollBody, enrollMutex](const httplib::Request & request,
                                                                                httplib::Response & response)
            {
                {
                    std::lock_guard<std::mutex> lock(*enrollMutex);
                    *lastEnrollBody = request.body;
                }

                if (!request.has_header("protocol-version"))
                {
                    response.status = 400;
                    response.set_content(
                        R"({"error":{"code":"missing_protocol_version","message":"protocol-version required"}})",
                        "application/json");
                    return;
                }

                if (enrollForcedStatus != 0)
                {
                    response.status = enrollForcedStatus;
                    response.set_content(R"({"error":{"code":"forced","message":"forced by test"}})",
                                         "application/json");
                    return;
                }

                if (!verifyEnroll(request))
                {
                    response.status = 401;
                    response.set_content(R"({"error":{"code":"invalid_signature","message":"signature mismatch"}})",
                                         "application/json");
                    return;
                }

                std::string name = "unknown";

                try
                {
                    const auto parsed = nlohmann::json::parse(request.body);

                    if (parsed.contains("name"))
                    {
                        name = parsed.at("name").get<std::string>();
                    }
                }
                catch (const std::exception&)
                {
                    response.status = 400;
                    response.set_content(R"({"error":{"code":"invalid_body","message":"malformed JSON"}})",
                                         "application/json");
                    return;
                }

                response.status = 200;
                nlohmann::json body;
                body["id"] = "042";
                body["name"] = name;
                body["ip"] = "127.0.0.1";
                body["key"] = "3132333435363738393031323334353637383930313233343536373839303132";
                response.set_content(body.dump(), "application/json");
            });

            server.Get("/peek/enroll",
                       [lastEnrollBody, enrollMutex](const httplib::Request&, httplib::Response & response)
            {
                std::lock_guard<std::mutex> lock(*enrollMutex);
                response.status = 200;
                response.set_content(*lastEnrollBody, "text/plain");
            });
        }

        // Self-signed cert + key generated in-process (no CLI, no files). The
        // client uses HC_VERIFY_NONE, so the cert only needs to exist.
        static void makeSelfSigned(EVP_PKEY** keyOut, X509** certOut)
        {
            EVP_PKEY* pkey = EVP_RSA_gen(2048);
            X509* cert = X509_new();
            ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
            X509_gmtime_adj(X509_get_notBefore(cert), 0);
            X509_gmtime_adj(X509_get_notAfter(cert), 60L * 60L);
            X509_set_pubkey(cert, pkey);
            X509_NAME* name = X509_get_subject_name(cert);
            X509_NAME_add_entry_by_txt(
                name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("127.0.0.1"), -1, -1, 0);
            X509_set_issuer_name(cert, name);
            X509_sign(cert, pkey, EVP_sha256());
            *keyOut = pkey;
            *certOut = cert;
        }

        void runServer()
        {
            if (m_tls)
            {
                EVP_PKEY* pkey = nullptr;
                X509* cert = nullptr;
                makeSelfSigned(&pkey, &cert);
                httplib::SSLServer server {cert, pkey};
                registerEndpoints(server);
                server.listen("127.0.0.1", m_port);
                X509_free(cert);
                EVP_PKEY_free(pkey);
                return;
            }

            httplib::Server server;
            registerEndpoints(server);
            server.listen("127.0.0.1", m_port);
        }

        void waitUntilReady() const
        {
            const char* scheme = m_tls ? "https" : "http";
            const std::string base = std::string {scheme} + "://127.0.0.1:" + std::to_string(m_port);
            httplib::Client probe {base};
            probe.enable_server_certificate_verification(false);

            for (int attempt = 0; attempt < 6000; attempt++)
            {
                if (auto result = probe.Post("/control"))
                {
                    return; // Any HTTP reply means the listener is up.
                }

                usleep(50 * 1000);
            }
        }

        pid_t m_pid {-1};
        uint16_t m_port;
        std::string m_keyHex;
        bool m_tls {false};
        int m_settingsFlipAfter {0};
        std::string m_configBlob;
        size_t m_statelessMaxBody {0};
        int m_rotateKeyAfterNotifies {0};
        std::string m_rotatedKeyHex;
        std::string m_statefulHoldFile;
        uint64_t m_vdFeedOffset {0};
        int m_scanVdRejectFirstNAttempts {0};
        std::string m_enrollPassword;
        int m_enrollForcedStatus {0};
};

#endif // _HC_FAKE_MANAGER_HPP
