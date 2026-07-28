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

#include "cmacSigner.hpp"
#include "digest.hpp"
#include "keyProvider.hpp"

#include "external/cpp-httplib/httplib.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <atomic>
#include <csignal>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

/**
 * @brief Fork-based plaintext fake manager (the http-request component-test
 *        idiom). It validates the AES-CMAC of every request server-side with
 *        the shared key, so a 200 proves real cross-implementation auth
 *        interop; a mismatch yields 401. It supports a one-shot 503 (back-
 *        pressure) and a 426 mode.
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
        /// client whose local hash differs downloads it.
        /// statelessMaxBody > 0: a /stateless POST whose body exceeds it gets
        /// 413, so the client must split and resend smaller (#37835).
        /// rotateKeyAfterNotifies > 0 with rotatedKeyHex set: after that many
        /// notifies the server verifies ONLY against rotatedKeyHex, so the old
        /// key starts getting 401 (#37828 re-enrollment).
        FakeManager(uint16_t port, const std::string& keyHex, bool tls = false,
                    int settingsFlipAfter = 0, std::string configBlob = {},
                    size_t statelessMaxBody = 0, int rotateKeyAfterNotifies = 0,
                    std::string rotatedKeyHex = {})
            : m_port(port)
            , m_keyHex(keyHex)
            , m_tls(tls)
            , m_settingsFlipAfter(settingsFlipAfter)
            , m_configBlob(std::move(configBlob))
            , m_statelessMaxBody(statelessMaxBody)
            , m_rotateKeyAfterNotifies(rotateKeyAfterNotifies)
            , m_rotatedKeyHex(std::move(rotatedKeyHex))
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
        static bool verifyCmac(const std::string& keyHex, const std::string& target,
                               const httplib::Request& request)
        {
            const auto auth = request.get_header_value("Authorization");
            // Format: "Wazuh <id>:<ts>:<mac>".
            const auto space = auth.find(' ');

            if (auth.rfind("Wazuh ", 0) != 0 || space == std::string::npos)
            {
                return false;
            }

            const std::string token = auth.substr(space + 1);
            const auto firstColon = token.find(':');
            const auto secondColon = token.rfind(':');

            if (firstColon == std::string::npos || firstColon == secondColon)
            {
                return false;
            }

            const std::string id = token.substr(0, firstColon);
            const std::string ts = token.substr(firstColon + 1, secondColon - firstColon - 1);
            const std::string mac = token.substr(secondColon + 1);

            const std::string canonical =
                "WAZUH-REQUEST\n1\nPOST\n" + target + "\n" + id + "\n" + ts + "\n" + request.body;
            const ConfigKeyProvider provider {keyHex};
            const auto key = provider.cmacKey();

            if (!key)
            {
                return false;
            }

            const auto expected =
                CmacSigner::macHex(*key, reinterpret_cast<const uint8_t*>(canonical.data()),
                                   canonical.size());
            return expected.has_value() && *expected == mac;
        }

        template<typename ServerT>
        void registerEndpoints(ServerT& server)
        {
            const std::string keyHex = m_keyHex;
            const int settingsFlipAfter = m_settingsFlipAfter;
            const std::string configBlob = m_configBlob;
            const size_t statelessMaxBody = m_statelessMaxBody;
            const std::string configHash =
                configBlob.empty() ? std::string {}
                :
                sha256Hex(configBlob.data(), configBlob.size());
            auto backpressureArmed = std::make_shared<std::atomic<bool>>(true);
            auto notifyCount = std::make_shared<std::atomic<int>>(0);

            // The key every endpoint verifies against: after the configured
            // notify count the server rotates to the new key, so requests
            // signed with the old key start getting 401 (#37828).
            const int rotateAfter = m_rotateKeyAfterNotifies;
            const std::string rotatedKey = m_rotatedKeyHex;
            const auto verify = [keyHex, rotatedKey, rotateAfter, notifyCount](
                                    const std::string & target, const httplib::Request & request)
            {
                const bool rotated =
                    rotateAfter > 0 && !rotatedKey.empty() && notifyCount->load() >= rotateAfter;
                return verifyCmac(rotated ? rotatedKey : keyHex, target, request);
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
                       [acceptedEvents, acceptedMutex](const httplib::Request&,
                                                       httplib::Response & response)
            {
                std::lock_guard<std::mutex> lock(*acceptedMutex);
                response.status = 200;
                response.set_content(*acceptedEvents, "text/plain");
            });

            server.Post("/download",
                        [verify, configBlob](const httplib::Request & request,
                                             httplib::Response & response)
            {
                if (!verify("/download", request))
                {
                    response.status = 401;
                    return;
                }

                if (configBlob.empty() ||
                        request.body.find("\"resource_type\":\"config\"") == std::string::npos)
                {
                    response.status = 404;
                    return;
                }

                // Chunked transfer on purpose (#37733 5.2.3): the client's
                // decode + stream-to-file path is exercised for real.
                response.status = 200;
                response.set_chunked_content_provider(
                    "application/octet-stream",
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

            server.Post("/control",
                        [verify, settingsFlipAfter, notifyCount, configHash, controlTypes, controlMutex](
                            const httplib::Request & request, httplib::Response & response)
            {
                if (!verify("/control", request))
                {
                    response.status = 401;
                    return;
                }

                if (request.has_header("X-Reject-Version"))
                {
                    response.status = 426;
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
                // and the settings_hash of the CURRENT startup body.
                static const std::string startupV1 =
                    R"({"limits":{"eps":0},"cluster":{"name":"fake","node":"node01"},)"
                    R"("agent":{"groups":["default"]}})";
                static const std::string startupV2 =
                    R"({"limits":{"eps":100},"cluster":{"name":"fake","node":"node01"},)"
                    R"("agent":{"groups":["default"]}})";
                const bool flipped = settingsFlipAfter > 0 &&
                                     notifyCount->load() >= settingsFlipAfter;
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
                    const std::string agent =
                        configHash.empty()
                        ? std::string {R"({"groups":["default"]})"}
                        :
                        R"({"groups":["default"],"config_hash":")" + configHash + R"("})";
                    response.set_content(
                        R"({"agent":)" + agent + R"(,"settings_hash":")" +
                        sha256Hex(startupBody.data(), startupBody.size()) + R"("})",
                        "application/json");
                    return;
                }

                if (request.body.find("\"type\":\"shutdown\"") != std::string::npos)
                {
                    response.set_content("{}", "application/json"); // Disconnect ack.
                    return;
                }

                // Unknown /control type: 400.
                response.status = 400;
                response.set_content(R"({"error":"unknown control type"})", "application/json");
            });

            server.Get("/peek/control",
                       [controlTypes, controlMutex](const httplib::Request&,
                                                    httplib::Response & response)
            {
                std::lock_guard<std::mutex> lock(*controlMutex);
                response.status = 200;
                response.set_content(*controlTypes, "text/plain");
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
            X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char*>("127.0.0.1"), -1, -1, 0);
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

            for (int attempt = 0; attempt < 200; attempt++)
            {
                if (auto result = probe.Post("/control"))
                {
                    return; // Any HTTP reply means the listener is up.
                }

                usleep(20 * 1000);
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
};

#endif // _HC_FAKE_MANAGER_HPP
