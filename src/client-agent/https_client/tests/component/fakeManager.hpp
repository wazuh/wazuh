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
#include "keyProvider.hpp"

#include "external/cpp-httplib/httplib.h"

#include <atomic>
#include <csignal>
#include <cstdint>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

/**
 * @brief Fork-based plaintext fake manager (the http-request component-test
 *        idiom). It validates the AES-CMAC of every request server-side with
 *        the shared key, so a 200 proves real cross-implementation auth
 *        interop; a mismatch yields 401. It supports a one-shot 503 (back-
 *        pressure), a session LRU-of-one (dedup), and a 426 mode.
 *
 * The child process runs the server; the parent asserts on the responses it
 * receives (the two sides do not share memory).
 */
class FakeManager final
{
public:
    explicit FakeManager(uint16_t port, const std::string& keyHex)
        : m_port(port)
        , m_keyHex(keyHex)
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

    void runServer()
    {
        httplib::Server server;
        const std::string keyHex = m_keyHex;
        auto backpressureArmed = std::make_shared<std::atomic<bool>>(true);
        auto lastSession = std::make_shared<std::string>();

        server.Post("/stateless",
                    [keyHex, backpressureArmed](const httplib::Request& request, httplib::Response& response)
                    {
                        if (!verifyCmac(keyHex, "/stateless", request))
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
                        response.status = 200;
                        response.set_content(request.body, "text/plain"); // Echo for body assertions.
                    });

        server.Post("/stateful",
                    [keyHex, lastSession](const httplib::Request& request, httplib::Response& response)
                    {
                        if (!verifyCmac(keyHex, "/stateful", request))
                        {
                            response.status = 401;
                            return;
                        }
                        const auto session = request.get_header_value("X-Session-Id");
                        const bool cached = (*lastSession == session);
                        *lastSession = session;
                        response.status = 200;
                        response.set_content(
                            std::string {"{\"sessionId\":\""} + session + "\",\"cached\":" +
                                (cached ? "true" : "false") + ",\"bytes\":" +
                                std::to_string(request.body.size()) + "}",
                            "application/json");
                    });

        server.Post("/control",
                    [keyHex](const httplib::Request& request, httplib::Response& response)
                    {
                        if (!verifyCmac(keyHex, "/control", request))
                        {
                            response.status = 401;
                            return;
                        }
                        if (request.has_header("X-Reject-Version"))
                        {
                            response.status = 426;
                            return;
                        }
                        response.status = 200;
                        response.set_content(R"({"limits":{"eps":0}})", "application/json");
                    });

        server.listen("127.0.0.1", m_port);
    }

    void waitUntilReady()
    {
        httplib::Client probe {"127.0.0.1", m_port};
        for (int attempt = 0; attempt < 100; attempt++)
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
};

#endif // _HC_FAKE_MANAGER_HPP
