/*
 * Wazuh remoted module - Fake VD module HTTP-over-UDS server for tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 10, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Stands in for the VD module's /vulnerability-detector/offset (and /scan) endpoints. Unlike
 * fakeUdsServer.hpp (which emulates the WazuhDBClient/TaskClient SizeHeaderProtocol), VdClient
 * and ScanVdHandlerImpl are real httplib::Client callers speaking real HTTP -- so this fake is a
 * real httplib::Server bound to a UDS socket, not a hand-rolled protocol stub, to avoid subtly
 * diverging from how the real VD module actually behaves (status codes, body framing, etc.).
 */

#ifndef _REMOTED_MODULE_TEST_FAKE_VD_SERVER_HPP
#define _REMOTED_MODULE_TEST_FAKE_VD_SERVER_HPP

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <httplib.h>
#include <json.hpp>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>

namespace remoted::test
{
    class FakeVdServer
    {
    public:
        using Handler = std::function<void(const httplib::Request&, httplib::Response&)>;

        explicit FakeVdServer(std::string socketPath)
            : m_socketPath(std::move(socketPath))
        {
            std::filesystem::remove(m_socketPath);
            m_server.set_address_family(AF_UNIX);

            m_server.Get("/vulnerability-detector/offset",
                         [this](const httplib::Request& req, httplib::Response& res)
                         {
                             m_offsetRequestCount.fetch_add(1);
                             if (m_offsetHandler)
                             {
                                 m_offsetHandler(req, res);
                             }
                         });

            m_server.Post("/vulnerability-detector/scan",
                          [this](const httplib::Request& req, httplib::Response& res)
                          {
                              m_scanRequestCount.fetch_add(1);
                              if (m_scanHandler)
                              {
                                  m_scanHandler(req, res);
                              }
                          });

            m_thread = std::thread(
                [this]
                {
                    if (!m_server.bind_to_port(m_socketPath, 80))
                    {
                        m_bindFailed.store(true);
                        return;
                    }
                    m_server.listen_after_bind();
                });

            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (!m_server.is_running() && !m_bindFailed.load() && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }

            if (m_bindFailed.load() || !m_server.is_running())
            {
                if (m_thread.joinable())
                {
                    m_thread.join();
                }
                throw std::runtime_error("FakeVdServer failed to bind " + m_socketPath);
            }
        }

        ~FakeVdServer()
        {
            m_server.stop();
            if (m_thread.joinable())
            {
                m_thread.join();
            }
            std::filesystem::remove(m_socketPath);
        }

        FakeVdServer(const FakeVdServer&) = delete;
        FakeVdServer& operator=(const FakeVdServer&) = delete;

        /// @brief Set the handler invoked for GET /vulnerability-detector/offset.
        void setOffsetHandler(Handler handler)
        {
            m_offsetHandler = std::move(handler);
        }

        /// @brief Set the handler invoked for POST /vulnerability-detector/scan.
        void setScanHandler(Handler handler)
        {
            m_scanHandler = std::move(handler);
        }

        /// @brief Convenience: respond 200 with {"offset": offset} to every offset request.
        void setOffset(uint64_t offset)
        {
            setOffsetHandler([offset](const httplib::Request&, httplib::Response& res)
                             { res.set_content(nlohmann::json {{"offset", offset}}.dump(), "application/json"); });
        }

        /// @brief Convenience: fail every offset request with the given HTTP status (default 500).
        void setOffsetFailure(int status = 500)
        {
            setOffsetHandler([status](const httplib::Request&, httplib::Response& res) { res.status = status; });
        }

        size_t offsetRequestCount() const
        {
            return m_offsetRequestCount.load();
        }

        size_t scanRequestCount() const
        {
            return m_scanRequestCount.load();
        }

    private:
        std::string m_socketPath;
        httplib::Server m_server;
        std::thread m_thread;
        Handler m_offsetHandler;
        Handler m_scanHandler;
        std::atomic<bool> m_bindFailed {false};
        std::atomic<size_t> m_offsetRequestCount {0};
        std::atomic<size_t> m_scanRequestCount {0};
    };

    /// @brief Build a unique UDS path per test, same convention as fakeUdsServer.hpp's helper.
    inline std::string makeUniqueVdSocketPath(const std::string& tag)
    {
        return "/tmp/wazuh_vd_" + tag + "_" + std::to_string(::getpid()) + "_" +
               std::to_string(reinterpret_cast<uintptr_t>(&tag)) + ".sock";
    }
} // namespace remoted::test

#endif // _REMOTED_MODULE_TEST_FAKE_VD_SERVER_HPP
