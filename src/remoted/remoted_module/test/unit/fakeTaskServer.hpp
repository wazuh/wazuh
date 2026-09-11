/*
 * Wazuh remoted module - Fake Task Manager HTTP-over-UDS server for tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Stands in for the Task Manager's POST /v1/tasks/pending route.
 *
 * NOT fakeUdsServer.hpp, which emulates the `[uint32_t size][payload]` SizeHeaderProtocol. The
 * Task Manager serves HTTP/1.1 over its socket now and TaskClient reaches it through
 * AsioUdsHttpClient, so a framed fake answers a request the client cannot read and every call
 * fails as an I/O error -- which is a test asserting on the harness rather than on the client.
 * A real httplib::Server bound to a UDS keeps the status codes and body framing honest, the same
 * way fakeVdServer.hpp does for the VD module.
 */

#ifndef _REMOTED_MODULE_TEST_FAKE_TASK_SERVER_HPP
#define _REMOTED_MODULE_TEST_FAKE_TASK_SERVER_HPP

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <httplib.h>
#include <json.hpp>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

namespace remoted::test
{
    class FakeTaskServer
    {
    public:
        using Handler = std::function<void(const httplib::Request&, httplib::Response&)>;

        explicit FakeTaskServer(std::string socketPath)
            : m_socketPath(std::move(socketPath))
        {
            std::filesystem::remove(m_socketPath);
            m_server.set_address_family(AF_UNIX);

            m_server.Post("/v1/tasks/pending",
                          [this](const httplib::Request& req, httplib::Response& res)
                          {
                              m_requestCount.fetch_add(1);
                              {
                                  std::lock_guard<std::mutex> lock(m_stateMutex);
                                  m_lastBody = req.body;
                              }
                              if (const auto handler = copyHandler())
                              {
                                  handler(req, res);
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
                throw std::runtime_error("FakeTaskServer failed to bind " + m_socketPath);
            }
        }

        ~FakeTaskServer()
        {
            m_server.stop();
            if (m_thread.joinable())
            {
                m_thread.join();
            }
            std::filesystem::remove(m_socketPath);
        }

        FakeTaskServer(const FakeTaskServer&) = delete;
        FakeTaskServer& operator=(const FakeTaskServer&) = delete;

        void setHandler(Handler handler)
        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            m_handler = std::move(handler);
        }

        /// @brief Answer every request 200 with `body` verbatim -- including a body that is not
        ///        JSON, which is one of the cases the client has to survive.
        void setBody(std::string body, int status = 200)
        {
            setHandler(
                [body = std::move(body), status](const httplib::Request&, httplib::Response& res)
                {
                    res.status = status;
                    res.set_content(body, "application/json");
                });
        }

        /// @brief Answer with a status and no body, for the non-2xx path.
        void setStatus(int status)
        {
            setHandler([status](const httplib::Request&, httplib::Response& res) { res.status = status; });
        }

        /// @brief Hold every request open for `duration`, so the client's own deadline is what
        ///        ends it. This is how a timeout is produced without waiting out a real one.
        void setStall(std::chrono::milliseconds duration)
        {
            setHandler(
                [duration](const httplib::Request&, httplib::Response& res)
                {
                    std::this_thread::sleep_for(duration);
                    res.set_content("{}", "application/json");
                });
        }

        std::string lastBody() const
        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            return m_lastBody;
        }

        std::size_t requestCount() const
        {
            return m_requestCount.load();
        }

    private:
        // Copied under the lock and invoked outside it: a stalling handler holding the mutex would
        // serialize the whole pool behind one parked request.
        Handler copyHandler() const
        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            return m_handler;
        }

        std::string m_socketPath;
        httplib::Server m_server;
        std::thread m_thread;
        mutable std::mutex m_stateMutex;
        Handler m_handler;
        std::string m_lastBody;
        std::atomic<bool> m_bindFailed {false};
        std::atomic<std::size_t> m_requestCount {0};
    };
} // namespace remoted::test

#endif // _REMOTED_MODULE_TEST_FAKE_TASK_SERVER_HPP
