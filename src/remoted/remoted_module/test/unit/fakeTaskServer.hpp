/*
 * Wazuh remoted module - Fake Task Manager HTTP-over-UDS server for tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Stands in for the Task Manager's POST /v1/tasks/pending and /v1/tasks/wpk-authorization routes.
 *
 * NOT fakeUdsServer.hpp, which emulates the `[uint32_t size][payload]` SizeHeaderProtocol. The
 * Task Manager serves HTTP/1.1 over its socket now and TaskClient reaches it through
 * AsioUdsHttpClient, so a framed fake answers a request the client cannot read and every call
 * fails as an I/O error -- which is a test asserting on the harness rather than on the client.
 * This fake serves through the same uds_http_server the Task Manager does (see udsHttpTestServer.hpp),
 * with the same route class, which keeps the status codes and body framing honest, the same way
 * fakeVdServer.hpp does for the VD module.
 */

#ifndef _REMOTED_MODULE_TEST_FAKE_TASK_SERVER_HPP
#define _REMOTED_MODULE_TEST_FAKE_TASK_SERVER_HPP

#include "udsHttpTestServer.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>

namespace remoted::test
{
    class FakeTaskServer
    {
    public:
        using Handler = TestHandler;

        explicit FakeTaskServer(std::string socketPath)
            : m_server(std::move(socketPath), "FakeTaskServer")
        {
            route("/v1/tasks/pending", m_lastBody);
            route("/v1/tasks/wpk-authorization", m_lastWpkAuthorizationBody);

            m_server.start();
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
            setHandler([body = std::move(body), status](const wazuh::uds_http::HttpRequest&,
                                                        wazuh::uds_http::HttpResponse& res)
                       { res = wazuh::uds_http::HttpResponse::json(status, body); });
        }

        /// @brief Answer with a status and no body, for the non-2xx path.
        void setStatus(int status)
        {
            setHandler([status](const wazuh::uds_http::HttpRequest&, wazuh::uds_http::HttpResponse& res)
                       { res.status = status; });
        }

        /// @brief Hold every request open for `duration`, so the client's own deadline is what
        ///        ends it. This is how a timeout is produced without waiting out a real one.
        void setStall(std::chrono::milliseconds duration)
        {
            setHandler(
                [duration](const wazuh::uds_http::HttpRequest&, wazuh::uds_http::HttpResponse& res)
                {
                    std::this_thread::sleep_for(duration);
                    res = wazuh::uds_http::HttpResponse::json(200, "{}");
                });
        }

        std::string lastBody() const
        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            return m_lastBody;
        }

        std::string lastWpkAuthorizationBody() const
        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            return m_lastWpkAuthorizationBody;
        }

        /// @brief Path of the last request on any route.
        std::string lastPath() const
        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            return m_lastPath;
        }

        /// @brief Requests received on any route.
        std::size_t requestCount() const
        {
            return m_requestCount.load();
        }

    private:
        void route(const std::string& path, std::string& lastBody)
        {
            m_server.addRoute(
                wazuh::uds_http::Method::Post,
                path,
                wazuh::uds_http::RouteOptions {wazuh::uds_http::RouteClass::Data},
                [this, &lastBody](const wazuh::uds_http::HttpRequest& req)
                {
                    m_requestCount.fetch_add(1);
                    std::lock_guard<std::mutex> lock(m_stateMutex);
                    lastBody = req.body;
                    m_lastPath = req.target;
                },
                [this] { return copyHandler(); });
        }

        // Copied under the lock and run outside it, on the request's worker: a stalling handler holding the
        // mutex would serialize every request behind one parked one.
        Handler copyHandler() const
        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            return m_handler;
        }

        mutable std::mutex m_stateMutex;
        Handler m_handler;
        std::string m_lastBody;
        std::string m_lastWpkAuthorizationBody;
        std::string m_lastPath;
        std::atomic<std::size_t> m_requestCount {0};
        // Last on purpose: destroyed first, so its workers are joined while the handlers they run are still here.
        UdsHttpTestServer m_server;
    };
} // namespace remoted::test

#endif // _REMOTED_MODULE_TEST_FAKE_TASK_SERVER_HPP
