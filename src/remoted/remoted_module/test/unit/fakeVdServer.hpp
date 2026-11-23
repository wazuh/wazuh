/*
 * Wazuh remoted module - Fake VD module HTTP-over-UDS server for tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Stands in for the VD module's /vulnerability-detector/offset (and /scan) endpoints. Unlike
 * fakeUdsServer.hpp (which emulates WazuhDBClient's `[uint32_t size][payload]` SizeHeaderProtocol),
 * VdClient and ScanVdHandlerImpl speak real HTTP/1.1 through remoted's AsioUdsHttpClient -- so this
 * fake serves through the same uds_http_server the VD module does (see udsHttpTestServer.hpp), with
 * the same route classes and scan body cap, not a hand-rolled protocol stub, to avoid subtly
 * diverging from how the real VD module actually behaves (status codes, body framing, etc.).
 */

#ifndef _REMOTED_MODULE_TEST_FAKE_VD_SERVER_HPP
#define _REMOTED_MODULE_TEST_FAKE_VD_SERVER_HPP

#include "udsHttpTestServer.hpp"

#include <atomic>
#include <json.hpp>
#include <mutex>
#include <string>
#include <unistd.h>

namespace remoted::test
{
    class FakeVdServer
    {
    public:
        using Handler = TestHandler;

        explicit FakeVdServer(std::string socketPath)
            : m_server(std::move(socketPath), "FakeVdServer")
        {
            m_server.addRoute(
                wazuh::uds_http::Method::Get,
                "/vulnerability-detector/offset",
                wazuh::uds_http::RouteOptions {wazuh::uds_http::RouteClass::Liveness},
                [this](const wazuh::uds_http::HttpRequest&) { m_offsetRequestCount.fetch_add(1); },
                [this] { return copyHandler(m_offsetHandler); });

            // A small control request in the VD module too: a body past 4 KiB is refused before any handler.
            wazuh::uds_http::RouteOptions scanRoute {wazuh::uds_http::RouteClass::Control};
            scanRoute.maxBodyBytes = 4096;
            m_server.addRoute(
                wazuh::uds_http::Method::Post,
                "/vulnerability-detector/scan",
                scanRoute,
                [this](const wazuh::uds_http::HttpRequest&) { m_scanRequestCount.fetch_add(1); },
                [this] { return copyHandler(m_scanHandler); });

            m_server.start();
        }

        FakeVdServer(const FakeVdServer&) = delete;
        FakeVdServer& operator=(const FakeVdServer&) = delete;

        /// @brief Set the handler invoked for GET /vulnerability-detector/offset. Safe to call
        /// while requests are in flight (tests move the offset mid-test): the swap and the route
        /// lambdas' reads share m_handlerMutex.
        void setOffsetHandler(Handler handler)
        {
            std::lock_guard<std::mutex> lock(m_handlerMutex);
            m_offsetHandler = std::move(handler);
        }

        /// @brief Set the handler invoked for POST /vulnerability-detector/scan.
        void setScanHandler(Handler handler)
        {
            std::lock_guard<std::mutex> lock(m_handlerMutex);
            m_scanHandler = std::move(handler);
        }

        /// @brief Convenience: respond 200 with {"offset": offset} to every offset request.
        void setOffset(uint64_t offset)
        {
            setOffsetHandler(
                [offset](const wazuh::uds_http::HttpRequest&, wazuh::uds_http::HttpResponse& res)
                { res = wazuh::uds_http::HttpResponse::json(200, nlohmann::json {{"offset", offset}}.dump()); });
        }

        /// @brief Convenience: fail every offset request with the given HTTP status (default 500).
        void setOffsetFailure(int status = 500)
        {
            setOffsetHandler([status](const wazuh::uds_http::HttpRequest&, wazuh::uds_http::HttpResponse& res)
                             { res.status = status; });
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
        // Copied under the lock and run outside it, on the request's worker: handlers may block (gated
        // tests), and holding the mutex across the call would serialize every request behind one parked one.
        Handler copyHandler(const Handler& handler) const
        {
            std::lock_guard<std::mutex> lock(m_handlerMutex);
            return handler;
        }

        mutable std::mutex m_handlerMutex;
        Handler m_offsetHandler;
        Handler m_scanHandler;
        std::atomic<size_t> m_offsetRequestCount {0};
        std::atomic<size_t> m_scanRequestCount {0};
        // Last on purpose: destroyed first, so its workers are joined while the handlers they run are still here.
        UdsHttpTestServer m_server;
    };

    /// @brief Build a unique UDS path per test, same convention as fakeUdsServer.hpp's helper.
    inline std::string makeUniqueVdSocketPath(const std::string& tag)
    {
        return "/tmp/wazuh_vd_" + tag + "_" + std::to_string(::getpid()) + "_" +
               std::to_string(reinterpret_cast<uintptr_t>(&tag)) + ".sock";
    }
} // namespace remoted::test

#endif // _REMOTED_MODULE_TEST_FAKE_VD_SERVER_HPP
