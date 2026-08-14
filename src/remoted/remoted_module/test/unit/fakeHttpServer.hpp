/*
 * Wazuh remoted module (C++ worker bridge) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_MODULE_TEST_FAKE_HTTP_SERVER_HPP
#define _REMOTED_MODULE_TEST_FAKE_HTTP_SERVER_HPP

#include "http_server/IHttpServer.hpp"

#include <cstddef>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace remoted::testutil
{

    /**
     * @brief Fake transport: stores registered routes so a test can dispatch them directly
     *        (synchronously, no sockets), exactly as a route handler would run on a worker thread.
     *
     * Uses a REAL InFlightBudget (already transport-agnostic -- plain atomics, no RESTinio/asio)
     * rather than a fake counter, so tests exercise the actual reserve/grow/release mechanics
     * production relies on instead of a simplified stand-in that could behave differently.
     */
    class FakeHttpServer final : public remoted::http::IHttpServer
    {
    public:
        // Defaults to a budget generously larger than anything a test fixture will need, i.e. "no
        // meaningful constraint" in practice; tests that care about reservation behavior construct
        // with a small value instead.
        explicit FakeHttpServer(std::size_t maxInFlightBytes = std::numeric_limits<std::size_t>::max() / 2)
            : m_budget {maxInFlightBytes}
        {
        }

        void addRoute(remoted::http::Method method,
                      const std::string& path,
                      remoted::http::RouteHandler handler,
                      bool /*countAgainstBudget*/,
                      remoted::http::ResponseMode mode) override
        {
            m_routes[{method, path}] = std::move(handler);
            m_modes[{method, path}] = mode;
        }

        /// @brief The response mode a route was registered with, for asserting the registration.
        remoted::http::ResponseMode modeOf(remoted::http::Method method, const std::string& path) const
        {
            const auto it = m_modes.find({method, path});
            return it == m_modes.end() ? remoted::http::ResponseMode::Buffered : it->second;
        }
        std::optional<remoted::http::InFlightBudget::Reservation>
        tryReserveInFlightBytes(std::size_t bytes) override
        {
            return m_budget.tryReserve(bytes);
        }
        void start(const remoted::http::HttpServerConfig&) override {}
        void stopAccepting() noexcept override {}
        void stop() noexcept override {}

        remoted::http::InFlightBudget m_budget;

        void dispatch(remoted::http::Method method,
                      const std::string& path,
                      const remoted::http::HttpRequest& request,
                      std::shared_ptr<remoted::http::IHttpResponder> responder)
        {
            // The transport hands the handler a shared_ptr<const>; mirror that here.
            m_routes.at({method, path})(std::make_shared<const remoted::http::HttpRequest>(request),
                                        std::move(responder));
        }

        bool hasRoute(remoted::http::Method method, const std::string& path) const
        {
            return m_routes.count({method, path}) != 0;
        }

    private:
        std::map<std::pair<remoted::http::Method, std::string>, remoted::http::RouteHandler> m_routes;
        std::map<std::pair<remoted::http::Method, std::string>, remoted::http::ResponseMode> m_modes;
    };

} // namespace remoted::testutil

#endif // _REMOTED_MODULE_TEST_FAKE_HTTP_SERVER_HPP
