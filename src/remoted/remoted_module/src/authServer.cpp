/*
 * Wazuh auth middleware (framework-agnostic)
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "authServer.hpp"

#include <atomic>
#include <map>
#include <mutex>
#include <utility>

#include "authMiddleware.hpp"

// No HTTP-library header appears here yet -- see authServer.hpp. Once a
// library (RESTinio is the current candidate) is wired in, Impl gains the
// actual reactor/listener state and each connection dispatches through
// `middleware` (already built below) instead of start()/stop() just
// flipping a flag.

namespace wazuh_auth
{

    struct AuthServer::Impl
    {
        ServerConfig serverConfig;
        TlsConfig tlsConfig;
        AuthConfig authConfig;
        std::shared_ptr<IAgentKeyResolver> resolver;
        std::shared_ptr<AuthMiddleware> middleware;

        std::mutex routesMutex;
        std::map<std::pair<Method, std::string>, EndpointHandler> routes;

        std::atomic<bool> running {false};
    };

    AuthServer::AuthServer()
        : m_impl(std::make_unique<Impl>())
    {
    }

    AuthServer::~AuthServer()
    {
        stop();
    }

    void
    AuthServer::configure(const ServerConfig& serverConfig, const TlsConfig& tlsConfig, const AuthConfig& authConfig)
    {
        m_impl->serverConfig = serverConfig;
        m_impl->tlsConfig = tlsConfig;
        m_impl->authConfig = authConfig;
    }

    void AuthServer::setKeyResolver(std::shared_ptr<IAgentKeyResolver> resolver)
    {
        m_impl->resolver = std::move(resolver);
    }

    void AuthServer::addRoute(Method method, const std::string& route, EndpointHandler handler)
    {
        std::lock_guard<std::mutex> lock(m_impl->routesMutex);
        m_impl->routes[{method, route}] = std::move(handler);
    }

    void AuthServer::start(bool /*useThread*/)
    {
        // useThread is part of the IAuthServer contract but has nothing to
        // drive yet -- no reactor exists until a transport library is wired in.
        m_impl->middleware = std::make_shared<AuthMiddleware>(m_impl->authConfig, m_impl->resolver);
        m_impl->running = true;
    }

    void AuthServer::stop()
    {
        m_impl->running = false;
        m_impl->middleware.reset();
    }

    bool AuthServer::isRunning() const
    {
        return m_impl->running.load();
    }

} // namespace wazuh_auth
