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

#pragma once

#include <memory>
#include <string>

#include "iAgentKeyResolver.hpp"
#include "iAuthServer.hpp"
#include "serverConfig.hpp"

namespace wazuh_auth
{

    /**
     * @brief IAuthServer implementation; the HTTP library behind it is not
     *        chosen yet.
     *
     * Shape only for now: configure()/setKeyResolver()/addRoute() store what
     * they're given and start()/stop()/isRunning() track a plain running
     * flag -- no HTTP-library type appears anywhere here or in authServer.cpp
     * yet, so this compiles and is unit-testable (lifecycle only) before a
     * concrete library is wired in. Whatever library is chosen (RESTinio is
     * the current candidate) stays confined to authServer.cpp via pimpl, same
     * as the rest of this interface -- this header stays library-agnostic so
     * callers don't leak library-specific includes transitively.
     */
    class AuthServer : public IAuthServer<AuthServer>
    {
    public:
        AuthServer();
        ~AuthServer();

        AuthServer(const AuthServer&) = delete;
        AuthServer& operator=(const AuthServer&) = delete;

        void configure(const ServerConfig& serverConfig, const TlsConfig& tlsConfig, const AuthConfig& authConfig);
        void setKeyResolver(std::shared_ptr<IAgentKeyResolver> resolver);
        void addRoute(Method method, const std::string& route, EndpointHandler handler);
        void start(bool useThread = true);
        void stop();
        bool isRunning() const;

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace wazuh_auth
