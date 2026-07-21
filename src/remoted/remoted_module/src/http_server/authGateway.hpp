/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_AUTH_GATEWAY_HPP
#define _REMOTED_HTTP_AUTH_GATEWAY_HPP

#include "IHttpServer.hpp"
#include "authMiddleware.hpp"    // wazuh_auth::AuthMiddleware
#include "authTypes.hpp"         // wazuh_auth::AuthenticatedRequest, AuthConfig
#include "iAgentKeyResolver.hpp" // wazuh_auth::IAgentKeyResolver

#include <functional>
#include <memory>
#include <string>

namespace remoted::http
{

/**
 * @brief Post-authentication endpoint handler.
 *
 * Runs only after the AES-CMAC validation succeeds and receives the verified
 * request as a parameter. Synchronous: it executes on the server's worker pool
 * (never on the I/O threads), so it may block without stalling the transport.
 */
using AuthenticatedHandler = std::function<HttpResponse(const wazuh_auth::AuthenticatedRequest&)>;

/**
 * @brief Applies the agent<->manager auth protocol in front of endpoint handlers.
 *
 * Header/auth validation is common to (almost) every endpoint and always
 * synchronous (AES-CMAC over CPU). Instead of each endpoint repeating it, the
 * gateway owns one AuthMiddleware and registers, on our transport-agnostic
 * IHttpServer, a raw async route whose worker-thread body:
 *   1. runs the full validation (protocol-version + Authorization + timestamp
 *      window + key resolution + AES-CMAC over the exact body bytes),
 *   2. on failure, answers with publicErrorFor()'s status/message, and
 *   3. on success, calls the AuthenticatedHandler with the verified request.
 *
 * The gateway is the only adapter between wazuh_auth (framework-agnostic) and
 * remoted::http (our transport); swapping the HTTP library never touches it.
 */
class AuthGateway
{
public:
    /**
     * @param config   Auth-protocol tunables (protocol version, timestamp window, max body size).
     * @param resolver Agent-key lookup; must outlive the routes registered through this gateway.
     */
    AuthGateway(wazuh_auth::AuthConfig config, std::shared_ptr<wazuh_auth::IAgentKeyResolver> resolver);

    /**
     * @brief Register an authenticated endpoint. Call before IHttpServer::start().
     *
     * @param server  Transport to register the route on.
     * @param method  HTTP method to match.
     * @param path    Path to match (the query string is not matched, but IS part of the MAC).
     * @param handler Invoked only after authentication succeeds.
     */
    void addAuthenticatedRoute(IHttpServer& server, Method method, const std::string& path, AuthenticatedHandler handler);

private:
    std::shared_ptr<wazuh_auth::AuthMiddleware> m_middleware;
};

} // namespace remoted::http

#endif // _REMOTED_HTTP_AUTH_GATEWAY_HPP
