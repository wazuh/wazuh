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

#ifndef _REMOTED_ENDPOINTS_AUTH_GATEWAY_HPP
#define _REMOTED_ENDPOINTS_AUTH_GATEWAY_HPP

#include "auth/authMiddleware.hpp"     // remoted::auth::AuthMiddleware
#include "auth/authTypes.hpp"          // remoted::auth::AuthConfig
#include "auth/iAgentKeystore.hpp"     // remoted::auth::IAgentKeystore
#include "decoding/iBodyDecoder.hpp"   // remoted::decoding::IBodyDecoder
#include "endpoint.hpp"                // AuthenticatedHandler + shared type aliases
#include "http_server/IHttpServer.hpp" // remoted::http::IHttpServer

#include <memory>
#include <string>

namespace remoted::endpoints
{

    /**
     * @brief Applies the agent<->manager auth protocol in front of endpoint handlers.
     *
     * Header/auth validation is common to (almost) every endpoint and always
     * synchronous (AES-CMAC over CPU). Instead of each endpoint repeating it, the
     * gateway owns one AuthMiddleware and registers, on our transport-agnostic
     * IHttpServer, a raw async route whose worker-thread body:
     *   1. runs the full validation (protocol-version + Authorization + timestamp
     *      window + key lookup + AES-CMAC over the exact wire body bytes -- the MAC
     *      always covers what was actually sent, compressed or not),
     *   2. on failure, answers with publicErrorFor()'s status/message,
     *   3. on success, runs the injected IBodyDecoder over the verified body and
     *      answers with publicErrorFor() if it rejects, then
     *   4. hands the verified (and, if applicable, decoded) request and the responder to
     *      the handler.
     *
     * Step 3 is a plain dependency on purpose: the gateway does not know which
     * `Content-Encoding` values exist, how a body is decoded, or how the memory that costs
     * is accounted for -- only that the step can fail with an AuthError. That keeps this
     * class about authentication alone, and keeps decoding independently testable (it lives in
     * its own layer, `src/decoding/`). Because the decoder is configured once here rather than per route,
     * a new endpoint cannot accidentally opt out of it.
     *
     * The gateway is the only adapter between remoted::auth (framework-agnostic) and
     * remoted::http (our transport); swapping the HTTP library never touches it.
     */
    class AuthGateway
    {
    public:
        /**
         * @param config      Auth-protocol tunables (protocol version, timestamp window, max body size).
         * @param keystore    Agent-key lookup; must outlive the routes registered through this gateway.
         * @param bodyDecoder Post-authentication body-decoding step (see IBodyDecoder). Required, and
         *                    must be non-null: every authenticated route runs it, and it owns the
         *                    whole `Content-Encoding` policy -- including deciding that an absent
         *                    header means "pass the body through untouched". Making it optional would
         *                    mean a second copy of that policy here, free to drift from the real one.
         */
        AuthGateway(remoted::auth::AuthConfig config,
                    std::shared_ptr<remoted::auth::IAgentKeystore> keystore,
                    std::shared_ptr<const remoted::decoding::IBodyDecoder> bodyDecoder);

        /**
         * @brief Register an authenticated endpoint. Call before IHttpServer::start().
         *
         * @param server  Transport to register the route on.
         * @param method  HTTP method to match.
         * @param path    Path to match (the query string is not matched, but IS part of the MAC).
         * @param handler Invoked only after authentication succeeds; owns sending the response.
         * @param mode    Whether the handler may answer with a streamed body. Forwarded verbatim to
         *                IHttpServer::addRoute(): the transport fixes a response's output mode when
         *                the request is dispatched, so a route that streams must declare it here.
         */
        void addAuthenticatedRoute(remoted::http::IHttpServer& server,
                                   Method method,
                                   const std::string& path,
                                   AuthenticatedHandler handler,
                                   remoted::http::ResponseMode mode = remoted::http::ResponseMode::Buffered);

    private:
        std::shared_ptr<remoted::auth::AuthMiddleware> m_middleware;
        std::shared_ptr<const remoted::decoding::IBodyDecoder> m_bodyDecoder; ///< Post-auth body decoding; never null.
    };

} // namespace remoted::endpoints

#endif // _REMOTED_ENDPOINTS_AUTH_GATEWAY_HPP
