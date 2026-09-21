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

#include "auth/authMiddleware.hpp"             // remoted::auth::AuthMiddleware
#include "auth/authTypes.hpp"                  // remoted::auth::AuthConfig
#include "auth/iAgentKeystore.hpp"             // remoted::auth::IAgentKeystore
#include "common/requestOutcomeMetrics.hpp"    // remoted::metrics::EndpointHttpMetrics
#include "decoding/iBodyDecoder.hpp"           // remoted::decoding::IBodyDecoder
#include "endpoint.hpp"                        // AuthenticatedHandler + shared type aliases
#include "http_server/IHttpServer.hpp"         // remoted::http::IHttpServer
#include "http_server/endpointRateLimiter.hpp" // remoted::http::EndpointRateLimiter

#include <functional>
#include <memory>
#include <string>

#include <wazuh_metrics/iManager.hpp>

namespace remoted::endpoints
{

    /**
     * @brief Optional rate limit charged in front of ONE authenticated route.
     *
     * Why it lives here rather than in endpoints/rateLimitGate.hpp's wrap(): that helper takes and
     * returns a remoted::http::RouteHandler, while addAuthenticatedRoute() takes an
     * AuthenticatedHandler and builds the RouteHandler itself, with authenticate() inside it. So a
     * wrapped handler could only ever be charged AFTER authentication -- which would put 401 before
     * 429 and make every refusal pay a keystore lookup and an HMAC. The gate is charged inside the
     * registered lambda instead, before authenticate() and before the `receivedAt` stamp, with
     * wrap()'s semantics reproduced exactly (see authGateway.cpp).
     *
     * Default-constructed it is inert, which is what keeps the six existing authenticated routes
     * untouched: a null or disabled limiter is resolved once at registration and costs one pointer
     * test per request.
     */
    struct AuthenticatedRouteGate
    {
        /// The bucket. Shared with the facade, which publishes its diagnostics as pull metrics.
        /// Null (or a limiter with rate 0) makes the whole gate a no-op.
        std::shared_ptr<remoted::http::EndpointRateLimiter> limiter;
        /// Builds the 429 body in the ROUTE's own error envelope -- the gate has no business
        /// choosing between the envelopes the endpoints use. `Retry-After` is the gate's to add.
        std::function<remoted::http::HttpResponse()> rejection;
        /// The route's `remoted.<endpoint>.rate_limited` counter (the WHY). May be null.
        std::shared_ptr<wazuh::metrics::ICounter> rejected;
        /// The route's `remoted.http.<endpoint>.responses.*` family (the WHAT). Only the 429 cell
        /// is touched, never the latency histogram: the request never entered the handler. Raw
        /// pointer, so it must outlive every route registered with this gate.
        const remoted::metrics::EndpointHttpMetrics* httpMetrics {nullptr};
        /// Route name for the throttled log line ("POST /enroll/secret").
        const char* route {nullptr};
    };

    /**
     * @brief Applies the agent<->manager auth protocol in front of endpoint handlers.
     *
     * Header/auth validation is common to (almost) every endpoint and always
     * synchronous (HMAC over CPU). Instead of each endpoint repeating it, the
     * gateway owns one AuthMiddleware and registers, on our transport-agnostic
     * IHttpServer, a raw async route whose worker-thread body:
     *   1. runs the full validation (protocol-version + `Bearer` wazuh-agent+jwt token:
     *      key lookup + address rule + signature/claims/time policy -- header-only, the
     *      body is not part of authentication) and the authenticated-body size cap,
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
         * @param path    Path to match (the query string is not matched; nor is it part of authentication).
         * @param handler Invoked only after authentication succeeds; owns sending the response.
         * @param mode    Whether the handler may answer with a streamed body. Forwarded verbatim to
         *                IHttpServer::addRoute(): the transport fixes a response's output mode when
         *                the request is dispatched, so a route that streams must declare it here.
         * @param gate    Optional per-route rate limit, charged BEFORE authentication (see
         *                AuthenticatedRouteGate). Default-constructed -> no gate at all.
         *
         * @warning A gate whose limiter is still null at registration time is silently inert -- no
         * log, no error -- and the route then ships unlimited. The facade constructs
         * m_enrollRateLimiter AFTER its authenticated-route block, so a registration that wants a
         * gate must sit below that construction.
         */
        void addAuthenticatedRoute(remoted::http::IHttpServer& server,
                                   Method method,
                                   const std::string& path,
                                   AuthenticatedHandler handler,
                                   remoted::http::ResponseMode mode = remoted::http::ResponseMode::Buffered,
                                   AuthenticatedRouteGate gate = {});

    private:
        std::shared_ptr<remoted::auth::AuthMiddleware> m_middleware;
        std::shared_ptr<const remoted::decoding::IBodyDecoder> m_bodyDecoder; ///< Post-auth body decoding; never null.
    };

} // namespace remoted::endpoints

#endif // _REMOTED_ENDPOINTS_AUTH_GATEWAY_HPP
