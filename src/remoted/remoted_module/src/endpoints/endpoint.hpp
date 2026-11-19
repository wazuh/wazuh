/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_ENDPOINT_HPP
#define _REMOTED_ENDPOINTS_ENDPOINT_HPP

#include "auth/authTypes.hpp"              // remoted::auth::AuthenticatedRequest
#include "endpoints/authRejectMetrics.hpp" // remoted::endpoints::AuthRejectMetrics + the name catalog
#include "http_server/IHttpServer.hpp"     // remoted::http::{HttpRequest,HttpResponse,IHttpResponder,Method}

#include <functional>
#include <memory>
#include <string_view>

namespace remoted::endpoints
{

    // Shared types an endpoint unit needs, re-exported so a new endpoint includes
    // only this contract header (plus its own logic). As more endpoints are added,
    // each lives in its own folder under src/endpoints/<name>/ and depends on this.
    using remoted::auth::AuthenticatedRequest;
    using remoted::http::HttpRequest;
    using remoted::http::HttpResponse;
    using remoted::http::IHttpResponder;
    using remoted::http::Method;

    /**
     * @brief Post-authentication endpoint handler.
     *
     * Invoked only after the bearer-token validation succeeds, with the verified request
     * and the responder. Asynchronous by contract: the handler owns delivering the
     * response and may do so inline or later, from any thread (it runs on the
     * server's worker pool, so it never stalls the I/O threads). It must call
     * responder->send(...) exactly once.
     *
     * The request is a shared_ptr<const> so a handler may retain it across deferred
     * pipeline stages without copying the verified payload.
     */
    using AuthenticatedHandler =
        std::function<void(std::shared_ptr<const AuthenticatedRequest>, std::shared_ptr<IHttpResponder>)>;

    /**
     * @brief Installs the process-wide instance errorResponseFor() counts on.
     *
     * Process-wide state on purpose, same precedent as errorResponseFor()'s own throttles:
     * endpoint.cpp has no object to hang it off, and threading a struct through
     * AuthGateway -> every endpoint -> errorResponseFor()'s signature would touch every
     * endpoint and test for no functional gain. NOT safe against concurrent re-install: the
     * facade calls this from start(), under its lifecycle lock, before any route serves --
     * idempotent across restarts because the counters dedupe by name on the never-reset
     * manager. Tests that install must do so sequentially with request traffic.
     */
    void installAuthRejectMetrics(AuthRejectMetrics metrics);

    /**
     * @brief Builds the client-visible {"error","code"} response for an AuthError.
     *
     * Single source of truth for that response shape, shared by AuthGateway (auth-protocol
     * failures) and any endpoint that raises an AuthError of its own after authentication
     * succeeds (e.g. stateless::validatePayloadIdentity()'s PayloadAgentMismatch). A 401's `code`
     * is the public class (string) and its `WWW-Authenticate` challenge names the same class
     * (PublicError); every other status keeps the numeric status as `code`.
     *
     * Also the single place every client-visible rejection is logged and counted, with the FINE
     * reason -- finer than the class the wire names (see endpoint.cpp): operator-actionable causes
     * -- clock skew, body-cap, unusable key, agent-id mismatch -- become throttled warnings naming
     * the relevant setting, while client-fault rejections stay at debug so an unauthenticated peer
     * cannot flood wazuh-manager.log.
     *
     * @param err          The rejection reason.
     * @param agentContext Optional authenticated agent id, included in the agent-id-mismatch
     *                     warning. Only endpoints that reject AFTER authentication have one.
     */
    remoted::http::HttpResponse errorResponseFor(remoted::auth::AuthError err, std::string_view agentContext = {});

} // namespace remoted::endpoints

#endif // _REMOTED_ENDPOINTS_ENDPOINT_HPP
