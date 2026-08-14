/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_STATELESS_ENDPOINT_HPP
#define _REMOTED_ENDPOINTS_STATELESS_ENDPOINT_HPP

#include "downstream/deferredForwarder.hpp" // DownstreamTarget, DownstreamError/DownstreamResponse, DeferredForwarder
#include "endpoint.hpp"                     // AuthenticatedHandler
#include "http_server/IHttpServer.hpp"      // HttpResponse

#include <string>

namespace remoted::endpoints::stateless
{

    /**
     * @brief Policy for the `POST /stateless` endpoint: what to forward downstream and how to map the
     *        downstream result back to the agent.
     *
     * This is per-endpoint policy, deliberately kept out of the generic `downstream/` machinery. The
     * facade injects the socket path (from config); the endpoint owns the engine ingest contract
     * (path + content-type) and the response mapping.
     */

    /// @brief The engine event-ingress target reached over @p socketPath.
    remoted::downstream::DownstreamTarget target(const std::string& socketPath);

    /**
     * @brief Map the downstream result to the agent response.
     *
     * send-error / timeout / 5xx -> 503 (the agent retries); 2xx -> 202 Accepted (empty; the engine
     * enqueued the batch, it is not fully processed); 400 -> 400 (invalid batch, neutral body);
     * 413 -> 413.
     */
    remoted::http::HttpResponse postProcess(remoted::downstream::DownstreamError error,
                                            const remoted::downstream::DownstreamResponse& response);

    /**
     * @brief Cross-checks the payload's claimed identity against the authenticated identity.
     *
     * Parses the body's `H <json>` line (RapidJSON, non-in-situ length-based Parse -- the payload is
     * a view into a shared, non-null-terminated buffer) and compares `/wazuh/agent/id` (a JSON
     * string, parsed as a non-negative integer) against @p req.agentId (also parsed as one). Pure
     * function, no side effects -- unit-tested directly, no sockets, no forwarding.
     *
     * Any of the following collapses to the same AuthError::PayloadAgentMismatch: the body doesn't
     * start with "H ", the JSON after it doesn't parse, `/wazuh/agent/id` is missing or not a string,
     * either side fails to parse as a non-negative integer, or the two integers differ. There is no
     * partial-validation bypass: a missing/malformed header is rejected exactly like a real mismatch.
     *
     * @param req Verified request; payload.bytes() must still be valid (call before any release()).
     * @return AuthError::None on match, AuthError::PayloadAgentMismatch otherwise.
     */
    remoted::auth::AuthError validatePayloadIdentity(const remoted::auth::AuthenticatedRequest& req);

    /**
     * @brief Builds the complete `/stateless` AuthenticatedHandler: validate, then forward.
     *
     * On validation failure, answers via the same {"error","code"} shape every other auth rejection
     * uses (remoted::endpoints::errorResponseFor) and never calls forward(). On success, delegates to
     * forwarder.forward(req, responder, target(socketPath), postProcess).
     *
     * @warning The returned handler stores a reference to @p forwarder. The caller must guarantee
     * forwarder outlives every route registered with it -- i.e. the HTTP server (which owns the route
     * table holding this handler) must be stopped/destroyed before forwarder is destroyed.
     * RemotedModuleFacade::stop() already orders teardown this way.
     */
    remoted::endpoints::AuthenticatedHandler makeHandler(remoted::downstream::DeferredForwarder& forwarder,
                                                         std::string socketPath);

} // namespace remoted::endpoints::stateless

#endif // _REMOTED_ENDPOINTS_STATELESS_ENDPOINT_HPP
