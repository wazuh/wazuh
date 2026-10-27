/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
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

    /**
     * @brief The engine event-ingress target reached over @p socketPath, carrying @p agentId as
     *        `X-Wazuh-Agent-Id`.
     *
     * @p agentId is the canonical id the gateway verified (AuthenticatedRequest::agentId, the token's
     * `sub`), never a value read from the agent's request: it tells the engine which agent the batch
     * belongs to outside the agent-written H line, the same way /stateful, /stats and /config already
     * do for their downstreams.
     */
    remoted::downstream::DownstreamTarget target(const std::string& socketPath, const std::string& agentId);

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
     * @brief Checks the H-line prefix and byte limit before forwarding an authenticated batch.
     *
     * The body must start with literal "H ". The following bytes, up to the first LF or the end
     * of the body, must fit within 8 KiB. This is a length-aware slice, with no JSON parsing or
     * identity lookup. Empty, malformed and header-only slices are left for the engine to validate.
     *
     * The gateway already verified the JWT. The caller sends req.agentId as X-Wazuh-Agent-Id;
     * the engine checks that the H-line identity path is unique and equals that trusted id on a
     * cache miss. A cache hit reuses validation of the same id and exact header bytes.
     *
     * @param req Verified request; payload.bytes() must still be valid (call before any release()).
     * @return AuthError::None for an in-limit H-line slice, AuthError::PayloadAgentMismatch otherwise.
     */
    remoted::auth::AuthError validatePayloadIdentity(const remoted::auth::AuthenticatedRequest& req);

    /**
     * @brief Builds the complete `/stateless` AuthenticatedHandler: validate, then forward.
     *
     * On validation failure, answers via the same {"error","code"} shape every other auth rejection
     * uses (remoted::endpoints::errorResponseFor) and never calls forward(). On success, delegates to
     * forwarder.forward(req, responder, target(socketPath, req->agentId), postProcess).
     *
     * @warning The returned handler stores a reference to @p forwarder. The caller must guarantee
     * forwarder outlives every route registered with it -- i.e. the HTTP server (which owns the route
     * table holding this handler) must be stopped/destroyed before forwarder is destroyed.
     * RemotedModuleFacade::stop() already orders teardown this way.
     *
     * @param metrics This endpoint's remoted.http.stateless.* metric set, or null for none. Must
     * point at storage that outlives the handler (a facade value member -- see
     * DownstreamTarget::httpMetrics). The handler counts its own pre-forward 400 and hands the
     * pointer to the forwarder, which counts every delivered status and observes latency.
     */
    remoted::endpoints::AuthenticatedHandler
    makeHandler(remoted::downstream::DeferredForwarder& forwarder,
                std::string socketPath,
                const remoted::metrics::EndpointHttpMetrics* metrics = nullptr);

} // namespace remoted::endpoints::stateless

#endif // _REMOTED_ENDPOINTS_STATELESS_ENDPOINT_HPP
