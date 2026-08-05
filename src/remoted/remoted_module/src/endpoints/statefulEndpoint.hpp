/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_STATEFUL_ENDPOINT_HPP
#define _REMOTED_ENDPOINTS_STATEFUL_ENDPOINT_HPP

#include "downstream/deferredForwarder.hpp" // DownstreamTarget, DownstreamError/DownstreamResponse, DeferredForwarder
#include "endpoint.hpp"                     // AuthenticatedHandler
#include "http_server/IHttpServer.hpp"      // HttpResponse

#include <string>

namespace remoted::endpoints::stateful
{

    /**
     * @brief Policy for the `POST /stateful` endpoint: inventory synchronization sessions.
     *
     * The body is the agent's FlatBuffer `Message{FullSession}` -- OPAQUE to remoted (never parsed
     * here); it is forwarded verbatim to modulesd's inventory sync server, which owns validation.
     * Unlike /stateless and /stats, the downstream result IS the session result, so postProcess()
     * passes the contract's status codes and bodies through instead of collapsing them.
     */

    /**
     * @brief The inventory-sync-server `POST /stateful` target reached over @p socketPath.
     *
     * Carries the authenticated agent id as `X-Wazuh-Agent-Id` (written by us from the identity the
     * gateway verified, never by the agent) -- the server cross-checks it against the FlatBuffer's
     * `Start.agentid` (403 on mismatch). @p responseTimeoutMs is the route's dedicated downstream
     * deadline (remoted.downstream_stateful_response_timeout): sessions are indexed and flushed
     * within the request, so it is deliberately longer than the global default.
     */
    remoted::downstream::DownstreamTarget
    target(const std::string& socketPath, const std::string& agentId, int responseTimeoutMs);

    /**
     * @brief Map the downstream result to the agent response: passthrough of the sync contract.
     *
     * The server's status codes and bodies ARE the agent contract (D2 -- 200 ok/noop, 400, 403
     * identity, 409 checksum mismatch, 413 over budget, 500 scan/apply failed, 503 not
     * ready/capacity), so those pass through verbatim -- the bodies are produced by the manager's
     * own server, never echoed agent input, which is what makes reflecting them safe. Of the
     * downstream headers only `Retry-After` is forwarded (on 503, digits-only), because it is the
     * one header in the contract; reflecting arbitrary downstream headers stays off the table.
     * Transport failures (send error / timeout / bad HTTP) and any status outside the contract
     * collapse to a neutral 503 (the agent retries).
     */
    remoted::http::HttpResponse postProcess(remoted::downstream::DownstreamError error,
                                            const remoted::downstream::DownstreamResponse& response);

    /**
     * @brief Builds the `/stateful` AuthenticatedHandler: reject empty bodies, then forward.
     *
     * No payload identity check here (unlike /stateless): the body is an opaque FlatBuffer and
     * parsing it is the sync server's job -- identity is enforced downstream against the
     * `X-Wazuh-Agent-Id` header target() injects (doc 05 §3). The only local check is non-emptiness:
     * an empty body cannot be a FullSession, and rejecting it saves a deferred-work slot and a UDS
     * round trip.
     *
     * @warning The returned handler stores a reference to @p forwarder. The caller must guarantee
     * forwarder outlives every route registered with it -- i.e. the HTTP server (which owns the route
     * table holding this handler) must be stopped/destroyed before forwarder is destroyed.
     * RemotedModuleFacade::stop() already orders teardown this way.
     */
    remoted::endpoints::AuthenticatedHandler
    makeHandler(remoted::downstream::DeferredForwarder& forwarder, std::string socketPath, int responseTimeoutMs);

} // namespace remoted::endpoints::stateful

#endif // _REMOTED_ENDPOINTS_STATEFUL_ENDPOINT_HPP
