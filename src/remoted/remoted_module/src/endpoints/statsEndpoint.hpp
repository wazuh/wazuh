/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_STATS_ENDPOINT_HPP
#define _REMOTED_ENDPOINTS_STATS_ENDPOINT_HPP

#include "downstream/deferredForwarder.hpp" // DownstreamTarget, DownstreamError/DownstreamResponse, DeferredForwarder
#include "endpoint.hpp"                     // AuthenticatedHandler
#include "http_server/IHttpServer.hpp"      // HttpResponse

#include <string>

namespace remoted::endpoints::stats
{

    /**
     * @brief Policy for the `POST /stats` endpoint: forward the agent's JSON document to modulesd's
     *        inventory sync server and hand its answer back.
     *
     * DUMMY. The whole pipeline is real -- authentication, admission control, deferred forwarding,
     * the UDS round trip and the response mapping -- but neither side interprets the document yet.
     * modulesd only checks that it is a JSON object and stamps `wazuh.agent.id` and `@timestamp`
     * onto it. This exists so the plumbing and the file layout are settled before the real
     * statistics payload is defined.
     *
     * @note `/stats` and `/config` are deliberate near-duplicates rather than one shared unit. They
     * are the same shape today only because both are dummies; their real payloads, validation and
     * downstream semantics will diverge, and separating them now means that divergence is a change
     * to one file instead of a refactor of a shared one. Keep them in sync until they must not be.
     */

    /// @brief The inventory sync server target reached over @p socketPath, tagged with @p agentId.
    ///
    /// The authenticated agent id travels as a header because, unlike a /stateless batch, the
    /// document itself does not carry it -- modulesd is what writes it into the JSON.
    remoted::downstream::DownstreamTarget target(const std::string& socketPath, const std::string& agentId);

    /**
     * @brief Map the downstream result onto the agent's response.
     *
     * Passes the downstream body through on success, unlike /stateless which discards it: the point
     * of this endpoint today is that the caller can see what modulesd added to the document. Failure
     * statuses are still collapsed to fixed local messages so an arbitrary downstream string is never
     * reflected back to an agent.
     */
    remoted::http::HttpResponse postProcess(remoted::downstream::DownstreamError error,
                                            const remoted::downstream::DownstreamResponse& response);

    /**
     * @brief Build the endpoint's post-authentication handler.
     *
     * Rejects an empty body with 400 before spending a deferred-work slot; everything else about the
     * document is modulesd's business, so the body is not parsed here. The gateway has already
     * verified the AES-CMAC and the agent identity by the time this runs.
     *
     * @warning The returned handler stores a reference to @p forwarder. The caller must guarantee
     * forwarder outlives every route registered with it -- i.e. the HTTP server (which owns the route
     * table holding this handler) must be stopped/destroyed before forwarder is destroyed.
     * RemotedModuleFacade::stop() already orders teardown this way.
     */
    remoted::endpoints::AuthenticatedHandler makeHandler(remoted::downstream::DeferredForwarder& forwarder,
                                                         std::string socketPath);

} // namespace remoted::endpoints::stats

#endif // _REMOTED_ENDPOINTS_STATS_ENDPOINT_HPP
