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

#ifndef _REMOTED_ENDPOINTS_CONFIG_ENDPOINT_HPP
#define _REMOTED_ENDPOINTS_CONFIG_ENDPOINT_HPP

#include "downstream/deferredForwarder.hpp" // DownstreamTarget, DownstreamError/DownstreamResponse, DeferredForwarder
#include "endpoint.hpp"                     // AuthenticatedHandler
#include "http_server/IHttpServer.hpp"      // HttpResponse

#include <string>

namespace remoted::endpoints::config
{

    /**
     * @brief Policy for the `POST /config` endpoint: forward the agent's JSON document to modulesd's
     *        inventory sync server and hand its answer back.
     *
     * DUMMY. The whole pipeline is real -- authentication, admission control, deferred forwarding,
     * the UDS round trip and the response mapping -- but neither side interprets the document yet.
     * modulesd only checks that it is a JSON object and stamps `wazuh.agent.id` and `@timestamp`
     * onto it. This exists so the plumbing and the file layout are settled before the real
     * configuration payload is defined.
     *
     * @note A deliberate near-duplicate of statsEndpoint -- see the note there. They are the same
     * shape only because both are dummies; keep them in sync until their real payloads force them
     * apart.
     *
     * @warning Do not introduce a local or parameter named `config` inside this unit: it would shadow
     * this namespace and make unqualified lookups inside it resolve to the variable.
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

} // namespace remoted::endpoints::config

#endif // _REMOTED_ENDPOINTS_CONFIG_ENDPOINT_HPP
