/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_ENDPOINTS_STATS_ENDPOINT_HPP
#define _INVSYNC_ENDPOINTS_STATS_ENDPOINT_HPP

#include "http_server/IUdsHttpServer.hpp"

namespace invsync::endpoints::stats
{

    /**
     * @brief The agent statistics ingress endpoint, reached through remoted's `POST /stats`.
     *
     * DUMMY. It does the full request/response cycle and the enrichment, but nothing durable: the
     * document is parsed, checked to be a JSON object, stamped with `wazuh.agent.id` and
     * `@timestamp`, echoed back, and then DISCARDED. Nothing is indexed or stored. This is the seam
     * where the real statistics handling lands; keeping it a separate unit from the start means that
     * work is a change to one file plus its test.
     *
     * @note `/stats` and `/config` are deliberate near-duplicates rather than one shared handler
     * registered twice. They are identical today only because both are dummies; their real payloads
     * and semantics will diverge, and separating them now means that divergence is a change to one
     * file instead of a refactor of a shared one. Keep them in sync until they must not be.
     *
     * ## Where the agent id comes from
     *
     * From the `X-Wazuh-Agent-Id` request header, which remoted sets from the identity it already
     * authenticated via AES-CMAC. It is NOT taken from the document: the whole point is that this
     * endpoint stamps the *authenticated* id onto whatever the agent sent, so a document claiming a
     * different id cannot override it. A request without that header is a remoted/modulesd contract
     * violation rather than agent input, and is answered 400.
     */

    /// @brief The verb this endpoint answers.
    constexpr http::Method method()
    {
        return http::Method::Post;
    }

    /// @brief The path this endpoint answers. Must match remoted's downstream target for `/stats`;
    /// statsEndpoint_test.cpp pins it so a silent drift fails a test.
    constexpr const char* path()
    {
        return "/stats";
    }

    /// @brief The header carrying remoted's authenticated agent id. Lower-case: the transport
    /// normalizes header names, so a handler may look this up unconditionally.
    constexpr const char* agentIdHeader()
    {
        return "x-wazuh-agent-id";
    }

    /**
     * @brief Build the endpoint's route handler.
     *
     * The returned handler replies inline and holds no state. When real statistics handling lands it
     * may instead move the responder onto a queue and return without answering -- which is what the
     * transport's deferred-response contract exists to support, and why the signature already takes a
     * responder rather than returning a response.
     */
    http::RouteHandler makeHandler();

} // namespace invsync::endpoints::stats

#endif // _INVSYNC_ENDPOINTS_STATS_ENDPOINT_HPP
