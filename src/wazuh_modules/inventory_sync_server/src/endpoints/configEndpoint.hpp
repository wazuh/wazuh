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

#ifndef _INVSYNC_ENDPOINTS_CONFIG_ENDPOINT_HPP
#define _INVSYNC_ENDPOINTS_CONFIG_ENDPOINT_HPP

#include "http_server/IUdsHttpServer.hpp"

namespace invsync::endpoints::config
{

    /**
     * @brief The agent configuration ingress endpoint, reached through remoted's `POST /config`.
     *
     * DUMMY. It does the full request/response cycle and the enrichment, but nothing durable: the
     * document is parsed, checked to be a JSON object, stamped with `wazuh.agent.id` and
     * `@timestamp`, echoed back, and then DISCARDED. Nothing is indexed or stored.
     *
     * @note A deliberate near-duplicate of statsEndpoint -- see the note there. Identical today only
     * because both are dummies; keep them in sync until their real payloads force them apart.
     *
     * @warning Do not introduce a local or parameter named `config` inside this unit: it would shadow
     * this namespace and make unqualified lookups inside it resolve to the variable.
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

    /// @brief The path this endpoint answers. Must match remoted's downstream target for `/config`;
    /// configEndpoint_test.cpp pins it so a silent drift fails a test.
    constexpr const char* path()
    {
        return "/config";
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
     * The returned handler replies inline and holds no state. When real configuration handling lands
     * it may instead move the responder onto a queue and return without answering -- which is what the
     * transport's deferred-response contract exists to support, and why the signature already takes a
     * responder rather than returning a response.
     */
    http::RouteHandler makeHandler();

} // namespace invsync::endpoints::config

#endif // _INVSYNC_ENDPOINTS_CONFIG_ENDPOINT_HPP
