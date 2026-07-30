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
#include "indexer/IIndexerConnectorAsync.hpp"

#include <memory>

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
     * The returned handler replies inline. When real configuration handling lands it may instead move the
     * responder onto a queue and return without answering -- which is what the transport's
     * deferred-response contract exists to support, and why the signature already takes a responder
     * rather than returning a response.
     *
     * @param connector The async indexer connector, held WEAKLY and locked at each point of use.
     *
     * Weak, not a reference and not a shared_ptr, and the reason is not defensiveness:
     *
     *  - A reference would be safe *today* -- IUdsHttpServer::stopAccepting() guarantees no handler is
     *    running or will run again, and the facade tears the connector down only after that returns.
     *    It becomes a dangling reference the moment this handler defers its reply, because the
     *    continuation then runs on another thread with no ordering against that teardown. Deferring is
     *    exactly what this connector is being injected for.
     *  - A strong shared_ptr would be safe but would move the teardown: handler closures are stored in
     *    the transport's route table, which is co-owned by every outstanding responder, so the facade's
     *    reset() would stop being destructive and the connector's destructor (with its background
     *    threads) would run later, possibly on whatever thread releases the last responder.
     *
     * Weak keeps both properties: correct after deferral lands, and the facade's documented phase
     * ordering stays true. The cost is one lock() per request and an explicit "it is gone" branch.
     */
    http::RouteHandler makeHandler(std::weak_ptr<invsync::indexer::IIndexerConnectorAsync> connector);

} // namespace invsync::endpoints::config

#endif // _INVSYNC_ENDPOINTS_CONFIG_ENDPOINT_HPP
