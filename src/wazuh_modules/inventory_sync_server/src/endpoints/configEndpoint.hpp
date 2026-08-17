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

#include "common/clusterIdentity.hpp"
#include "http_server/IUdsHttpServer.hpp"
#include "indexer/IIndexerConnectorAsync.hpp"

#include <memory>

namespace invsync::endpoints::config
{

    /**
     * @brief The agent configuration ingress endpoint, reached through remoted's `POST /config`.
     *
     * The body is a JSON array of `{"module": <string>, "config": <object>}` pairs -- one per agent
     * module (e.g. `fim`, `logcollector`). Each valid element is reduced to exactly those two keys
     * (anything else the agent sent is dropped) and wrapped into the document indexed under
     * `wazuh-agent-config`:
     *
     * @code
     * {
     *   "state": { "modified_at": "...", "document_version": 1 },
     *   "wazuh": {
     *     "schema": { "version": "1.0" },
     *     "agent": { "id": "<authenticated id>",
     *                "configuration": { "modules": ["fim", "logcollector", ...],
     *                                   "content": { "fim": {...}, "logcollector": {...}, ... } } },
     *     "cluster": { "name": "..." }
     *   }
     * }
     * @endcode
     *
     * `content` is an OBJECT keyed by module name, not the array the agent sends -- a module is
     * unique per report, so this makes "does agent X have module Y" a single field lookup. `modules`
     * is derived from `content`'s keys so the two can never drift apart. The template also declares
     * an explicit per-module sub-schema under `content` (`content.fim.syscheck.frequency`, etc.).
     *
     * The `wazuh-agent-config` index template is `dynamic: false`: a field outside that per-module
     * sub-schema (an unrecognized module, or a legacy/undeclared key within a known one) is still
     * written and kept in `_source`, just not indexed for search -- so this endpoint only sanitizes
     * the outer `{module, config}` shape, never the fields inside `config` itself.
     *
     * The document is indexed under the agent id as its `_id`, via a plain upsert: each report
     * replaces the previous one for that agent, there is no separate delete step.
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
     *
     * ## Where the cluster name comes from
     *
     * From this module's own configuration (`inventory_sync_server_config_t::cluster_name`),
     * injected once at registration time via `makeHandler()`'s `cluster` parameter -- NOT read
     * per-request from anything the caller sends. There is no per-request source for it, unlike
     * the agent id: this manager's identity does not change between requests.
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
     *
     * @param cluster This manager's cluster name, taken BY VALUE (a small string, copied once per
     *                registration) rather than by weak_ptr: unlike the connector, there is no
     *                background object with a teardown ordering to protect -- just a string whose
     *                lifetime the closure can own outright.
     */
    http::RouteHandler makeHandler(std::weak_ptr<invsync::indexer::IIndexerConnectorAsync> connector,
                                   invsync::common::ClusterIdentity cluster);

} // namespace invsync::endpoints::config

#endif // _INVSYNC_ENDPOINTS_CONFIG_ENDPOINT_HPP
