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

#include "common/clusterIdentity.hpp"
#include "http_server/IUdsHttpServer.hpp"
#include "indexer/IIndexerConnectorAsync.hpp"
#include "sync/stateIndexAllowlist.hpp" // AGENT_STATS_INDEX -- shared with the deletion scope

#include <memory>
#include <string_view>

namespace invsync::endpoints::stats
{

    /**
     * @brief The agent statistics ingress endpoint, reached through remoted's `POST /stats`.
     *
     * The agent reports every module it can collect statistics from in one push, keyed by module:
     *
     * ```json
     * {"modules": {"agent": {…}, "logcollector": {…}}}
     * ```
     *
     * This endpoint indexes one document per agent, whose id IS the agent id, so every push replaces
     * the previous one:
     *
     * ```json
     * {"state": {"modified_at": …, "document_version": 1},
     *  "wazuh": {"schema": {"version": "1.0"}, "cluster": {…},
     *            "agent": {"id": …, "statistics": {"agent": {…}, …}}}}
     * ```
     *
     * `modules` moves under `wazuh.agent.statistics` untouched. Nothing here renames a metric or
     * reshapes a module's body: the agent sends the document ready to index, so a mapping table on
     * this side would have to be edited for every metric the agent ever adds, and only the agent
     * knows which of its counters are cumulative.
     *
     * That does NOT make an agent-side addition free. The `wazuh-agent-stats` mapping is
     * `dynamic: strict` with every leaf declared, so a module or metric it does not declare makes the
     * indexer reject the whole document with `strict_dynamic_mapping_exception`. The write is
     * fire-and-forget and the agent already has its 200, so that rejection is silent: a new metric
     * needs no change HERE, but it does need one in the index template.
     *
     * The document is built from scratch rather than by stamping onto the agent's, so the `agent_id`
     * and `cluster` the agent's reporter writes at the root are dropped instead of ending up indexed
     * next to the authoritative `wazuh.agent.id`.
     *
     * A report is all or nothing: one malformed module rejects the whole thing with 400, rather than
     * indexing a partial report the agent has no way to tell apart from a complete one.
     *
     * @note `/stats` and `/config` are deliberate near-duplicates rather than one shared handler
     * registered twice. Their payloads and semantics differ, and separating them means a divergence is
     * a change to one file instead of a refactor of a shared one.
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

    /// @brief The index holding one live statistics document per agent. A regular index, not a data
    /// stream, because a data stream forbids the stable document id the replacement relies on.
    /// Taken from the deletion scope rather than re-spelled here, so DELETE /agents can never miss
    /// this index.
    constexpr std::string_view indexName()
    {
        return invsync::sync::AGENT_STATS_INDEX;
    }

    /**
     * @brief Build the endpoint's route handler.
     *
     * The returned handler replies inline: the write is fire-and-forget through the async connector,
     * so there is nothing to wait for. The signature still takes a responder because the transport's
     * deferred-response contract is what a later, acknowledged write would need.
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

} // namespace invsync::endpoints::stats

#endif // _INVSYNC_ENDPOINTS_STATS_ENDPOINT_HPP
