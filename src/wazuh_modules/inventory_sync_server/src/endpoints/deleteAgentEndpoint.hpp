/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_ENDPOINTS_DELETE_AGENT_ENDPOINT_HPP
#define _INVSYNC_ENDPOINTS_DELETE_AGENT_ENDPOINT_HPP

#include "http_server/IUdsHttpServer.hpp"
#include "indexer/IIndexerConnectorSync.hpp"
#include "sync/syncPipeline.hpp"

#include <memory>

namespace invsync::endpoints::delete_agent
{

    /**
     * @brief Whole-agent state deletion: `DELETE /agents` (design doc 04).
     *
     * UDS-local only (D15): the sole production caller is authd, after it removes the agent from
     * client.keys and wazuh-db. The target agent travels in the same `X-Wazuh-Agent-Id` header the
     * sync route uses; the body is ignored. The deletion is DEFERRED to the SyncPipeline on the
     * agent's shard, so it orders FIFO against any in-flight session of that same agent -- the
     * legacy path raced them on a lock (RF-10's footgun), and lost deletions were silent. Here the
     * caller sees the result: 200 means the delete-by-query was flushed; 503/500 mean "retry".
     */

    /// @brief The verb of the canonical route.
    constexpr http::Method method()
    {
        return http::Method::Delete;
    }

    /// @brief The canonical path.
    constexpr const char* path()
    {
        return "/agents";
    }

    /// @brief POST alias of the same handler, for C callers whose HTTP helper (uhttp_*) only
    /// speaks POST -- authd uses this one (design doc 04 §2's sanctioned alternative).
    constexpr http::Method altMethod()
    {
        return http::Method::Post;
    }

    /// @brief The POST alias' path. Distinct from /agents so a POST there stays a 404 instead of
    /// silently meaning something else later.
    constexpr const char* altPath()
    {
        return "/agents/delete";
    }

    /**
     * @brief Everything the handler needs, captured by value at registration.
     *
     * Both weak, like every other route: the facade's stop() resets them and the weak capture keeps
     * that reset destructive. The connector is only the admission availability check; the pipeline
     * worker re-checks its own at dispatch.
     */
    struct Dependencies
    {
        std::weak_ptr<invsync::sync::SyncPipeline> pipeline;
        std::weak_ptr<invsync::indexer::IIndexerConnectorSync> indexer;
    };

    /**
     * @brief Build the route handler: validate the header (400), gate on availability (503), and
     *        enqueue a DeleteAgent item on the agent's shard; the worker answers.
     */
    http::RouteHandler makeHandler(Dependencies dependencies);

} // namespace invsync::endpoints::delete_agent

#endif // _INVSYNC_ENDPOINTS_DELETE_AGENT_ENDPOINT_HPP
