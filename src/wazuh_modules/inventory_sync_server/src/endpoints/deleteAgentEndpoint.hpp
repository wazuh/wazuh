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

#include "common/metricNames.hpp" // invsync::metrics::RequestCounters
#include "indexer/IIndexerConnectorSync.hpp"
#include "sync/syncPipeline.hpp"
#include <uds_http_server/IUdsHttpServer.hpp>

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
     * legacy path raced them on a lock (RF-10's footgun), and lost deletions were silent.
     *
     * ANSWERED AT ADMISSION: the 200 means "recorded and queued, it WILL be purged", not "already
     * purged". Waiting for the flush is what wedged the caller: authd relays deletions from the one
     * thread that persists client.keys, and on populated wazuh-states-* a single delete-by-query
     * legitimately outlives authd's 30 s budget -- so it timed out, retried into the very same
     * running purge, and blocked every key write meanwhile (no new agent could enroll). The purge's
     * own outcome stays observable in this module's log, never on this wire; the same contract
     * POST /vulnerability-detector/scan already moved to, for the same reason.
     */

    /// @brief The verb of the canonical route.
    constexpr wazuh::uds_http::Method method()
    {
        return wazuh::uds_http::Method::Delete;
    }

    /// @brief The canonical path.
    constexpr const char* path()
    {
        return "/agents";
    }

    /// @brief POST alias of the same handler, for C callers whose HTTP helper (uhttp_*) only
    /// speaks POST -- authd uses this one (design doc 04 §2's sanctioned alternative).
    constexpr wazuh::uds_http::Method altMethod()
    {
        return wazuh::uds_http::Method::Post;
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
     *
     * requestCounters is the same sync.requests.total.* family the sync route holds (dedupe by
     * name on one manager). This route answers AT ADMISSION, so every response it produces is sent
     * from here -- the inline 400/503 rejections and the 200 that accepts the deletion alike; the
     * queued item carries no responder, so the pipeline counts nothing for it. Each response is
     * still counted exactly once, at the site that sends it. Default-constructed it counts nothing
     * (the null object the tests rely on).
     */
    struct Dependencies
    {
        std::weak_ptr<invsync::sync::SyncPipeline> pipeline;
        std::weak_ptr<invsync::indexer::IIndexerConnectorSync> indexer;
        invsync::metrics::RequestCounters requestCounters;
    };

    /**
     * @brief Build the route handler: validate the header (400), gate on availability (503),
     *        enqueue a DeleteAgent item on the agent's shard and answer 200 right there.
     */
    wazuh::uds_http::RouteHandler makeHandler(Dependencies dependencies);

} // namespace invsync::endpoints::delete_agent

#endif // _INVSYNC_ENDPOINTS_DELETE_AGENT_ENDPOINT_HPP
