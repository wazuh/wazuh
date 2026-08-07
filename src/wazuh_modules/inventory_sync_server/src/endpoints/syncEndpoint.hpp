/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_ENDPOINTS_SYNC_ENDPOINT_HPP
#define _INVSYNC_ENDPOINTS_SYNC_ENDPOINT_HPP

#include "common/clusterIdentity.hpp"
#include "common/metricNames.hpp"
#include "http_server/IUdsHttpServer.hpp"
#include "indexer/IIndexerConnectorSync.hpp"
#include "sync/syncPipeline.hpp"
#include "vd/IVdScanner.hpp"
#include "vd/vdScanLane.hpp"

#include <memory>

namespace invsync::endpoints::sync
{

    /**
     * @brief The inventory synchronization ingress endpoint: POST /stateful.
     *
     * One request = one whole session (Message{FullSession}); the HTTP response IS the result the
     * agent acts on. The handler runs only the CPU-bound part on the I/O strand -- FlatBuffers
     * verification, identity, shape -- and defers the indexer work to the SyncPipeline, answering
     * later through the retained responder.
     */

    /// @brief The verb this endpoint answers.
    constexpr http::Method method()
    {
        return http::Method::Post;
    }

    /// @brief The path this endpoint answers. Mirrors the `POST /stateful` route remoted exposes
    /// to agents (remoted forwards the body here verbatim); syncEndpoint_test.cpp pins the value
    /// so a silent drift is caught before it breaks that forwarding.
    constexpr const char* path()
    {
        return "/stateful";
    }

    /// @brief The header carrying remoted's authenticated agent id. Lower-case: the transport
    /// normalizes header names, so a handler may look this up unconditionally.
    constexpr const char* agentIdHeader()
    {
        return "x-wazuh-agent-id";
    }

    /**
     * @brief Everything the handler needs, captured by value at registration.
     *
     * The pipeline and the connector are held WEAKLY: the facade's stop() resets both, and a weak
     * capture is what keeps that reset destructive (same pattern as /stats and /config). The
     * connector here is only the ADMISSION availability check; the pipeline workers re-check their
     * own connectors at dispatch.
     */
    struct Dependencies
    {
        std::weak_ptr<invsync::sync::SyncPipeline> pipeline;
        std::weak_ptr<invsync::indexer::IIndexerConnectorSync> indexer;
        invsync::common::ClusterIdentity cluster;
        /// Retry-After seconds attached to the 503 for vulnerability-detection sessions (D17).
        int vdRetryAfterSeconds {60};
        /// The D22 scan lane for VD data sessions and its feed gate. Both weak, like the rest;
        /// either expiring means the module is stopping (503).
        std::weak_ptr<invsync::vd::VdScanLane> scanLane;
        std::weak_ptr<invsync::vd::IVdScanner> scanner;
        /// D18: counters for the responses THIS handler sends inline (rejections; deferred
        /// responses are counted where they are sent, by the pipeline/lane). Pre-resolved
        /// shared_ptr counters, not the manager: the hot path never does a registry lookup.
        /// Default (null) counts nothing.
        invsync::metrics::RequestCounters requestCounters;
        /// D18: 503-with-Retry-After responses (the strand-side feed gate).
        std::shared_ptr<wazuh::metrics::ICounter> retryAfterTotal;
    };

    /**
     * @brief Build the endpoint's route handler.
     *
     * The handler validates on the strand and either rejects inline (400/403/413-at-transport/503)
     * or enqueues {request, responder, session} on the pipeline and returns without answering --
     * the transport's deferred-response contract is what makes that safe.
     */
    http::RouteHandler makeHandler(Dependencies dependencies);

} // namespace invsync::endpoints::sync

#endif // _INVSYNC_ENDPOINTS_SYNC_ENDPOINT_HPP
