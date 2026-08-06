/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_ENDPOINTS_METRICS_ENDPOINT_HPP
#define _INVSYNC_ENDPOINTS_METRICS_ENDPOINT_HPP

#include "http_server/IUdsHttpServer.hpp"

#include <wazuh_metrics/iManager.hpp>

#include <memory>

namespace invsync::endpoints::metrics
{

    /**
     * @brief The module's statistics dump: `GET /metrics` (D18).
     *
     * UDS-local only, like everything on this socket -- remoted exposes no route to it, so
     * agents can never reach it; the consumers are operators (curl over the socket) and the
     * benchmark harness. NOT `/stats`: `POST /stats` on this same server is the INGEST of
     * agent statistics documents, and sharing the path with the opposite semantics would be
     * an operator trap. `/metrics` is also the name the engine uses for this concept.
     */

    /// @brief The verb this endpoint answers.
    constexpr http::Method method()
    {
        return http::Method::Get;
    }

    /// @brief The path this endpoint answers. metricsEndpoint_test.cpp pins it.
    constexpr const char* path()
    {
        return "/metrics";
    }

    /**
     * @brief Build the route handler: dump every registered metric as JSON.
     *
     * The manager is captured weakly for CONSISTENCY with every other route (503 when gone),
     * even though the facade never resets its metrics manager -- the counters survive restart
     * retries on purpose.
     */
    http::RouteHandler makeHandler(std::weak_ptr<wazuh::metrics::IManager> manager);

} // namespace invsync::endpoints::metrics

#endif // _INVSYNC_ENDPOINTS_METRICS_ENDPOINT_HPP
