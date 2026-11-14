// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _API_METRICS_HANDLERS_HPP
#define _API_METRICS_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
#include <fastmetrics/iManager.hpp>
#include <httpsrv/irouteregistrar.hpp>

#include <string>

namespace api::metrics::handlers
{

/**
 * @brief Enable or disable a specific metric
 *
 * POST /metrics/enable
 * Request: { "instrumentName": "router.events.processed", "status": true }
 */
adapter::RouteHandler enableMetric(const std::shared_ptr<fastmetrics::IManager>& metricsManager);

/**
 * @brief Get a specific metric value
 *
 * POST /metrics/get
 * Request: { "instrumentName": "router.events.processed" }
 */
adapter::RouteHandler getMetric(const std::shared_ptr<fastmetrics::IManager>& metricsManager);

/**
 * @brief List all metrics names
 *
 * POST /metrics/list
 * Request: {}
 */
adapter::RouteHandler listMetrics(const std::shared_ptr<fastmetrics::IManager>& metricsManager);

/**
 * @brief Dump all metrics values
 *
 * POST /metrics/dump
 * Request: {}
 */
adapter::RouteHandler dumpMetrics(const std::shared_ptr<fastmetrics::IManager>& metricsManager,
                                  const std::string& daemonName,
                                  const std::string& uptimeISO);

/// Body cap of the metrics routes: their requests are a few bytes of JSON.
constexpr std::size_t METRICS_BODY_CAP {4U * 1024U};

/**
 * @brief Register all metrics API handlers
 */
inline void registerHandlers(const std::shared_ptr<fastmetrics::IManager>& metricsManager,
                             const std::shared_ptr<httpsrv::IRouteRegistrar>& server,
                             const std::string& daemonName,
                             const std::string& uptimeISO)
{
    // Control routes run by the request workers, not inline: reading a metric can wait, since the registry is
    // read under its lock and pull metrics call into other modules (the indexer connector, the agent cache), so
    // they must not hold a transport I/O thread nor the Liveness sessions GET /status relies on. Under a
    // saturated executor they wait or get 503 like any other API call.
    httpsrv::RouteOptions metrics;
    metrics.cls = httpsrv::RouteClass::Control;
    metrics.runInline = false;
    metrics.maxBodyBytes = METRICS_BODY_CAP;
    server->addRoute(httpsrv::Method::POST, "/metrics/enable", enableMetric(metricsManager), metrics);
    server->addRoute(httpsrv::Method::POST, "/metrics/get", getMetric(metricsManager), metrics);
    server->addRoute(httpsrv::Method::POST, "/metrics/list", listMetrics(metricsManager), metrics);
    server->addRoute(
        httpsrv::Method::POST, "/metrics/dump", dumpMetrics(metricsManager, daemonName, uptimeISO), metrics);
}

} // namespace api::metrics::handlers

#endif // _API_METRICS_HANDLERS_HPP
