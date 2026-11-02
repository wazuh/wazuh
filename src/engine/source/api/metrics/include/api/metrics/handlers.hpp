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

/**
 * @brief Register all metrics API handlers
 */
inline void registerHandlers(const std::shared_ptr<fastmetrics::IManager>& metricsManager,
                             const std::shared_ptr<httpsrv::IRouteRegistrar>& server,
                             const std::string& daemonName,
                             const std::string& uptimeISO)
{
    // Liveness routes answered on the I/O thread (they only touch the in-memory registry), so metrics stay
    // readable while long API requests hold every worker.
    httpsrv::RouteOptions liveness;
    liveness.cls = httpsrv::RouteClass::Liveness;
    liveness.runInline = true;
    server->addRoute(httpsrv::Method::POST, "/metrics/enable", enableMetric(metricsManager), liveness);
    server->addRoute(httpsrv::Method::POST, "/metrics/get", getMetric(metricsManager), liveness);
    server->addRoute(httpsrv::Method::POST, "/metrics/list", listMetrics(metricsManager), liveness);
    server->addRoute(
        httpsrv::Method::POST, "/metrics/dump", dumpMetrics(metricsManager, daemonName, uptimeISO), liveness);
}

} // namespace api::metrics::handlers

#endif // _API_METRICS_HANDLERS_HPP
