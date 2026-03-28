#ifndef _API_METRICS_HANDLERS_HPP
#define _API_METRICS_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
#include <fastmetrics/iManager.hpp>

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
adapter::RouteHandler dumpMetrics(const std::shared_ptr<fastmetrics::IManager>& metricsManager);

/**
 * @brief Register all metrics API handlers
 */
inline void registerHandlers(const std::shared_ptr<fastmetrics::IManager>& metricsManager,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/metrics/enable", enableMetric(metricsManager));
    server->addRoute(httpsrv::Method::POST, "/metrics/get", getMetric(metricsManager));
    server->addRoute(httpsrv::Method::POST, "/metrics/list", listMetrics(metricsManager));
    server->addRoute(httpsrv::Method::POST, "/metrics/dump", dumpMetrics(metricsManager));
}

} // namespace api::metrics::handlers

#endif // _API_METRICS_HANDLERS_HPP
