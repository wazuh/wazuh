#ifndef _API_METRICS_HANDLERS_HPP
#define _API_METRICS_HANDLERS_HPP

#include <api/api.hpp>
#include <metrics/iMetricsManagerAPI.hpp>

namespace api::metrics::handlers
{
/**
 * @brief Dumps content of instruments.
 *
 * @return Dumped data, or error message.
 */
api::HandlerSync metricsDumpCmd(const std::shared_ptr<metricsManager::IMetricsManagerAPI>& metricsAPI);

/**
 * @brief Get a specific instrument.
 *
 * @return Instrument data, or error message.
 */
api::HandlerSync metricsGetCmd(const std::shared_ptr<metricsManager::IMetricsManagerAPI>& metricsAPI);

/**
 * @brief Enable or disable a specific instrument.
 *
 * @return Returns "OK" if success, otherwise error message.
 */
api::HandlerSync metricsEnableCmd(const std::shared_ptr<metricsManager::IMetricsManagerAPI>& metricsAPI);

/**
 * @brief List instruments.
 *
 * @return Return the list of instruments.
 */
api::HandlerSync metricsList(const std::shared_ptr<metricsManager::IMetricsManagerAPI>& metricsAPI);

/**
 * @brief Generate a test instrument.
 *
 * @return Returns "OK".
 */
api::HandlerSync metricsTestCmd(const std::shared_ptr<metricsManager::IMetricsManagerAPI>& metricsAPI);

/**
 * @brief Register all available Metrics commands in the API registry.
 *
 * @param registry API registry.
 * @throw std::runtime_error If the command registration fails for any reason.
 */
void registerHandlers(const std::shared_ptr<metricsManager::IMetricsManagerAPI>& metricsAPI,
                      std::shared_ptr<api::Api> api);

} // namespace api::metrics::handlers

#endif // _API_METRICS_HANDLERS_HPP
