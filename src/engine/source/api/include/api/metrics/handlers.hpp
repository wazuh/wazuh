#ifndef _API_METRICS_HANDLERS_HPP
#define _API_METRICS_HANDLERS_HPP

#include <api/registry.hpp>
#include <metrics/iMetricsManagerAPI.hpp>

namespace api::metrics::handlers
{
/**
 * @brief Dumps content of instruments.
 *
 * @return [api::CommandFn] Dumped data, or error message.
 */
api::Handler metricsDumpCmd(const std::shared_ptr<metrics_manager::IMetricsManagerAPI>& metricsAPI);

/**
* @brief Get a specific instrument.
*
* @return [api::CommandFn] Instrument data, or error message.
*/
api::Handler metricsGetCmd(const std::shared_ptr<metrics_manager::IMetricsManagerAPI>& metricsAPI);

/**
* @brief Enable or disable a specific instrument.
*
* @return [api::CommandFn] Returns "OK" if success, otherwise error message.
*/
api::Handler metricsEnableCmd(const std::shared_ptr<metrics_manager::IMetricsManagerAPI>& metricsAPI);

/**
 * @brief List instruments.
 *
 * @return [api::CommandFn] Return the list of instruments.
 */
api::Handler metricsList(const std::shared_ptr<metrics_manager::IMetricsManagerAPI>& metricsAPI);

/**
* @brief Generate a test instrument.
*
* @return [api::CommandFn] Returns "OK".
*/
api::Handler metricsTestCmd(const std::shared_ptr<metrics_manager::IMetricsManagerAPI>& metricsAPI);

/**
 * @brief Register all available Metrics commands in the API registry.
 *
 * @param registry API registry.
 * @throw std::runtime_error If the command registration fails for any reason.
 */
void registerHandlers(const std::shared_ptr<metrics_manager::IMetricsManagerAPI>& metricsAPI, std::shared_ptr<api::Registry> registry);

} // namespace api::metrics::handlers

#endif // _API_METRICS_HANDLERS_HPP
