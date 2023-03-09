#ifndef _METRICS_COMMANDS_HPP
#define _METRICS_COMMANDS_HPP

#include <memory>
#include "api/registry.hpp"
#include "metrics.hpp"

namespace api::metrics::cmds
{
constexpr char METRICS_NAME_MISSING[] {"Metrics \"Name\" parameter is missing"};
constexpr char METRICS_NAME_EMPTY[] {"Metrics \"Name\" parameter cannot be empty"};

/**
 * @brief Get the Metrics's name from the params or return an error.
 *
 * @param params The json /data from the request.
 * @return [bool, std::string] True if the name is valid, false otherwise
 *                             The name if it's valid, the error message otherwise.
 */
std::tuple<bool, std::string> getNameOrError(const json::Json& params);

/**
 * @brief Dumps content of instruments.
 *
 * @return [api::CommandFn] Dumped data, or error message.
 */
api::CommandFn metricsDumpCmd();

/**
 * @brief Get a specific instrument.
 *
 * @return [api::CommandFn] Instrument data, or error message.
 */
api::CommandFn metricsGetCmd();

/**
 * @brief Enable or disable a specific instrument.
 *
 * @return [api::CommandFn] Returns "OK" if success, otherwise error message.
 */
api::CommandFn metricsEnableCmd();

/**
 * @brief List instruments.
 *
 * @return [api::CommandFn] Return the list of instruments.
 */
api::CommandFn metricsListCmd();

/**
 * @brief Generate a test instrument.
 *
 * @return [api::CommandFn] Returns "OK".
 */
api::CommandFn metricsTestCmd();

/**
 * @brief Register all available Metrics commands in the API registry.
 *
 * @param registry API registry.
 * @throw std::runtime_error If the command registration fails for any reason.
 */
void registerAllCmds(std::shared_ptr<api::Registry> registry);
} // namespace api::metrics::cmds

#endif // _METRICS_COMMANDS_HPP
