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
 * @brief Get the Metrics's name from the params or return an error
 *
 * @param params The json /data from the request
 * @return [bool, std::string] True if the name is valid, false otherwise
 *                             The name if it's valid, the error message otherwise.
 */
std::tuple<bool, std::string> getNameOrError(const json::Json& params);
api::CommandFn metricsDumpCmd();
api::CommandFn metricsGetCmd();

void registerAllCmds(std::shared_ptr<api::Registry> registry);
} // namespace api::metrics::cmds

#endif // _METRICS_COMMANDS_HPP
