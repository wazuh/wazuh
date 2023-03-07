#ifndef _METRICS_COMMANDS_HPP
#define _METRICS_COMMANDS_HPP

#include <memory>
#include "api/registry.hpp"
#include "metrics.hpp"

namespace api::metrics::cmds
{

api::CommandFn metricsDumpCmd();
api::CommandFn metricsEnableCmd();

void registerAllCmds(std::shared_ptr<api::Registry> registry);
} // namespace api::metrics::cmds

#endif // _METRICS_COMMANDS_HPP

