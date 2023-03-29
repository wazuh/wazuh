#ifndef _CMD_START_HPP
#define _CMD_START_HPP

#include <memory>

#include <CLI/CLI.hpp>

#include <conf/cliconf.hpp>
#include <conf/iconf.hpp>

#include <metrics/iMetricsManager.hpp>
#include <metrics/iMetricsManagerAPI.hpp>

namespace cmd::server
{

using ConfHandler = std::shared_ptr<conf::IConf<conf::CliConf>>;

void runStart(ConfHandler confManager, const std::shared_ptr<metrics_manager::IMetricsManager>& metricsManager,
                                       const std::shared_ptr<metrics_manager::IMetricsManagerAPI>& metricsManagerAPI);

void configure(CLI::App_p app, const std::shared_ptr<metrics_manager::IMetricsManager>& metricsManager,
                               const std::shared_ptr<metrics_manager::IMetricsManagerAPI>& metricsManagerAPI);

} // namespace cmd::server

#endif // _CMD_START_HPP
