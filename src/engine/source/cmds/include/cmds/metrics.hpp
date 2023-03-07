#ifndef _CMD_METRICS_HPP
#define _CMD_METRICS_HPP

#include <memory>

#include <CLI/CLI.hpp>

#include <api/wazuhRequest.hpp>
#include <api/wazuhResponse.hpp>
#include <json/json.hpp>


namespace cmd::metrics
{

namespace details
{
constexpr auto ORIGIN_NAME = "engine_integrated_metrics_api";

constexpr auto API_METRICS_DUMP_SUBCOMMAND {"dump"};
constexpr auto API_METRICS_ENABLE_SUBCOMMAND {"enable"};

std::string commandName(const std::string& command);

json::Json getParameters(const std::string& action);

void processResponse(const api::WazuhResponse& response);
void singleRequest(const api::WazuhRequest& request, const std::string& socketPath);
} // namespace details

void configure(CLI::App_p app);

void runDump(const std::string& socketPath);
void runEnableInstrument(const std::string& socketPath, const std::string& nameInstrument, bool enableState = true);

} // namespace cmd::metrics

#endif // _CMD_METRICS_HPP
