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
constexpr auto API_METRICS_GET_SUBCOMMAND {"get"};
constexpr auto API_METRICS_ENABLE_SUBCOMMAND {"enable"};
constexpr auto API_METRICS_LIST_SUBCOMMAND {"list"};
constexpr auto API_METRICS_TEST_SUBCOMMAND {"test"};

std::string commandName(const std::string& command);
json::Json getParameters(const std::string& action);
json::Json getParameters(const std::string& action, const std::string& name);

void processResponse(const api::WazuhResponse& response);
void singleRequest(const api::WazuhRequest& request, const std::string& socketPath);
} // namespace details

void configure(CLI::App_p app);
void runDump(const std::string& socketPath);
void runGetInstrument(const std::string& socketPath, const std::string& name);
void runEnableInstrument(const std::string& socketPath, const std::string& nameInstrument, bool enableState = true);
void runListInstruments(const std::string& socketPath);
void runTest(const std::string& socketPath);
} // namespace cmd::metrics

#endif // _CMD_METRICS_HPP
