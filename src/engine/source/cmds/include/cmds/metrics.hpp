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

/**
 * @brief Build the commmand name.
 *
 * @param command The name of the commmand.
 * @return std::string Name of command.
 */
std::string commandName(const std::string& command);

/**
 * @brief Get the parameters.
 *
 * @param action The action of the commmand.
 * @return json::Json Json with the parameters commmands.
 */
json::Json getParameters(const std::string& action);

/**
 * @brief Get the parameters.
 *
 * @param action The action of the commmand.
 * @param name The name of the commmand.
 * @return json::Json Json with the parameters of commmands.
 */
json::Json getParameters(const std::string& action, const std::string& name);

/**
 * @brief Process the response.
 *
 * @param response The response to process.
 */
void processResponse(const api::WazuhResponse& response);

/**
 * @brief Process the response.
 *
 * @param request The request.
 * @param socketPath The socket.
 */
void singleRequest(const api::WazuhRequest& request, const std::string& socketPath);
} // namespace details

/**
 * @brief Configure the app.
 *
 * @param app The app.
 */
void configure(CLI::App_p app);

/**
 * @brief Run the command dump.
 *
 * @param socketPath The socket.
 */
void runDump(const std::string& socketPath);

/**
 * @brief Run the command get.
 *
 * @param socketPath The socket.
 * @param name The instrument name.
 */
void runGetInstrument(const std::string& socketPath, const std::string& name);

/**
 * @brief Enables or disables an instrument.
 *
 * @param socketPath The socket.
 * @param name The instrument name.
 * @param enableState The desired state.
 */
void runEnableInstrument(const std::string& socketPath, const std::string& nameInstrument, bool enableState = true);

/**
 * @brief List the instruments.
 *
 * @param request The request.
 */
void runListInstruments(const std::string& socketPath);

/**
 * @brief Run the command test.
 *
 * @param socketPath The socket.
 */
void runTest(const std::string& socketPath);
} // namespace cmd::metrics

#endif // _CMD_METRICS_HPP
