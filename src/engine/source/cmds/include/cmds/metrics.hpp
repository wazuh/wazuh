#ifndef _CMD_METRICS_HPP
#define _CMD_METRICS_HPP

#include <CLI/CLI.hpp>

#include <cmds/apiclnt/client.hpp>
#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>

namespace cmd::metrics
{

namespace details
{
constexpr auto ORIGIN_NAME {"engine_integrated_metrics_api"};
constexpr auto API_METRICS_DUMP_SUBCOMMAND {"dump"};
constexpr auto API_METRICS_GET_SUBCOMMAND {"get"};
constexpr auto API_METRICS_ENABLE_SUBCOMMAND {"enable"};
constexpr auto API_METRICS_LIST_SUBCOMMAND {"list"};
constexpr auto API_METRICS_TEST_SUBCOMMAND {"test"};

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
void runDump(std::shared_ptr<apiclnt::Client> client);

/**
 * @brief Run the command get.
 *
 * @param socketPath The socket.
 * @param name The instrument name.
 */
void runGetInstrument(std::shared_ptr<apiclnt::Client> client, const std::string& scopeName, const std::string& instrumentName);

/**
 * @brief Enables or disables an instrument.
 *
 * @param socketPath The socket.
 * @param name The instrument name.
 * @param status The desired status.
 */
void runEnableInstrument(std::shared_ptr<apiclnt::Client> client, const std::string& scopeName, const std::string& instrumentName, bool status);

/**
 * @brief List the instruments.
 *
 * @param request The request.
 */
void runListInstruments(std::shared_ptr<apiclnt::Client> client);

/**
 * @brief Run the command test.
 *
 * @param socketPath The socket.
 */
void runTest(std::shared_ptr<apiclnt::Client> client);
} // namespace cmd::metrics

#endif // _CMD_METRICS_HPP
