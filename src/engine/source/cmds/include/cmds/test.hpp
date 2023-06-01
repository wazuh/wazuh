#ifndef _CMD_TEST_HPP
#define _CMD_TEST_HPP

#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <cmds/apiclnt/client.hpp>
#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>

namespace cmd::test
{

namespace details
{
constexpr auto ORIGIN_NAME {"engine_integrated_test_api"};
} // namespace details

/**
 * @brief Run policy in test mode. Inputs from stdin, outputs event to stdout and
 * debug to stderr.
 *
 * @param policyName Path to KVDB folder.
 * @param event Path to asset folders.
 */
struct Options
{
    std::string apiEndpoint;
    std::string policyName;
    std::string event;
    std::string protocolLocation;
    uint32_t protocolQueue;
    int debugLevel;
};

void run(std::shared_ptr<apiclnt::Client> client, const Options& options);

void configure(CLI::App_p app);
} // namespace cmd::test

#endif // _CMD_TEST_HPP
