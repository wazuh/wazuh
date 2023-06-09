#ifndef _CMD_TEST_HPP
#define _CMD_TEST_HPP

#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>
#include <cmds/apiclnt/client.hpp>

namespace cmd::test
{

namespace details
{
constexpr auto ORIGIN_NAME {"engine_integrated_test_api"};
} // namespace details

struct Options
{
    std::string apiEndpoint;
    std::string sessionName;
    std::string event;
    std::string protocolLocation;
    uint32_t protocolQueue;
    int debugLevel;
};

/**
 * @brief Command handler to test an event in a certain session.
 * 
 * @param client Client instance
 * @param options Options instance
 */
void run(std::shared_ptr<apiclnt::Client> client, const Options& options);

void configure(CLI::App_p app);
} // namespace cmd::test

#endif // _CMD_TEST_HPP
