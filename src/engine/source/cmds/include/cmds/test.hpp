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

constexpr auto SESSION_GET_DATA_FORMAT = R"({{"id":"{}","creation_date":"{}","policy":"{}","filter":"{}",)"
                                         R"("route":"{}","lifespan":{},"description":"{}"}})"; ///< Session data format

constexpr auto OUTPUT_ONLY {0};
constexpr auto OUTPUT_AND_TRACES {1};
constexpr auto OUTPUT_AND_TRACES_WITH_DETAILS {2};

struct Parameters
{
    bool deleteAll;
    bool jsonFormat;
    int32_t debugLevel;
    std::string apiEndpoint;
    std::string assetTrace;
    std::string description;
    std::string event;
    std::string policy;
    std::string protocolLocation;
    std::string protocolQueue;
    std::string sessionName;
    uint32_t lifespan;
    int clientTimeout;
};

/**
 * @brief Command handler to test an event in a certain session.
 *
 * @param client Client instance
 * @param parameters Parameters instance
 */
void run(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters);

void configure(CLI::App_p app);
} // namespace cmd::test

#endif // _CMD_TEST_HPP
