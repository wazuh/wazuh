#ifndef _CMD_TEST_HPP
#define _CMD_TEST_HPP

#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>
#include <cmds/apiclnt/client.hpp>

namespace cmd::tester
{

namespace details
{
constexpr auto ORIGIN_NAME {"engine_integrated_test_api"};
} // namespace details

constexpr auto OUTPUT_ONLY {0};
constexpr auto OUTPUT_AND_TRACES {1};
constexpr auto OUTPUT_AND_TRACES_WITH_DETAILS {2};

/**
 * @brief Struct holding various configuration parameters.
 *
 * This struct stores a collection of parameters used for program configuration.
 */
struct Parameters
{
    bool jsonFormat;                      /**< Output data in JSON format. */
    int32_t debugLevel;                   /**< Debug level value. */
    std::string apiEndpoint;              /**< API endpoint to connect to. */
    std::vector<std::string> assetTrace;  /**< Asset tracing configuration. */
    std::string description;              /**< Description for the operation. */
    std::string event;                    /**< Event associated with the operation. */
    std::vector<std::string> namespaceid; /**< Namespaces where are the assets to test */
    std::string policy;                   /**< Policy configuration. */
    std::string protocolLocation;         /**< Protocol location. */
    std::string protocolQueue;            /**< Protocol queue. */
    std::string sessionName;              /**< Session name. */
    uint32_t lifetime;                    /**< Lifetime duration. */
    int clientTimeout;                    /**< Client timeout duration. */
};

/**
 * @brief Creates a new testing session based on the provided parameters.
 *
 * This function connects to the provided API client and creates a new testing session using the specified parameters.
 *
 * @param client A shared pointer to the apiclnt::Client instance.
 * @param parameters The configuration parameters for creating the testing session.
 */
void sessionCreate(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters);

/**
 * @brief Deletes an existing testing session based on the provided parameters.
 *
 * This function connects to the provided API client and deletes an existing testing session using the specified parameters.
 *
 * @param client A shared pointer to the apiclnt::Client instance.
 * @param parameters The configuration parameters for deleting the testing session.
 */
void sessionDelete(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters);

/**
 * @brief Retrieves information about a specific testing session based on the provided parameters.
 *
 * This function connects to the provided API client and retrieves information about a specific testing session using the specified parameters.
 *
 * @param client A shared pointer to the apiclnt::Client instance.
 * @param parameters The configuration parameters for getting information about the testing session.
 */
void sessionGet(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters);

/**
 * @brief Retrieves a list of all existing testing sessions.
 *
 * This function connects to the provided API client and retrieves a list of all existing testing sessions.
 *
 * @param client A shared pointer to the apiclnt::Client instance.
 */
void sessionList(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters);

/**
 * @brief Command handler to test an event in a certain session.
 *
 * @param client Client instance
 * @param parameters Parameters instance
 */
void run(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters);

/**
 * @brief Configures the program using the provided CLI application instance.
 *
 * This function is responsible for configuring the program's behavior by
 * setting up command-line options and arguments using the provided CLI application instance.
 *
 * @param app A pointer to the CLI::App instance to be configured.
 */
void configure(CLI::App_p app);
} // namespace cmd::test

#endif // _CMD_TEST_HPP
