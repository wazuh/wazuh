#ifndef _CMD_ROUTER_HPP
#define _CMD_ROUTER_HPP

#include <string>

#include <CLI/CLI.hpp>
#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>
#include <cmds/apiclnt/client.hpp>

namespace cmd::router
{

namespace details
{
constexpr auto ORIGIN_NAME = "engine_integrated_router_api";
} // namespace details

/**
 * @brief Retrieves information about a specific router based on its name.
 *
 * This function connects to the provided API client and retrieves information about a specific router
 * using the specified router name.
 *
 * @param client A shared pointer to the apiclnt::Client instance.
 * @param nameStr The name of the router to retrieve information about.
 */
void runGet(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr, const bool jsonFormat);

/**
 * @brief Adds a new router with the specified parameters.
 *
 * This function connects to the provided API client and adds a new router with the specified name, priority,
 * filter name, and policy.
 *
 * @param client A shared pointer to the apiclnt::Client instance.
 * @param nameStr The name of the router to add.
 * @param priority The priority of the router.
 * @param filterName The name of the filter associated with the router.
 * @param policy The policy associated with the router.
 */
void runAdd(std::shared_ptr<apiclnt::Client> client,
            const std::string& nameStr,
            int priority,
            const std::string& filterName,
            const std::string& policy);

/**
 * @brief Deletes an existing router based on its name.
 *
 * This function connects to the provided API client and deletes an existing router with the specified name.
 *
 * @param client A shared pointer to the apiclnt::Client instance.
 * @param nameStr The name of the router to delete.
 */
void runDelete(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr);

/**
 * @brief Reloads the configuration of a specific router based on its name.
 *
 * This function connects to the provided API client and reloads the configuration of a specific router
 * using the specified router name.
 *
 * @param client A shared pointer to the apiclnt::Client instance.
 * @param nameStr The name of the router to reload.
 */
void runReload(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr);

/**
 * @brief Updates the priority of an existing router based on its name.
 *
 * This function connects to the provided API client and updates the priority of an existing router
 * using the specified router name and priority.
 *
 * @param client A shared pointer to the apiclnt::Client instance.
 * @param nameStr The name of the router to update.
 * @param priority The new priority for the router.
 */
void runUpdate(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr, int priority);

/**
 * @brief Ingests an event into the router with the specified name.
 *
 * This function connects to the provided API client and ingests the specified event into the router
 * using the specified router name.
 *
 * @param client A shared pointer to the apiclnt::Client instance.
 * @param event The event to be ingested into the router.
 */
void runIngest(std::shared_ptr<apiclnt::Client> client, const std::string& event);

/**
 * @brief Change the EPS limiter settings
 *
 * @param client A shared pointer to the apiclnt::Client instance.
 * @param eps Number of events per second allowed to be processed
 * @param intervalSec Interval window size in seconds for resetting the counter
 */
void runChangeEpsSettings(std::shared_ptr<apiclnt::Client> client, int eps, int intervalSec);

/**
 * @brief Get the EPS limiter settings
 *
 * @param client A shared pointer to the apiclnt::Client instance.
 */
void runGetEpsSettings(std::shared_ptr<apiclnt::Client> client);

/**
 * @brief Activate the EPS limiter
 *
 * @param client A shared pointer to the apiclnt::Client instance.
 */
void runActivateEps(std::shared_ptr<apiclnt::Client> client);

/**
 * @brief Deactivate the EPS limiter
 *
 * @param client A shared pointer to the apiclnt::Client instance.
 */
void runDeactivateEps(std::shared_ptr<apiclnt::Client> client);

/**
 * @brief Configures the program using the provided CLI application instance.
 *
 * This function is responsible for configuring the program's behavior by
 * setting up command-line options and arguments using the provided CLI application instance.
 *
 * @param app A pointer to the CLI::App instance to be configured.
 */
void configure(CLI::App_p app);
} // namespace cmd::router

#endif // _CMD_ROUTER_HPP
