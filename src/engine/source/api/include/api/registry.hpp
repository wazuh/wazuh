#ifndef _API_REGISTRY_HPP
#define _API_REGISTRY_HPP

#include <functional>
#include <map>
#include <shared_mutex>
#include <string>

#include <json/json.hpp>

#include <utils/wazuhProtocol/wazuhResponse.hpp>
#include <utils/wazuhProtocol/wazuhRequest.hpp>

namespace api
{

// TODO: Implement a way to unregister commands
// TODO: Add a command to list all available commands (And their description)
// TODO: Add a command to get info about engine (version, etc) and API (version, etc)

/**
 * @brief Represent a command function, which receives a json::Json with the params and
 * returns a WazuhResponse.
 */
// TODO change accept WazuhRequest
using wpResponse = base::utils::wazuhProtocol::WazuhResponse;
using wpRequest = base::utils::wazuhProtocol::WazuhRequest;
using CommandFn = std::function<wpResponse(const wpRequest&)>; // TODO change to HANDLER

/**
 * @brief A registry for API commands
 *
 * This class is used as registry of API wazuh internal commands.
 * It allows to register API commands with a callback function.
 *
 */
class Registry
{

    std::map<std::string, CommandFn> m_commands; ///< Map of commands and callbacks
    std::shared_mutex m_mutex; ///< A mutex for thread safety (protect m_commands)

public:
    // Constructors
    Registry()
        : m_commands()
        , m_mutex() {};
    ~Registry()
    {
        // Lock mutex for write access and unlock on destruction
        std::unique_lock<std::shared_mutex> lock {m_mutex};
        m_commands.clear();
    };

    // A unique instance of the same registry, remove copy and move constructors
    Registry(const Registry&) = delete;
    Registry(Registry&&) = delete;
    Registry& operator=(const Registry&) = delete;
    Registry& operator=(Registry&&) = delete;

    /**
     * @brief Register a command in the registry
     *
     * @param command The command name, can't be empty
     * @param callback The callback function
     * @return true If the command was registered
     * @return false If the command was not registered (already exists, the command is
     * empty or the callback is null)
     */
    bool registerCommand(const std::string& command, const CommandFn callback);

    /**
     * @brief Get the callback function for a command
     *
     * @param command The command name
     * @return The callback function
     * @return commandNotFound function If the command was not found
     */
    CommandFn getCallback(const std::string& command);
};

} // namespace api

#endif // _API_REGISTRY_HPP
