#ifndef _API_REGISTRY_HPP
#define _API_REGISTRY_HPP

#include <functional>
#include <map>
#include <shared_mutex>
#include <string>

#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>

namespace api
{

/**
 * @brief Alias for WazuhResponse and WazuhRequest
 */
using wpResponse = base::utils::wazuhProtocol::WazuhResponse;
using wpRequest = base::utils::wazuhProtocol::WazuhRequest;
/**
 * @brief Represent a handler function, which receives a WazuhRequest and returns a WazuhResponse
 */
using HandlerAsync = std::function<void(const wpRequest&, std::function<void(const wpResponse&)>)>;
using HandlerSync = std::function<wpResponse(const wpRequest&)>;

/**
 * @brief A registry for API handlers
 *
 * This class is used as registry of API wazuh internal handlers.
 * It allows to register API command with a handler function.
 *
 */
class Registry
{

    std::map<std::string, HandlerAsync> m_handlers; ///< Map of command and handlers
    std::shared_mutex m_mutex;                 ///< A mutex for thread safety (protect m_handlers)

public:
    // Constructors
    Registry()
        : m_handlers()
        , m_mutex() {};
    ~Registry()
    {
        // Lock mutex for write access and unlock on destruction
        std::unique_lock<std::shared_mutex> lock {m_mutex};
        m_handlers.clear();
    };

    // A unique instance of the same registry, remove copy and move constructors
    Registry(const Registry&) = delete;
    Registry(Registry&&) = delete;
    Registry& operator=(const Registry&) = delete;
    Registry& operator=(Registry&&) = delete;

    /**
     * @brief Register a route in the registry
     *
     * @param command The command name, can't be empty
     * @param handler The handler function
     * @return true If the command was registered
     * @return false If the command was not registered (already exists, the command is
     * empty or the callback is null)
     */
    bool registerHandler(const std::string& command, const HandlerAsync& handler);

    /**
     * @brief Get the callback function for a command
     *
     * @param command The command name
     * @return The handler function
     * @return commandNotFound function If the command was not found
     */
    HandlerAsync getHandler(const std::string& command);
};

} // namespace api

#endif // _API_REGISTRY_HPP
