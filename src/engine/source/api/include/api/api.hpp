#ifndef _API_API_HPP
#define _API_API_HPP

#include "registry.hpp"

#include <json/json.hpp>

namespace api
{
/**
 * @brief Class that handles all endpoints and exposes Server functionality.
 *
 * @note This class is thread-safe but the handlers must be thread-safe.

 */
class Api
{

private:
    std::shared_ptr<api::Registry> m_registry; ///< Registry of handlers

public:
    /**
     * @brief Construct a new Api
     */
    Api()
        : m_registry(std::make_shared<api::Registry>()) {};

    /**
     * @brief Register a handler for a command
     *
     * @param command Command to register
     * @param callback Callback to register
     * @return true if the handler was registered
     * @return false if the handler was not registered (command already registered)
     */
    bool registerHandler(const std::string& command, const Handler& callback)
    {
        return m_registry->registerHandler(command, callback);
    }

    /**
     * @brief Process a request
     *
     * Process a request as a string and return the response as a string, this
     * method is thread-safe and verify the request before calling the handler.
     * #TODO: add the correct description to the errors
     * #TODO: Test
     * Errors:
     * - If the request is invalid, the response will be an error message.
     * - If the handler throws an exception, the response will be an error message.
     * - If the handler is not registered, the response will be an error message.
     * @param message Request message
     * @return std::string Response message
     */
    std::string processRequest(const std::string& message)
    {
        wpResponse wresponse {};
        try
        {
            json::Json jrequest {message.c_str()};
            wpRequest wrequest {jrequest};
            if (wrequest.isValid())
            {
                wresponse = m_registry->getHandler(wrequest.getCommand().value())(wrequest);
            }
            else
            {
                wresponse = base::utils::wazuhProtocol::WazuhResponse::invalidRequest(wrequest.error().value());
            }
        }
        catch (const std::runtime_error& e)
        {
            wresponse = base::utils::wazuhProtocol::WazuhResponse::invalidJsonRequest();
        }
        catch (const std::exception& e)
        {
            wresponse = base::utils::wazuhProtocol::WazuhResponse::unknownError();
            // WAZUH_LOG_ERROR("Engine API endpoint: Error with client ({}): {}", client.peer(), e.what());
        }
        return wresponse.toString();
    }
};
} // namespace api

#endif // _API_API_HPP
