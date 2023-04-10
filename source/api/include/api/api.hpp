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
     * @param message Request message
     * @return std::string Response message
     */
    std::string processRequest(const std::string& message)
    {
        wpResponse wresponse {};
        json::Json jrequest {};

        try
        {
            jrequest = json::Json {message.c_str()};
        }
        catch (const std::exception& e)
        {
            wresponse = base::utils::wazuhProtocol::WazuhResponse::invalidJsonRequest();
            return wresponse.toString();
        }

        try
        {
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
        catch (const std::exception& e)
        {
            WAZUH_LOG_DEBUG("Exception in Api::processRequest: %s", e.what());
            wresponse = base::utils::wazuhProtocol::WazuhResponse::unknownError();
        }
        return wresponse.toString();
    }
};
} // namespace api

#endif // _API_API_HPP
