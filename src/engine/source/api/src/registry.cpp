#include "api/registry.hpp"

#include <base/logging.hpp>

namespace api
{

bool Registry::registerHandler(const std::string& command, const HandlerAsync& handler)
{
    if (command.empty() || handler == nullptr)
    {
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(m_mutex);
    if (m_handlers.find(command) != m_handlers.end())
    {
        return false;
    }
    m_handlers[command] = handler;

    return true;
};

HandlerAsync Registry::getHandler(const std::string& command)
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    if (m_handlers.find(command) != m_handlers.end())
    {
        return m_handlers[command];
    }
    return [command](const base::utils::wazuhProtocol::WazuhRequest& req,
                     std::function<void(const base::utils::wazuhProtocol::WazuhResponse&)> callbackFn)
    {
        auto response = base::utils::wazuhProtocol::WazuhResponse {
            json::Json {"{}"},
            static_cast<int>(base::utils::wazuhProtocol::RESPONSE_ERROR_CODES::COMMAND_NOT_FOUND),
            fmt::format(R"(Command "{}" not found)", command)};

        callbackFn(response);
    };
};

} // namespace api
