#include "api/registry.hpp"
#include "logging/logging.hpp"

namespace api
{

bool Registry::registerCommand(const std::string& command, const Handler callback)
{
    if (command.empty() || callback == nullptr)
    {
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(m_mutex);
    if (m_commands.find(command) != m_commands.end())
    {
        return false;
    }
    m_commands[command] = callback;

    return true;
};

Handler Registry::getCallback(const std::string& command)
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    if (m_commands.find(command) != m_commands.end())
    {
        return m_commands[command];
    }
    return [command](const base::utils::wazuhProtocol::WazuhRequest& req)
    {
        return base::utils::wazuhProtocol::WazuhResponse {
            json::Json {"{}"},
            static_cast<int>(base::utils::wazuhProtocol::RESPONSE_ERROR_CODES::COMMAND_NOT_FOUND),
            fmt::format(R"(Command "{}" not found)", command)};
    };
};

} // namespace api
