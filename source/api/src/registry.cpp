#include "api/registry.hpp"
#include "logging/logging.hpp"

namespace api
{

bool Registry::registerCommand(const std::string& command, const CommandFn callback)
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

CommandFn Registry::getCallback(const std::string& command)
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    if (m_commands.find(command) != m_commands.end())
    {
        return m_commands[command];
    }
    return [command](const json::Json&)
    {
        return base::utils::wazuhProtocol::WazuhResponse {
            json::Json {"{}"}, -1, fmt::format(R"(Command "{}" not found)", command)};
    };
};

} // namespace api
