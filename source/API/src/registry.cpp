#include "API/registry.hpp"


namespace api
{

bool Registry::registerCommand(const std::string& command, const CommandFn callback)
{
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
    return [](const json::Json&)
    {
        return WazuhResponse {json::Json {}, -1, "Command not found"};
    };
};

} // namespace api
