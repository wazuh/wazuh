#include "api/wazuhRequest.hpp"

namespace api
{
/*
 * https://github.com/wazuh/wazuh/issues/5934
 */
std::optional<std::string> WazuhRequest::validate() const
{
    if (!m_jrequest.isObject())
    {
        return "The request must be a JSON type object";
    }
    if (!m_jrequest.exists("/version") || !m_jrequest.isInt("/version"))
    {
        return "The request must have a version field with an integer value";
    }
    // Check if the version is supported
    if (m_jrequest.getInt("/version").value() != VERSION_SUPPORTED)
    {
        return "The request version is not supported";
    }
    if (!m_jrequest.exists("/command") || !m_jrequest.isString("/command"))
    {
        return "The request must have a command field with a string value";
    }
    if (!m_jrequest.exists("/parameters") || !m_jrequest.isObject("/parameters"))
    {
        return "The request must have a parameters field with a JSON object value";
    }
    if (!m_jrequest.exists("/origin") || !m_jrequest.isObject("/origin"))
    {
        return "The request must have an origin field with a JSON object value";
    }
    if (!m_jrequest.exists("/origin/name") || !m_jrequest.isString("/origin/name"))
    {
        return "The request must have an origin/name field with a string value";
    }
    if (!m_jrequest.exists("/origin/module") || !m_jrequest.isString("/origin/module"))
    {
        return "The request must have an origin/module field with a string value";
    }

    return std::nullopt;
}

WazuhRequest WazuhRequest::create(std::string_view command,
                                  std::string_view originName,
                                  const json::Json& parameters)
{

    if (command.empty())
    {
        throw std::runtime_error("Engine API request: A command cannot be empty.");
    }
    if (!parameters.isObject())
    {
        throw std::runtime_error(
            "Engine API request: The command parameters must be object JSON type.");
    }

    json::Json jrequest;
    jrequest.setInt(VERSION_SUPPORTED, "/version");
    jrequest.setString(command, "/command");
    jrequest.set("/parameters", parameters);
    jrequest.setString("wazuh-engine", "/origin/module");
    jrequest.setString(originName, "/origin/name");

    return WazuhRequest(jrequest);
}

} // namespace api
