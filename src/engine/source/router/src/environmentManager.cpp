#include <router/environmentManager.hpp>

#include <logging/logging.hpp>
#include <name.hpp>

namespace router
{

std::optional<base::Error> EnvironmentManager::addEnvironment(const std::string& name)
{
    // Validate the runtime environment name
    base::Name envName;
    try
    {
        envName = base::Name {name};
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Invalid environment name: {}", e.what())};
    }

    if (envName.parts().size() != 3)
    {
        return base::Error {fmt::format("Invalid environment name: \"{}\", the expected "
                                        "format is: \"environment/<env-name>/<version>\"",
                                        name)};
    }
    if (envName.parts()[0] != "environment")
    {
        return base::Error {fmt::format("Invalid environment name: \"{}\", it should "
                                        "start with the word \"environment\"",
                                        name)};
    }

    std::unique_lock<std::shared_mutex> lock(m_mutex);
    if (m_environments.find(name) != m_environments.end())
    {
        return base::Error {fmt::format("Environment \"{}\" already exists", name)};
    }

    auto env = std::make_shared<RuntimeEnvironment>(name, m_numThreads, m_queue);
    const auto err = env->build(m_builder);
    if (err)
    {
        return base::Error {err.value()};
    }
    m_environments.emplace(name, std::move(env));

    return std::nullopt;
}

std::optional<base::Error> EnvironmentManager::delEnvironment(const std::string& name)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_environments.find(name);
    if (it == m_environments.end())
    {
        return base::Error {fmt::format("Environment \"{}\" does not exist", name)};
    }

    it->second->stop();
    m_environments.erase(it);

    return std::nullopt;
}

void EnvironmentManager::delAllEnvironments()
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    for (auto& [name, env] : m_environments)
    {
        env->stop();
    }
    m_environments.clear();
}

std::optional<base::Error> EnvironmentManager::startEnvironment(const std::string& name)
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_environments.find(name);
    if (it != m_environments.end())
    {
        const auto err = it->second->run(m_queue);
        if (err)
        {
            return base::Error {err.value()};
        }
        return std::nullopt;
    }
    return base::Error {fmt::format("Environment \"{}\" does not exist", name)};
}

std::vector<std::string> EnvironmentManager::getAllEnvironments()
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    std::vector<std::string> names = {};
    for (auto& [name, env] : m_environments)
    {
        names.push_back(name);
    }

    return names;
}

/********************************************************************
 *                  callback API Request
 ********************************************************************/

api::CommandFn EnvironmentManager::apiCallback()
{
    return [this](const json::Json params)
    {
        api::WazuhResponse response {};
        const auto action = params.getString("/action");

        if (!action)
        {
            response.message("Missing \"action\" parameter");
        }
        else if (action.value() == "set")
        {
            response = apiSetEnvironment(params);
        }
        else if (action.value() == "get")
        {
            response = apiGetEnvironment(params);
        }
        else if (action.value() == "delete")
        {
            response = apiDelEnvironment(params);
        }
        else
        {
            response.message(fmt::format("Invalid action \"{}\"", action.value()));
        }
        return response;
    };
}

api::WazuhResponse EnvironmentManager::apiSetEnvironment(const json::Json& params)
{

    api::WazuhResponse response {};
    auto name = params.getString("/name");
    if (!name)
    {
        response.message(
            "The \"/name\" parameter is missing, it is required and must be a string");
        return response;
    }

    auto err = addEnvironment(name.value());

    if (err)
    {
        response.message(err.value().message);
        return response;
    }

    // TODO: Delete this when support for multiple environments is added
    // If build OK, then delete other environments
    for (auto& otherEnv : getAllEnvironments())
    {
        if (otherEnv != name.value())
        {
            delEnvironment(otherEnv);
        }
    }

    // start environment
    err = startEnvironment(name.value());

    if (err)
    {
        response.message(err.value().message);
        return response;
    }
    response.message("Environment created and started");

    return response;
}

api::WazuhResponse EnvironmentManager::apiGetEnvironment(const json::Json& params)
{
    api::WazuhResponse response {};

    // Array of environments
    json::Json envs;
    envs.setArray();
    for (auto& e : getAllEnvironments())
    {
        envs.appendString(e);
    }
    response.data(std::move(envs));

    return response;
}

api::WazuhResponse EnvironmentManager::apiDelEnvironment(const json::Json& params)
{
    api::WazuhResponse response {};
    auto name = params.getString("/name");
    if (!name)
    {
        response.message(
            "The \"/name\" parameter is missing, it is required and must be a string");
        return response;
    }

    auto err = delEnvironment(name.value());
    if (err)
    {
        response.message(err.value().message);
    }
    else
    {
        response.message("Environment deleted");
    }

    return response;
}

} // namespace router
