#include <router/environmentManager.hpp>

namespace router
{

std::optional<base::Error> EnvironmentManager::addEnvironment(const std::string& name)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    if (m_environments.find(name) != m_environments.end())
    {
        return base::Error {"Environment already exists"};
    }

    auto env = std::make_shared<RuntimeEnvironment>(name, m_numThreads, m_queue);
    auto err = env->build(m_builder);
    if (err)
    {
        return base::Error {err.value()};
    }
    m_environments.emplace(name, std::move(env));
    return std::nullopt;
}

void EnvironmentManager::delEnvironment(const std::string& name)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_environments.find(name);
    if (it != m_environments.end())
    {
        it->second->stop();
        m_environments.erase(it);
    }
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
        auto err = it->second->run(m_queue);
        if (err)
        {
            return base::Error {err.value()};
        }
        return std::nullopt;
    }
    return base::Error {"Environment does not exist"};
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
        auto action = params.getString("/action");

        if (!action)
        {
            response.message("Missing action parameter");
        }
        else if (action.value() == "set")
        {
            response = apiSetEnvironment(params);
        }
        else if (action.value() == "get")
        {
            response = apiGetEnvironment(params);
        }
        else
        {
            response.message("Invalid action parameter");
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

} // namespace router
