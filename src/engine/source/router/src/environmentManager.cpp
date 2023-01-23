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
        return base::Error {fmt::format("Invalid environment name: '{}'", e.what())};
    }

    if (envName.parts().size() != 3)
    {
        return base::Error {fmt::format("Invalid environment name: '{}', the expected "
                                        "format is: \"environment/<env-name>/<version>\"",
                                        name)};
    }
    if (envName.parts()[0] != "environment")
    {
        return base::Error {fmt::format("Invalid environment name: '{}', it should "
                                        "start with the word \"environment\"",
                                        name)};
    }

    // Create the environment
    std::vector<RuntimeEnvironment> envs = {};
    envs.reserve(m_numInstances);
    for (std::size_t i = 0; i < m_numInstances; ++i)
    {
        auto env = RuntimeEnvironment {name};
        const auto err = env.build(m_builder);
        if (err)
        {
            return base::Error {err.value()};
        }
        envs.push_back(env);
    }
    // Add the environment to the runtime list
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        if (m_environments.find(name) != m_environments.end())
        {
            return base::Error {fmt::format("Environment '{}' already exists.", name)};
        }
        m_environments.insert({name, std::move(envs)});
    }

    return std::nullopt;
}

std::optional<base::Error> EnvironmentManager::deleteEnvironment(const std::string& name)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_environments.find(name);
    if (it == m_environments.end())
    {
        return base::Error {fmt::format("Environment '{}' doesn't exist.", name)};
    }

    if (m_environments.erase(name) != 1)
    {
        return base::Error {fmt::format("Environment '{}' could not be deleted.", name)};
    }

    return std::nullopt;
}

void EnvironmentManager::delAllEnvironments()
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_environments.clear();
}

std::vector<std::string> EnvironmentManager::listEnvironments()
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    std::vector<std::string> names = {};
    names.reserve(m_environments.size());
    std::transform(m_environments.begin(),
                   m_environments.end(),
                   std::back_inserter(names),
                   [](const auto& pair) { return pair.first; });

    return names;
}

std::optional<base::Error>
EnvironmentManager::forwardEvent(const std::string& name, std::size_t instance, base::Event event)
{

    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_environments.find(name);
    if (it == m_environments.end())
    {
        return base::Error {fmt::format("Environment '{}' doesn't exist.", name)};
    }

    if (instance >= m_numInstances)
    {
        return base::Error {fmt::format("Invalid instance number '{}', the maximum is '{}'",
                                        instance,
                                        m_numInstances - 1)};
    }

    auto& env = it->second[instance];
    env.processEvent(std::move(event));

    return std::nullopt;
}

} // namespace router
