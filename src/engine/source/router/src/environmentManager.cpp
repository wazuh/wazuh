#include <router/environmentManager.hpp>

#include <logging/logging.hpp>
#include <name.hpp>

namespace router
{

std::optional<base::Error> PolicyManager::addPolicy(const std::string& name)
{
    // Validate the runtime policy name
    base::Name envName;
    try
    {
        envName = base::Name {name};
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Invalid policy name: '{}'", e.what())};
    }

    if (envName.parts().size() != 3)
    {
        return base::Error {fmt::format("Invalid policy name: '{}', the expected "
                                        "format is: \"policy/<env-name>/<version>\"",
                                        name)};
    }
    if (envName.parts()[0] != "policy")
    {
        return base::Error {fmt::format("Invalid policy name: '{}', it should "
                                        "start with the word \"policy\"",
                                        name)};
    }

    // Create the policy
    std::vector<RuntimePolicy> envs = {};
    envs.reserve(m_numInstances);
    for (std::size_t i = 0; i < m_numInstances; ++i)
    {
        auto env = RuntimePolicy {name};
        const auto err = env.build(m_builder);
        if (err)
        {
            return base::Error {err.value()};
        }
        envs.push_back(env);
    }
    // Add the policy to the runtime list
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        if (m_policys.find(name) != m_policys.end())
        {
            return base::Error {fmt::format("Policy '{}' already exists", name)};
        }
        m_policys.insert({name, std::move(envs)});
    }

    return std::nullopt;
}

std::optional<base::Error> PolicyManager::deletePolicy(const std::string& name)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_policys.find(name);
    if (it == m_policys.end())
    {
        return base::Error {fmt::format("Policy '{}' does not exist", name)};
    }

    if (m_policys.erase(name) != 1)
    {
        return base::Error {fmt::format("Policy '{}' could not be deleted", name)};
    }

    return std::nullopt;
}

void PolicyManager::delAllPolicys()
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_policys.clear();
}

std::vector<std::string> PolicyManager::listPolicys()
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    std::vector<std::string> names = {};
    names.reserve(m_policys.size());
    std::transform(
        m_policys.begin(), m_policys.end(), std::back_inserter(names), [](const auto& pair) { return pair.first; });

    return names;
}

std::optional<base::Error> PolicyManager::forwardEvent(const std::string& name, std::size_t instance, base::Event event)
{

    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_policys.find(name);
    if (m_policys.end() == it)
    {
        return base::Error {fmt::format("Policy '{}' does not exist", name)};
    }

    if (m_numInstances <= instance)
    {
        return base::Error {
            fmt::format("Invalid instance number '{}', the maximum is '{}'", instance, m_numInstances - 1)};
    }

    auto& env = it->second[instance];
    env.processEvent(std::move(event));

    return std::nullopt;
}

} // namespace router
