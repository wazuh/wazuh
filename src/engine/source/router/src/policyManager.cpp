#include <router/policyManager.hpp>

#include <logging/logging.hpp>
#include <name.hpp>

namespace router
{

std::optional<base::Error> PolicyManager::addPolicy(const std::string& name)
{
    // Validate the runtime policy name
    base::Name policyName;
    try
    {
        policyName = base::Name {name};
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Invalid policy name: '{}'", e.what())};
    }

    if (policyName.parts().size() != 3)
    {
        return base::Error {fmt::format("Invalid policy name: '{}', the expected "
                                        "format is: \"policy/<policy-name>/<version>\"",
                                        name)};
    }
    if (policyName.parts()[0] != "policy")
    {
        return base::Error {fmt::format("Invalid policy name: '{}', it should "
                                        "start with the word \"policy\"",
                                        name)};
    }

    // Create the policy
    std::vector<std::unique_ptr<RuntimePolicy>> envs;
    envs.reserve(m_numInstances);

    for (std::size_t i = 0; i < m_numInstances; ++i)
    {
        auto env = std::make_unique<RuntimePolicy>(name);
        const auto err = env->build(m_builder);
        if (err)
        {
            return base::Error {err.value()};
        }
        envs.push_back(std::move(env));
    }
    // Add the policy to the runtime list
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        if (m_policies.find(name) != m_policies.end())
        {
            return base::Error {fmt::format("Policy '{}' already exists", name)};
        }
        m_policies.insert({name, std::move(envs)});
    }

    return std::nullopt;
}

std::optional<base::Error> PolicyManager::deletePolicy(const std::string& name)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_policies.find(name);
    if (it == m_policies.end())
    {
        return base::Error {fmt::format("Policy '{}' does not exist", name)};
    }

    if (m_policies.erase(name) != 1)
    {
        return base::Error {fmt::format("Policy '{}' could not be deleted", name)};
    }

    return std::nullopt;
}

void PolicyManager::delAllPolicies()
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_policies.clear();
}

std::vector<std::string> PolicyManager::listPolicies()
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    std::vector<std::string> names = {};
    names.reserve(m_policies.size());
    std::transform(
        m_policies.begin(), m_policies.end(), std::back_inserter(names), [](const auto& pair) { return pair.first; });

    return names;
}

std::optional<base::Error> PolicyManager::forwardEvent(const std::string& name, std::size_t instance, base::Event event)
{

    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_policies.find(name);
    if (m_policies.end() == it)
    {
        return base::Error {fmt::format("Policy '{}' does not exist", name)};
    }

    if (m_numInstances <= instance)
    {
        return base::Error {
            fmt::format("Invalid instance number '{}', the maximum is '{}'", instance, m_numInstances - 1)};
    }

    auto& env = it->second[instance];
    env->processEvent(std::move(event));
    m_output = env->getOutput();
    m_trace = env->getTrace();

    return std::nullopt;
}

} // namespace router
