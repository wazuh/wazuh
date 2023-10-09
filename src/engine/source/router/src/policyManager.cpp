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

    // Complete the policies before deleting them
    for (auto& policy : it->second)
    {
        policy.complete();
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

    // TODO: Redesing the logic so this is not needed to be manual
    for (auto& [name, runPolicy] : m_policies)
    {
        for (auto& policy : runPolicy)
        {
            policy.complete();
        }
    }

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

std::optional<base::Error> PolicyManager::forwardEvent(const std::string& name, std::size_t instance, base::Event&& event)
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
    env.processEvent(std::move(event));

    return std::nullopt;
}

std::optional<base::Error> PolicyManager::subscribeOutputAndTraces(const OutputSubscriber& outputCallback,
                                                                   const bk::Subscriber& traceCallback,
                                                                   const std::vector<std::string>& assets,
                                                                   const std::string& name)
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_policies.find(name);
    if (m_policies.end() == it)
    {
        return base::Error {fmt::format("Policy '{}' does not exist", name)};
    }

    for (auto& env : it->second)
    {
        if (auto err = env.subscribeToOutput(outputCallback))
        {
            return err;
        }
        if (auto err = env.listenAllTrace(traceCallback, assets))
        {
            return err;
        }
    }

    return std::nullopt;
}

base::RespOrError<std::vector<std::string>> PolicyManager::getAssets(const std::string& name, std::size_t instance)
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

    return env.getAssets();
}

base::OptError PolicyManager::unSubscribeTraces(const std::string& name, std::size_t instance)
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

    env.unSubscribeTraces();

    return std::nullopt;
}

std::optional<std::string>  PolicyManager::getPolicyHash(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_policies.find(name);
    if (m_policies.end() == it)
    {
        return std::nullopt;
    }

    return it->second[0].hash();
}

} // namespace router
