#include <fmt/format.h>

#include <base/logging.hpp>

#include <kvdb/kvdbHandlerCollection.hpp>

namespace kvdbManager
{

void KVDBHandlerCollection::addKVDBHandler(const std::string& dbName, const std::string& scopeName)
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    const auto it = m_mapInstances.find(dbName);
    if (it != m_mapInstances.end())
    {
        auto& instance = it->second;
        instance->addScope(scopeName);
    }
    else
    {
        auto spInstance = std::make_shared<KVDBHandlerInstance>();
        spInstance->addScope(scopeName);
        m_mapInstances.emplace(dbName, std::move(spInstance));
    }
}

void KVDBHandlerCollection::removeKVDBHandler(const std::string& dbName, const std::string& scopeName)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    const auto it = m_mapInstances.find(dbName);
    if (it != m_mapInstances.end())
    {
        auto& instance = it->second;
        instance->removeScope(scopeName);
        if (instance->emptyScopes())
        {
            m_mapInstances.erase(it);
        }
    }
}

std::vector<std::string> KVDBHandlerCollection::getDBNames()
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    std::vector<std::string> dbNames;
    dbNames.reserve(m_mapInstances.size());

    for (const auto& instance : m_mapInstances)
    {
        dbNames.push_back(instance.first);
    }

    return dbNames;
}

std::map<std::string, uint32_t> KVDBHandlerCollection::getRefMap(const std::string& dbName)
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    const auto it = m_mapInstances.find(dbName);
    if (it != m_mapInstances.end())
    {
        return it->second->getRefMap();
    }

    return {};
}

void KVDBHandlerInstance::addScope(const std::string& scopeName)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    m_scopeCounter.addRef(scopeName);
}

void KVDBHandlerInstance::removeScope(const std::string& scopeName)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    m_scopeCounter.removeRef(scopeName);
}

bool KVDBHandlerInstance::emptyScopes()
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    return m_scopeCounter.empty();
}

std::vector<std::string> KVDBHandlerInstance::getRefNames()
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    return m_scopeCounter.getRefNames();
}

std::map<std::string, uint32_t> KVDBHandlerInstance::getRefMap()
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    return m_scopeCounter.getRefMap();
}

} // namespace kvdbManager
