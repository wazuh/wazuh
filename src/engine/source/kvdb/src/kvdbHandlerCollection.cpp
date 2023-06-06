#include <fmt/format.h>
#include <kvdb/kvdbHandlerCollection.hpp>
#include <logging/logging.hpp>

namespace kvdbManager
{

std::shared_ptr<IKVDBHandler> KVDBHandlerCollection::getKVDBHandler(rocksdb::DB* db,
                                                  rocksdb::ColumnFamilyHandle* cfHandle,
                                                  const std::string& dbName,
                                                  const std::string& scopeName)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_mapInstances.find(dbName);
    if (it != m_mapInstances.end())
    {
        auto& instance = it->second;
        instance->addScope(scopeName);
    }
    else
    {
        auto spInstance = std::make_shared<KVDBHandlerInstance>();
        spInstance->addScope(scopeName);
        m_mapInstances.insert(std::make_pair(dbName, std::move(spInstance)));
    }

    return std::make_unique<KVDBSpace>(m_handleManager, db, cfHandle, dbName, scopeName);
}

void KVDBHandlerCollection::removeKVDBHandler(const std::string& dbName, const std::string& scopeName, bool& isRemoved)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    isRemoved = false;
    auto it = m_mapInstances.find(dbName);
    if (it != m_mapInstances.end())
    {
        auto instance = it->second;
        instance->removeScope(scopeName);
        if (instance->emptyScopes())
        {
            m_mapInstances.erase(it);
            isRemoved = true;
        }
    }
}

std::vector<std::string> KVDBHandlerCollection::getDBNames()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> dbNames;
    for (const auto& instance : m_mapInstances)
    {
        dbNames.push_back(instance.first);
    }
    return dbNames;
}

std::map<std::string, int> KVDBHandlerCollection::getRefMap(const std::string& dbName)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_mapInstances.find(dbName);
    if (it != m_mapInstances.end())
    {
        return it->second->getRefMap();
    }

    return std::map<std::string, int>();
}

void KVDBHandlerCollection::KVDBHandlerInstance::addScope(const std::string& scopeName)
{
    m_scopeCounter.addRef(scopeName);
}

void KVDBHandlerCollection::KVDBHandlerInstance::removeScope(const std::string& scopeName)
{
    m_scopeCounter.removeRef(scopeName);
}

bool KVDBHandlerCollection::KVDBHandlerInstance::emptyScopes() const
{
    return m_scopeCounter.empty();
}

std::vector<std::string> KVDBHandlerCollection::KVDBHandlerInstance::getRefNames() const
{
    return m_scopeCounter.getRefNames();
}

std::map<std::string, int> KVDBHandlerCollection::KVDBHandlerInstance::getRefMap() const
{
    return m_scopeCounter.getRefMap();
}

} // namespace kvdbManager
