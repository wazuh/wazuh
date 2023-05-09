#include <kvdb2/kvdbHandlerCollection.hpp>

namespace kvdbManager
{

std::shared_ptr<IKVDBHandler> KVDBHandlerCollection::getKVDBHandler(rocksdb::DB* db, rocksdb::ColumnFamilyHandle* cfHandle, const std::string& dbName, const std::string& scopeName)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_mapInstances.find(dbName);
    if (it != m_mapInstances.end())
    {
        auto &instance = it->second;
        instance->addScope(scopeName);
        return it->second->getHandler();
    }
    else
    {
        auto spHandler = std::make_shared<KVDBSpace>(m_handleManager, db, cfHandle, dbName, scopeName);
        auto spInstance = std::make_shared<KVDBHandlerInstance>(spHandler);
        spInstance->addScope(scopeName);
        m_mapInstances.insert(std::make_pair(dbName, spInstance));
        return spHandler;
    }
}

void KVDBHandlerCollection::removeKVDBHandler(const std::string& dbName, const std::string& scopeName)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_mapInstances.find(dbName);
    if (it != m_mapInstances.end())
    {
        auto &instance = it->second;
        instance->removeScope(scopeName);
        if (instance->emptyScopes())
        {
            m_mapInstances.erase(it);
        }
    }
}
} // namespace kvdbManager
