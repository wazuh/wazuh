#include <kvdb2/kvdbHandlerCollection.hpp>

namespace kvdbManager
{

std::shared_ptr<IKVDBHandler> KVDBHandlerCollection::getKVDBHandler(const std::string& dbName, const std::string& scopeName)
{
    auto it = m_mapInstances.find(dbName);
    if (it != m_mapInstances.end())
    {
        auto &instance = it->second;
        instance->addScope(scopeName);
        return it->second->getHandler();
    }
    else
    {
        auto spHandler = std::make_shared<KVDBSpace>(m_handleManager, dbName, scopeName);
        auto spInstance = std::make_shared<KVDBHandlerInstance>(spHandler);
        spInstance->addScope(scopeName);
        m_mapInstances.insert(std::make_pair(dbName, spInstance));
        return spHandler;
    }
}

} // namespace kvdbManager
