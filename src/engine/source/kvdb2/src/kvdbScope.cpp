#include <kvdb2/iKVDBHandlerManager.hpp>
#include <kvdb2/kvdbScope.hpp>

namespace kvdbManager
{

std::unique_ptr<IKVDBHandler> KVDBScope::getKVDBHandler(const std::string& dbName)
{
    return m_handlerManager->getKVDBHandler(dbName, m_name);
}

} // namespace kvdbManager
