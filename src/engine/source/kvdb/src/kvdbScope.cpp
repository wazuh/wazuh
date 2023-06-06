#include <kvdb/iKVDBHandlerManager.hpp>
#include <kvdb/kvdbScope.hpp>

namespace kvdbManager
{

std::variant<std::shared_ptr<IKVDBHandler>, base::Error> KVDBScope::getKVDBHandler(const std::string& dbName)
{
    return m_handlerManager->getKVDBHandler(dbName, m_name);
}

} // namespace kvdbManager
