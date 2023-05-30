#include <kvdb2/iKVDBHandlerManager.hpp>
#include <kvdb2/kvdbScope.hpp>

namespace kvdbManager
{

std::variant<std::unique_ptr<IKVDBHandler>, base::Error> KVDBScope::getKVDBHandler(const std::string& dbName)
{
    return m_handlerManager->getKVDBHandler(dbName, m_name);
}

} // namespace kvdbManager
