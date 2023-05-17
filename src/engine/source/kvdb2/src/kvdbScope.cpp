#include <kvdb2/kvdbScope.hpp>
#include <fmt/format.h>
#include <logging/logging.hpp>

namespace kvdbManager
{

KVDBScope::KVDBScope(IKVDBHandlerManager* handlerManager, const std::string& name)
    : m_handlerManager(handlerManager)
{
    setName(name);
}

KVDBScope::~KVDBScope()
{
}

bool KVDBScope::initialize()
{
    m_initialized = true;
    return m_initialized;
}

KVDBHandler KVDBScope::getKVDBHandler(const std::string& dbName)
{
    return m_handlerManager->getKVDBHandler(dbName, getName());
}

} // namespace kvdbManager
