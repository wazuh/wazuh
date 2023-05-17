#include <kvdb2/kvdbScope.hpp>
#include <fmt/format.h>
#include <logging/logging.hpp>

namespace kvdbManager
{

KVDBScope::KVDBScope(IKVDBHandlerManager* handlerManager, const std::string& name)
    : m_handlerManager(handlerManager)
{
    LOG_INFO("KVDBScope::KVDBScope - name {}", name.c_str());
    std::cout << fmt::format("KVDBScope::KVDBScope - name {}", name.c_str()) << std::endl;

    setName(name);
}

KVDBScope::~KVDBScope()
{
    std::cout << fmt::format("KVDBScope::~KVDBScope - name {}", getName().c_str()) << std::endl;
}

bool KVDBScope::initialize()
{
    std::cout << fmt::format("KVDBScope::Initialize - name {}", getName().c_str()) << std::endl;
    m_initialized = true;
    return m_initialized;
}

std::shared_ptr<IKVDBHandler> KVDBScope::getKVDBHandler(const std::string& dbName)
{
    std::cout << fmt::format("KVDBScope::getKVDBHandler - name {}", getName().c_str()) << std::endl;
    return std::move(m_handlerManager->getKVDBHandler(dbName, getName()));
}

} // namespace kvdbManager
