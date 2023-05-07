#include <kvdb2/kvdbSpace.hpp>

namespace kvdbManager
{

KVDBSpace::~KVDBSpace() {
    m_handlerManager->removeKVDBHandler(m_spaceName, m_scopeName);
}

std::variant<bool, base::Error> KVDBSpace::set(const std::string& key, const std::string& value) {
    // Stub implementation of the set method
    return true;
}

bool KVDBSpace::add(const std::string& key) {
    // Stub implementation of the add method
    return true;
}

bool KVDBSpace::remove(const std::string& key) {
    // Stub implementation of the remove method
    return true;
}

std::variant<bool, base::Error> KVDBSpace::contains(const std::string& key) {
    // Stub implementation of the contains method
    return true;
}

std::variant<std::string, base::Error> KVDBSpace::get(const std::string& key) {
    // Stub implementation of the get method
    return std::string("value");
}


} // namespace kvdbManager
