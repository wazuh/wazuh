#include <kvdbstore/kvdbHandler.hpp>

namespace kvdbstore
{

KVDBHandler::KVDBHandler(std::shared_ptr<const KVMapStore> store) noexcept
    : m_store(std::move(store))
{
}

const json::Json& KVDBHandler::get(const std::string& key) const
{
    if (!m_store)
    {
        throw std::out_of_range("KVDBHandler has no backing store (null).");
    }

    const auto it = m_store->entries.find(key);
    if (it == m_store->entries.end())
    {
        throw std::out_of_range("Key not found in KVDB: '" + key + "'.");
    }

    return it->second;
}

bool KVDBHandler::contains(const std::string& key) const noexcept
{
    return m_store && (m_store->entries.find(key) != m_store->entries.end());
}

} // namespace kvdbstore
