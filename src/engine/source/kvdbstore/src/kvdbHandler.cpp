#include <kvdbstore/kvdbHandler.hpp>

namespace kvdbstore
{

KVDBHandler::KVDBHandler(std::shared_ptr<const KVMap> map) noexcept
    : m_map(std::move(map))
{
}

const json::Json& KVDBHandler::get(const std::string& key) const
{
    if (!m_map)
    {
        throw std::out_of_range("KVDBHandler has no backing map (null).");
    }

    const auto it = m_map->find(key);
    if (it == m_map->end())
    {
        throw std::out_of_range("Key not found in KVDB: '" + key + "'.");
    }

    return it->second;
}

bool KVDBHandler::contains(const std::string& key) const noexcept
{
    return m_map && (m_map->find(key) != m_map->end());
}

} // namespace kvdbstore
