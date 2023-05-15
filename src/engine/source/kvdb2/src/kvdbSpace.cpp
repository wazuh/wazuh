#include <kvdb2/kvdbSpace.hpp>

#include <fmt/format.h>

namespace kvdbManager
{

KVDBSpace::~KVDBSpace()
{
    m_handlerManager->removeKVDBHandler(m_spaceName, m_scopeName);
}

std::variant<bool, base::Error> KVDBSpace::set(const std::string& key, const std::string& value)
{
    auto status = m_pRocksDB->Put(rocksdb::WriteOptions(), m_pCFhandle, rocksdb::Slice(key), rocksdb::Slice(value));

    if (status.ok())
    {
        return true;
    }

    return base::Error { fmt::format("Cannot save value '{}' in key '{}'. Error: {}", value, key, status.getState()) };
}

std::variant<bool, base::Error> KVDBSpace::add(const std::string& key)
{
    return set(key, "");
}

std::variant<bool, base::Error> KVDBSpace::remove(const std::string& key)
{
    auto status = m_pRocksDB->Delete(rocksdb::WriteOptions(), m_pCFhandle, rocksdb::Slice(key));

    if (status.ok())
    {
        return true;
    }

    return base::Error { fmt::format("Cannot remove key '{}'. Error: {}", key, status.getState()) };
}

std::variant<bool, base::Error> KVDBSpace::contains(const std::string& key)
{
    return std::holds_alternative<std::string>(get(key));
}

std::variant<std::string, base::Error> KVDBSpace::get(const std::string& key)
{
    std::string value;
    auto status = m_pRocksDB->Get(rocksdb::ReadOptions(), m_pCFhandle, rocksdb::Slice(key), &value);

    if (status.ok())
    {
        return value;
    }

    return base::Error { fmt::format("Cannot get key '{}'. Error: {}", value, key, status.getState()) };
}

std::variant<std::unordered_map<std::string, std::string>, base::Error> KVDBSpace::dump()
{
    std::unordered_map<std::string, std::string> content {};
    std::shared_ptr<rocksdb::Iterator> iter(m_pRocksDB->NewIterator(rocksdb::ReadOptions(), m_pCFhandle));

    for (iter->SeekToFirst(); iter->Valid(); iter->Next())
    {
        content[iter->key().ToString()] = iter->value().ToString();
    }

    if (!iter->status().ok())
    {
        return base::Error { fmt::format("Database '{}': Couldn't iterate over database: '{}'", m_spaceName, iter->status().ToString()) };
    }

    iter->Reset();

    return content;
}

} // namespace kvdbManager