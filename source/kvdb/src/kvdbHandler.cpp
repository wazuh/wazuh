#include <kvdb/kvdbHandler.hpp>

#include <kvdb/iKVDBHandlerCollection.hpp>

#include <fmt/format.h>
#include <json/json.hpp>
#include <logging/logging.hpp>
#include <rocksdb/db.h>

namespace kvdbManager
{

KVDBHandler::KVDBHandler(rocksdb::DB* db,
                         rocksdb::ColumnFamilyHandle* cfHandle,
                         std::shared_ptr<IKVDBHandlerCollection> collection,
                         const std::string& spaceName,
                         const std::string& scopeName)
    : m_pRocksDB(db)
    , m_pCFhandle(cfHandle)
    , m_dbName(spaceName)
    , m_scopeName(scopeName)
    , m_spCollection(collection)
{
}

KVDBHandler::~KVDBHandler()
{
    m_spCollection->removeKVDBHandler(m_dbName, m_scopeName);
}

std::optional<base::Error> KVDBHandler::set(const std::string& key, const std::string& value)
{
    auto status = m_pRocksDB->Put(rocksdb::WriteOptions(), m_pCFhandle, rocksdb::Slice(key), rocksdb::Slice(value));

    if (status.ok())
    {
        return std::nullopt;
    }

    return base::Error {fmt::format("Cannot save value '{}' in key '{}'. Error: {}", value, key, status.getState())};
}

std::optional<base::Error> KVDBHandler::set(const std::string& key, const json::Json& value)
{
    return set(key, value.str());
}

std::optional<base::Error> KVDBHandler::add(const std::string& key)
{
    return set(key, "");
}

std::optional<base::Error> KVDBHandler::remove(const std::string& key)
{
    auto status = m_pRocksDB->Delete(rocksdb::WriteOptions(), m_pCFhandle, rocksdb::Slice(key));

    if (status.ok())
    {
        return std::nullopt;
    }

    return base::Error {fmt::format("Cannot remove key '{}'. Error: {}", key, status.getState())};
}

std::variant<bool, base::Error> KVDBHandler::contains(const std::string& key)
{
    try
    {
        std::string value;
        return m_pRocksDB->KeyMayExist(rocksdb::ReadOptions(), m_pCFhandle, rocksdb::Slice(key), &value);
    }
    catch(const std::exception& ex)
    {
        return base::Error {fmt::format("{Can not validate key {}. Error: {}}", key, ex.what())};
    }
}

std::variant<std::string, base::Error> KVDBHandler::get(const std::string& key)
{
    std::string value;
    auto status = m_pRocksDB->Get(rocksdb::ReadOptions(), m_pCFhandle, rocksdb::Slice(key), &value);

    if (status.ok())
    {
        return value;
    }

    return base::Error {fmt::format("Cannot get key '{}'. Error: {}", value, key, status.getState())};
}

std::variant<std::unordered_map<std::string, std::string>, base::Error> KVDBHandler::dump()
{
    std::unordered_map<std::string, std::string> content {};
    std::shared_ptr<rocksdb::Iterator> iter(m_pRocksDB->NewIterator(rocksdb::ReadOptions(), m_pCFhandle));

    for (iter->SeekToFirst(); iter->Valid(); iter->Next())
    {
        content[iter->key().ToString()] = iter->value().ToString();
    }

    if (!iter->status().ok())
    {
        return base::Error {
            fmt::format("Database '{}': Could not iterate over database: '{}'", m_dbName, iter->status().ToString())};
    }

    return content;
}

} // namespace kvdbManager
