#include <kvdb/kvdbHandler.hpp>

#include <kvdb/iKVDBHandlerCollection.hpp>

#include <fmt/format.h>
#include <json/json.hpp>
#include <logging/logging.hpp>
#include <rocksdb/db.h>

namespace kvdbManager
{

KVDBHandler::KVDBHandler(std::weak_ptr<rocksdb::DB> weakDB,
                         std::weak_ptr<rocksdb::ColumnFamilyHandle> weakCFHandle,
                         std::shared_ptr<IKVDBHandlerCollection> collection,
                         const std::string& spaceName,
                         const std::string& scopeName)
    : m_weakDB(weakDB)
    , m_weakCFHandle(weakCFHandle)
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
    auto pRocksDB = m_weakDB.lock();
    if (pRocksDB)
    {
        auto pCFhandle = m_weakCFHandle.lock();
        if (pCFhandle)
        {
            auto status =
                pRocksDB->Put(rocksdb::WriteOptions(), pCFhandle.get(), rocksdb::Slice(key), rocksdb::Slice(value));

            if (status.ok())
            {
                return std::nullopt;
            }
            else
            {
                return base::Error {
                    fmt::format("Cannot save value '{}' in key '{}'. Error: {}", value, key, status.getState())};
            }
        }
        else
        {
            return base::Error {"Cannot access RocksDB Column Family Handle"};
        }
    }

    return base::Error {"Cannot access RocksDB::DB"};
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
    auto pRocksDB = m_weakDB.lock();
    if (pRocksDB)
    {
        auto pCFhandle = m_weakCFHandle.lock();
        if (pCFhandle)
        {
            auto status = pRocksDB->Delete(rocksdb::WriteOptions(), pCFhandle.get(), rocksdb::Slice(key));

            if (status.ok())
            {
                return std::nullopt;
            }
            else
            {
                return base::Error {fmt::format("Cannot remove key '{}'. Error: {}", key, status.getState())};
            }
        }
        else
        {
            return base::Error {"Cannot access RocksDB Column Family Handle"};
        }
    }

    return base::Error {"Cannot access RocksDB::DB"};
}

std::variant<bool, base::Error> KVDBHandler::contains(const std::string& key)
{
    auto pRocksDB = m_weakDB.lock();
    if (pRocksDB)
    {
        auto pCFhandle = m_weakCFHandle.lock();
        if (pCFhandle)
        {
            try
            {
                std::string value; // mandatory to pass to KeyMayExist.
                bool valueFound;

                pRocksDB->KeyMayExist(
                    rocksdb::ReadOptions(), pCFhandle.get(), rocksdb::Slice(key), &value, &valueFound);

                return valueFound;
            }
            catch (const std::exception& ex)
            {
                return base::Error {fmt::format("Cannot validate existance of key {}. Error: {}", key, ex.what())};
            }
        }
        else
        {
            return base::Error {"Cannot access RocksDB Column Family Handle"};
        }
    }

    return base::Error {"Cannot access RocksDB::DB"};
}

std::variant<std::string, base::Error> KVDBHandler::get(const std::string& key)
{
    auto pRocksDB = m_weakDB.lock();
    if (pRocksDB)
    {
        auto pCFhandle = m_weakCFHandle.lock();
        if (pCFhandle)
        {
            std::string value;
            auto status = pRocksDB->Get(rocksdb::ReadOptions(), pCFhandle.get(), rocksdb::Slice(key), &value);

            if (status.ok())
            {
                return value;
            }
            else
            {
                return base::Error {fmt::format("Cannot get key '{}'. Error: {}", value, key, status.getState())};
            }
        }
        else
        {
            return base::Error {"Cannot access RocksDB Column Family Handle"};
        }
    }

    return base::Error {"Cannot access RocksDB::DB"};
}

std::variant<std::unordered_map<std::string, std::string>, base::Error> KVDBHandler::dump()
{
    auto pRocksDB = m_weakDB.lock();
    if (pRocksDB)
    {
        auto pCFhandle = m_weakCFHandle.lock();
        if (pCFhandle)
        {
            std::unordered_map<std::string, std::string> content {};
            std::shared_ptr<rocksdb::Iterator> iter(pRocksDB->NewIterator(rocksdb::ReadOptions(), pCFhandle.get()));

            for (iter->SeekToFirst(); iter->Valid(); iter->Next())
            {
                content[iter->key().ToString()] = iter->value().ToString();

                if (!iter->status().ok())
                {
                    return base::Error {fmt::format(
                        "Database '{}': Could not iterate over database: '{}'", m_dbName, iter->status().ToString())};
                }
            }

            return content;
        }
        else
        {
            return base::Error {"Cannot access RocksDB Column Family Handle"};
        }
    }

    return base::Error {"Cannot access RocksDB::DB"};
}

} // namespace kvdbManager
