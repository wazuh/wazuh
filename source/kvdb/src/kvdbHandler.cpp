#include <kvdb/kvdbHandler.hpp>

#include <kvdb/iKVDBHandlerCollection.hpp>

#include <fmt/format.h>
#include <json/json.hpp>
#include <logging/logging.hpp>
#include <rocksdb/db.h>

namespace kvdbManager
{

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

std::variant<std::list<std::pair<std::string, std::string>>, base::Error> KVDBHandler::dump(const uint32_t page,
                                                                                            const uint32_t records)
{
    auto pRocksDB = m_weakDB.lock();
    if (pRocksDB)
    {
        auto pCFhandle = m_weakCFHandle.lock();
        if (pCFhandle)
        {
            std::list<std::pair<std::string, std::string>> content;
            std::shared_ptr<rocksdb::Iterator> iter(pRocksDB->NewIterator(rocksdb::ReadOptions(), pCFhandle.get()));
            uint32_t actualPage = 1, counterRecords = 1;

            // std::string aproxSizeProp {};
            // pRocksDB->GetProperty("rocksdb.estimate-num-keys", &aproxSizeProp);
            // std::cout<<"Total size: "<<aproxSizeProp<<std::endl;

            if (page == 0 && records == 0)
            {
                for (iter->SeekToFirst(); iter->Valid(); iter->Next())
                {
                    content.push_back(std::make_pair(iter->key().ToString(), iter->value().ToString()));
                }
            }
            else
            {
                for (iter->SeekToFirst(); iter->Valid() && actualPage <= page; iter->Next())
                {
                    if (actualPage == page)
                    {
                        std::cout << "Iter: " << iter->key().ToString() << " : " << iter->value().ToString()
                                  << std::endl;
                        content.push_back(std::make_pair(iter->key().ToString(), iter->value().ToString()));
                    }

                    if (counterRecords == records)
                    {
                        counterRecords = 1;
                        actualPage++;
                    }
                    else
                    {
                        counterRecords++;
                    }
                }
            }

            if (!iter->status().ok())
            {
                return base::Error {fmt::format(
                    "Database '{}': Could not iterate over database: '{}'", m_dbName, iter->status().ToString())};
            }

            return content;
        }

        return base::Error {"Cannot access RocksDB Column Family Handle"};
    }

    return base::Error {"Cannot access RocksDB::DB"};
}

std::variant<std::unordered_map<std::string, std::string>, base::Error> KVDBHandler::search(const std::string& prefix)
{
    auto pRocksDB = m_weakDB.lock();
    if (pRocksDB)
    {
        auto pCFhandle = m_weakCFHandle.lock();
        if (pCFhandle)
        {
            std::unordered_map<std::string, std::string> content {};
            std::shared_ptr<rocksdb::Iterator> iter(pRocksDB->NewIterator(rocksdb::ReadOptions(), pCFhandle.get()));
            rocksdb::Slice sliceFilter(prefix);

            // if Iterator::Valid() is true, status() is guaranteed to be OK() so it's
            // safe to proceed other operations without checking status():
            for (iter->Seek(sliceFilter); iter->Valid() && iter->key().starts_with(sliceFilter); iter->Next())
            {
                content[iter->key().ToString()] = iter->value().ToString();
            }

            // errors include I/O errors, checksum mismatch, unsupported operations, internal errors, or other errors.
            if (!iter->status().ok())
            {
                return base::Error {fmt::format(
                    "Database '{}': Could not iterate over database: '{}'", m_dbName, iter->status().ToString())};
            }

            return content;
        }

        return base::Error {"Cannot access RocksDB Column Family Handle"};
    }

    return base::Error {"Cannot access RocksDB::DB"};
}

} // namespace kvdbManager
