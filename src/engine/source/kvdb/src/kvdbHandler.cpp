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
                    fmt::format("Can not save value '{}' in key '{}'. Error: {}", value, key, status.getState())};
            }
        }
        else
        {
            return base::Error {"Can not access RocksDB Column Family Handle"};
        }
    }

    return base::Error {"Can not access RocksDB::DB"};
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
                return base::Error {fmt::format("Can not remove key '{}'. Error: {}", key, status.getState())};
            }
        }
        else
        {
            return base::Error {"Can not access RocksDB Column Family Handle"};
        }
    }

    return base::Error {"Can not access RocksDB::DB"};
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
                return base::Error {fmt::format("Can not validate existance of key {}. Error: {}", key, ex.what())};
            }
        }
        else
        {
            return base::Error {"Can not access RocksDB Column Family Handle"};
        }
    }

    return base::Error {"Can not access RocksDB::DB"};
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
                return base::Error {fmt::format("Can not get key '{}'. Error: {}", value, key, status.getState())};
            }
        }
        else
        {
            return base::Error {"Can not access RocksDB Column Family Handle"};
        }
    }

    return base::Error {"Can not access RocksDB::DB"};
}

std::variant<std::map<std::string, std::string>, base::Error> KVDBHandler::dump(const unsigned int page,
                                                                                const unsigned int records)
{
    return pageContent("", page, records);
}

std::variant<std::map<std::string, std::string>, base::Error>
KVDBHandler::search(const std::string& prefix, const unsigned int page, const unsigned int records)
{
    return pageContent(prefix, page, records);
}

std::variant<std::map<std::string, std::string>, base::Error>
KVDBHandler::pageContent(const std::string& prefix, const unsigned int page, const unsigned int records)
{
    auto pRocksDB = m_weakDB.lock();
    if (pRocksDB)
    {
        auto pCFhandle = m_weakCFHandle.lock();
        if (pCFhandle)
        {
            std::unique_ptr<rocksdb::Iterator> iter(pRocksDB->NewIterator(rocksdb::ReadOptions(), pCFhandle.get()));
            rocksdb::Slice sliceFilter(prefix);
            std::map<std::string, std::string> content;
            uint32_t actualPage = 1, counterRecords = 1;

            if (page == 0 && records == 0)
            {
                if (!sliceFilter.empty())
                {
                    for (iter->SeekToFirst(); iter->Valid() && iter->key().starts_with(sliceFilter); iter->Next())
                    {
                        content[iter->key().ToString()] = iter->value().ToString();
                    }
                }
                else
                {
                    for (iter->SeekToFirst(); iter->Valid(); iter->Next())
                    {
                        content[iter->key().ToString()] = iter->value().ToString();
                    }
                }
            }
            else
            {
                for (iter->SeekToFirst(); iter->Valid() && actualPage <= page; iter->Next())
                {
                    if (!sliceFilter.empty())
                    {
                        if (!iter->key().starts_with(sliceFilter))
                        {
                            continue;
                        }
                    }

                    if (actualPage == page)
                    {
                        content[iter->key().ToString()] = iter->value().ToString();
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

        return base::Error {"Can not access RocksDB Column Family Handle"};
    }

    return base::Error {"Can not access RocksDB::DB"};
}

} // namespace kvdbManager
