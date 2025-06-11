#include <kvdb/kvdbHandler.hpp>

#include <base/json.hpp>
#include <base/logging.hpp>
#include <fmt/format.h>
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
                std::string_view error = status.getState() != nullptr ? status.getState() : "Unknown";
                return base::Error {fmt::format("Can not save value '{}' in key '{}'. Error: {}", value, key, error)};
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
                std::string_view error = status.getState() != nullptr ? status.getState() : "Unknown";
                return base::Error {fmt::format("Can not remove key '{}'. Error: {}", key, error)};
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
                bool valueFound = false;

                pRocksDB->KeyMayExist(
                    rocksdb::ReadOptions(), pCFhandle.get(), rocksdb::Slice(key), &value, &valueFound);

                // confirm exists
                if (valueFound)
                {
                    auto status = pRocksDB->Get(rocksdb::ReadOptions(), pCFhandle.get(), rocksdb::Slice(key), &value);

                    if (!status.ok())
                    {
                        valueFound = false;
                    }
                }

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
                bool isNotFound = status.IsNotFound() && value.empty();
                std::string_view error = isNotFound                     ? "Key not found"
                                         : status.getState() != nullptr ? status.getState()
                                                                        : "Unknown";
                return base::Error {fmt::format("Can not get key '{}'. Error: {}", key, error)};
            }
        }
        else
        {
            return base::Error {"Can not access RocksDB Column Family Handle"};
        }
    }

    return base::Error {"Can not access RocksDB::DB"};
}

std::variant<std::list<std::pair<std::string, std::string>>, base::Error> KVDBHandler::dump(const unsigned int page,
                                                                                            const unsigned int records)
{
    return pageContent(page, records);
}

std::variant<std::list<std::pair<std::string, std::string>>, base::Error>
KVDBHandler::search(const std::string& prefix, const unsigned int page, const unsigned int records)
{
    auto filter = [&prefix](const rocksdb::Slice& keyIter) -> bool
    {
        rocksdb::Slice slicePrefix(prefix);

        if (slicePrefix.empty())
            return true;
        else
            return keyIter.starts_with(slicePrefix);
    };

    return pageContent(page, records, filter);
}

std::variant<std::list<std::pair<std::string, std::string>>, base::Error>
KVDBHandler::pageContent(const unsigned int page, const unsigned int records)
{
    return pageContent(page, records, {});
}

std::variant<std::list<std::pair<std::string, std::string>>, base::Error> KVDBHandler::pageContent(
    const unsigned int page, const unsigned int records, const std::function<bool(const rocksdb::Slice&)>& filter)
{
    auto pRocksDB = m_weakDB.lock();
    if (pRocksDB)
    {
        auto pCFhandle = m_weakCFHandle.lock();
        if (pCFhandle)
        {
            std::unique_ptr<rocksdb::Iterator> iter(pRocksDB->NewIterator(rocksdb::ReadOptions(), pCFhandle.get()));
            std::list<std::pair<std::string, std::string>> content;

            unsigned int fromRecords = (page - 1) * records;
            unsigned int toRecords = fromRecords + records;

            unsigned int i = 0;
            for (iter->SeekToFirst(); iter->Valid() && i < toRecords; iter->Next())
            {
                if (!filter || filter(iter->key()))
                {
                    if (i >= fromRecords)
                    {
                        content.emplace_back(std::make_pair(iter->key().ToString(), iter->value().ToString()));
                    }
                    i++;
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
