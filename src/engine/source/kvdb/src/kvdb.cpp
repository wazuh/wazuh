#include <kvdb/kvdb.hpp>

#include <shared_mutex>
#include <unordered_map>

#include <fmt/format.h>
#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/slice.h>
#include <rocksdb/utilities/optimistic_transaction_db.h>
#include <rocksdb/utilities/transaction.h>

#include <logging/logging.hpp>

#include <iostream>

static const struct Option
{
    rocksdb::ReadOptions read;
    rocksdb::WriteOptions write;
    rocksdb::DBOptions open;
    rocksdb::ColumnFamilyOptions CF;
    rocksdb::OptimisticTransactionOptions TX;
} kOptions;

struct KVDB::Impl
{
    enum class State
    {
        Open,
        Closed,
        Locked,
        Error,
        Invalid,
    };

    Impl(const std::string& dbName, const std::string& folder)
        : m_name(dbName)
        , m_path(folder + dbName)
        , m_txDb(nullptr)
        , m_db(nullptr)
        , m_state(State::Invalid)
        , m_shouldCleanupFiles(false)
    {
        WAZUH_ASSERT_MSG(!m_name.empty(),
                         "Trying to create a DB with an empty name");
        WAZUH_ASSERT_MSG(!m_path.empty(),
                         "Trying to create a DB on an empty path");
    }

    bool init(bool createIfMissing)
    {
        if (m_state == State::Open)
        {
            // Already initialized
            return true;
        }

        std::unique_lock lk(m_mtx);
        std::vector<std::string> cfNames;
        auto s =
            rocksdb::DB::ListColumnFamilies(kOptions.open, m_path, &cfNames);
        if (s.ok())
        {
            for (auto name : cfNames)
            {
                m_CFDescriptors.push_back(
                    rocksdb::ColumnFamilyDescriptor(name, kOptions.CF));
            }
        }
        else
        {
            m_CFDescriptors.push_back(
                rocksdb::ColumnFamilyDescriptor(DEFAULT_CF_NAME, kOptions.CF));
        }

        rocksdb::Options dbOptions;
        dbOptions.OptimizeLevelStyleCompaction();
        dbOptions.OptimizeForSmallDb();
        dbOptions.create_if_missing = createIfMissing;

        rocksdb::OptimisticTransactionDB* txdb;
        std::vector<rocksdb::ColumnFamilyHandle*> cfHandles;
        s = rocksdb::OptimisticTransactionDB::Open(
            dbOptions, m_path, m_CFDescriptors, &cfHandles, &txdb);
        if (!s.ok())
        {
            WAZUH_LOG_ERROR("Couldn't create DB [{}] file, error: [{}]",
                            m_name,
                            s.ToString());

            m_state = State::Error;
            if (s.IsInvalidArgument())
            {
                // TODO: Investigate the reason of this:
                // RocksDB creates a DB even if the option create_if_missing is
                // false. The open operation fails, but the DB is created
                // anyway.
                rocksdb::DestroyDB(m_path, rocksdb::Options(), m_CFDescriptors);
            }
            return false;
        }

        for (auto handle : cfHandles)
        {
            m_CFHandlesMap[handle->GetName()] = handle;
        }

        m_txDb = txdb;
        m_db = txdb->GetBaseDB();
        m_state = State::Open;
        return true;
    }

    /**
     * @brief Check if the DB is able to be used.
     *
     * @return true if the DB can be used
     * @return false if the DB can´t be used
     */
    bool isReady() const
    {
        return (m_state == State::Open);
    }

    bool isValid() const
    {
        return (m_state != State::Invalid);
    }

    const std::string& getName() const
    {
        return m_name;
    }

    rocksdb::ColumnFamilyHandle* getCFHandle(std::string const& colName)
    {
        WAZUH_ASSERT_MSG(!colName.empty(), "Trying to get an empty column");

        if (m_state != State::Open)
        {
            WAZUH_LOG_ERROR("DB [{}] should be open for execution", m_name);
            return nullptr;
        }

        auto cfh = m_CFHandlesMap.find(colName);
        if (cfh == m_CFHandlesMap.end())
        {
            WAZUH_LOG_ERROR(
                "Failed to get CF [{}] in DB [{}]", colName, m_name);
            return nullptr;
        }

        return cfh->second;
    }

    bool createColumn(const std::string& columnName)
    {
        if (columnName.empty())
        {
            return false;
        }

        std::unique_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (cf)
        {
            // CF already present
            return false;
        }

        rocksdb::ColumnFamilyHandle* handler;
        rocksdb::Status s =
            m_db->CreateColumnFamily(kOptions.CF, columnName, &handler);
        if (s.ok())
        {
            m_CFDescriptors.push_back({columnName, {}});
            m_CFHandlesMap[handler->GetName()] = handler;
            return true;
        }

        WAZUH_LOG_ERROR("Couldn't create CF [{}] in DB [{}], error: ",
                        columnName,
                        m_name,
                        s.ToString());
        return false;
    }

    // TODO: all the default column names should be changed, one option is to
    // define a KVDB default CF in order to avoid using a deleteColumn or
    // cleanColumn without any argument
    bool deleteColumn(const std::string& columnName)
    {
        if (columnName.empty())
        {
            return false;
        }

        std::unique_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (!cf)
        {
            return false;
        }

        if (!m_db->DropColumnFamily(cf).ok())
        {
            return false;
        }

        rocksdb::Status s = m_db->DestroyColumnFamilyHandle(cf);
        if (s.ok())
        {
            m_CFHandlesMap.erase(columnName);
            m_CFDescriptors.erase(std::remove_if(
                m_CFDescriptors.begin(),
                m_CFDescriptors.end(),
                [&](auto const& des) { return des.name == columnName; }));

            return true;
        }

        return false;
    }

    bool cleanColumn(const std::string& columnName)
    {
        if (columnName.empty())
        {
            return false;
        }

        if (columnName == DEFAULT_CF_NAME)
        {
            rocksdb::Iterator* iter = m_db->NewIterator(kOptions.read);
            iter->SeekToFirst();
            while (iter->Valid())
            {
                deleteKey(iter->key().ToString(), columnName);
                iter->Next();
            };
            delete iter;
            return true;
        }
        else if (deleteColumn(columnName))
        {
            return createColumn(columnName);
        }
        return false;
    }

    bool write(const std::string& key,
               const std::string& value,
               const std::string& columnName)
    {
        if (key.empty() || columnName.empty())
        {
            return false;
        }

        std::shared_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (!cf)
        {
            return false;
        }

        rocksdb::Status s = m_db->Put(kOptions.write, cf, key, value);
        if (!s.ok())
        {
            WAZUH_LOG_ERROR(
                "Couldn't insert [{},{}] into DB [{}] CF [{}], error: [{}]",
                key,
                value,
                m_name,
                columnName,
                s.ToString());
            return false;
        }

        WAZUH_LOG_DEBUG("Successfull insert [{},{}] into DB [{}] CF [{}]",
                        key,
                        value,
                        m_name,
                        columnName);
        return true;
    }

    bool writeToTransaction(
        const std::vector<std::pair<std::string, std::string>>& pairsVector,
        const std::string& columnName)
    {
        if (columnName.empty())
        {
            return false;
        }

        std::shared_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (!cf)
        {
            return false;
        }

        if (!pairsVector.size())
        {
            WAZUH_LOG_INFO("Couldn't write transaction to DB [{}], need at "
                           "least 1 element",
                           m_name);
            return false;
        }

        rocksdb::Transaction* txn = m_txDb->BeginTransaction(kOptions.write);
        if (!txn)
        {
            WAZUH_LOG_ERROR("Couldn't begin in transaction in DB [{}]", m_name);
            return false;
        }

        // just delete the tx on scope exit
        _defer({ delete txn; });

        bool txnOk = true;
        for (auto const& [key, value] : pairsVector)
        {
            if (key.empty())
            {
                WAZUH_LOG_INFO("Discarding tuple [{},{}] in DB [{}] "
                               "because key is empty",
                               key,
                               value,
                               m_name);
                continue;
            }
            // Write a key-value in this transaction
            rocksdb::Status s = txn->Put(cf, key, value);
            if (!s.ok())
            {
                txnOk = false;
                WAZUH_LOG_ERROR("Couldn't execute Put in transaction for DB "
                                "[{}], error: [{}]",
                                m_name,
                                s.ToString());
            }
        }

        rocksdb::Status s = txn->Commit();
        if (!s.ok())
        {
            txnOk = false;
            WAZUH_LOG_ERROR(
                "Couldn't commit in transaction in DB [{}], error: [{}]",
                m_name,
                s.ToString());
        }

        return txnOk;
    }

    bool hasKey(const std::string& key, const std::string& columnName)
    {
        if (key.empty() || columnName.empty())
        {
            return false;
        }

        std::shared_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (!cf)
        {
            return false;
        }

        std::string value;
        // TODO We need to investigate this
        return m_db->KeyMayExist(kOptions.read, cf, key, &value);
    }

    std::string read(const std::string& key, const std::string& columnName)
    {
        if (key.empty() || columnName.empty())
        {
            return {};
        }

        std::shared_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (!cf)
        {
            return {};
        }

        std::string result, value;
        rocksdb::Status s = m_db->Get(kOptions.read, cf, key, &value);
        if (!s.ok())
        {
            WAZUH_LOG_ERROR(
                "Couldn't read value from DB [{}] CF [{}], error: [{}]",
                m_name,
                columnName,
                s.ToString());
            result.clear();
            return {};
        }

        WAZUH_LOG_DEBUG("Value obtained OK [{},{}] from DB [{}] CF [{}]",
                        key,
                        value,
                        m_name,
                        columnName);
        return value;
    }

    bool readPinned(const std::string& key,
                    std::string& value,
                    const std::string& columnName)
    {
        if (key.empty() || columnName.empty())
        {
            return false;
        }

        std::shared_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (!cf)
        {
            return false;
        }

        rocksdb::PinnableSlice pinnable_val;
        rocksdb::Status s = m_db->Get(kOptions.read, cf, key, &pinnable_val);
        if (!s.ok())
        {
            WAZUH_LOG_ERROR(
                "Couldn't read pinned value from DB [{}], error: [{}]",
                m_name,
                s.ToString());
            return false;
        }

        value = pinnable_val.ToString();
        WAZUH_LOG_DEBUG("Successfull read pinned value [{},{}] from DB [{}]",
                        key,
                        value,
                        m_name);
        return true;
    }

    bool deleteKey(const std::string& key, const std::string& columnName)
    {
        if (key.empty() || columnName.empty())
        {
            return false;
        }

        std::shared_lock lk(m_mtx);
        auto cf = getCFHandle(columnName);
        if (!cf)
        {
            return false;
        }

        rocksdb::Status s = m_db->Delete(kOptions.write, cf, key);
        if (!s.ok())
        {
            WAZUH_LOG_ERROR(
                "Couldn't delete key [{}] from DB [{}] CF [{}], error: [{}]",
                key,
                m_name,
                columnName,
                s.ToString());
            return false;
        }

        WAZUH_LOG_INFO("Key [{}] deleted OK from DB [{}]", key, m_name);
        return true;
    }

    bool close()
    {
        std::unique_lock lk(m_mtx);
        if (!m_txDb)
        {
            return true;
        }

        bool ret = true;
        rocksdb::Status s;
        for (auto const& it : m_CFHandlesMap)
        {
            s = m_db->DestroyColumnFamilyHandle(it.second);
            if (!s.ok())
            {
                WAZUH_LOG_ERROR("Couldn't destroy family handler from DB "
                                "[{}], error: [{}]",
                                m_name,
                                s.ToString());
                ret = false;
            }
        }

        m_CFHandlesMap.clear();

        s = m_db->Close();
        if (!s.ok())
        {
            WAZUH_LOG_ERROR(
                "Couldn't close DB [{}], error: [{}]", m_name, s.ToString());
            ret = false;
        }

        s = m_txDb->Close();
        if (!s.ok())
        {
            WAZUH_LOG_ERROR(
                "Couldn't close DB [{}], error: [{}]", m_name, s.ToString());
            ret = false;
        }

        delete m_txDb;
        m_txDb = nullptr;

        return ret;
    }

    /**
     * @brief Db destruction cleaning all files and data related to it
     *
     * @return true successfully destructed
     * @return false unsuccessfully destructed
     */
    bool deleteFile()
    {
        rocksdb::Status s =
            rocksdb::DestroyDB(m_path, rocksdb::Options(), m_CFDescriptors);
        if (!s.ok())
        {
            WAZUH_LOG_ERROR(
                "Couldn't destroy DB [{}], error: [{}]", m_name, s.ToString());
            m_state = State::Error;
            return false;
        }

        return true;
    }

    std::string m_name;
    std::string m_path;
    bool m_shouldCleanupFiles;
    State m_state = State::Invalid;

    rocksdb::OptimisticTransactionDB* m_txDb;
    rocksdb::DB* m_db;
    std::vector<rocksdb::ColumnFamilyDescriptor> m_CFDescriptors;
    std::unordered_map<std::string, rocksdb::ColumnFamilyHandle*>
        m_CFHandlesMap;

    std::shared_mutex m_mtx;
};

KVDB::KVDB(const std::string& dbName, const std::string& folder)
    : mImpl(std::make_unique<KVDB::Impl>(dbName, folder))
{
}

KVDB::KVDB()
    : mImpl(std::make_unique<KVDB::Impl>("", ""))
{
}

bool KVDB::init(bool errorIfExists)
{
    return mImpl->init(errorIfExists);
}

KVDB::~KVDB()
{
    mImpl->close();
    if (mImpl->m_shouldCleanupFiles)
    {
        mImpl->deleteFile();
    }
}

bool KVDB::close()
{
    return mImpl->close();
}

void KVDB::cleanupOnClose()
{
    mImpl->m_shouldCleanupFiles = true;
}

bool KVDB::writeKeyOnly(const std::string& key, const std::string& columnName)
{
    return mImpl->write(key, "", columnName);
}

bool KVDB::write(const std::string& key,
                 const std::string& value,
                 const std::string& columnName)
{
    return mImpl->write(key, value, columnName);
}

std::string KVDB::read(const std::string& key, const std::string& columnName)
{
    return mImpl->read(key, columnName);
}

bool KVDB::deleteKey(const std::string& key, const std::string& columnName)
{
    return mImpl->deleteKey(key, columnName);
}

bool KVDB::createColumn(const std::string& columnName)
{
    return mImpl->createColumn(columnName);
}

bool KVDB::deleteColumn(const std::string& columnName)
{
    return mImpl->deleteColumn(columnName);
}

bool KVDB::cleanColumn(const std::string& columnName)
{
    return mImpl->cleanColumn(columnName);
}

bool KVDB::writeToTransaction(
    const std::vector<std::pair<std::string, std::string>>& pairsVector,
    const std::string& columnName)
{
    return mImpl->writeToTransaction(pairsVector, columnName);
}

bool KVDB::hasKey(const std::string& key, const std::string& columnName)
{
    return mImpl->hasKey(key, columnName);
}

bool KVDB::readPinned(const std::string& key,
                      std::string& value,
                      const std::string& colName)
{
    return mImpl->readPinned(key, value, colName);
}

bool KVDB::isValid() const
{
    return mImpl->isValid();
}

bool KVDB::isReady() const
{
    return mImpl->isReady();
}

std::string_view KVDB::getName() const
{
    return mImpl->getName();
}
