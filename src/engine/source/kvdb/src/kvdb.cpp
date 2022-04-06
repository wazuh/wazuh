#include <kvdb/kvdb.hpp>

#include <iostream>
#include <unordered_map>

#include "rocksdb/db.h"
#include "rocksdb/options.h"
#include "rocksdb/slice.h"
#include "rocksdb/utilities/transaction.h"
#include <fmt/format.h>

#include <logging/logging.hpp>

static const struct Option
{
    rocksdb::ReadOptions read = rocksdb::ReadOptions();
    rocksdb::WriteOptions write = rocksdb::WriteOptions();
    rocksdb::DBOptions open = rocksdb::DBOptions();
    rocksdb::ColumnFamilyOptions CF = rocksdb::ColumnFamilyOptions();
    rocksdb::TransactionDBOptions TX = rocksdb::TransactionDBOptions();
} kOptions;

/**
 * @brief Construct a new KVDB::KVDB object
 *
 * @param dbName name of the DB
 * @param folder where the DB will be stored
 */
KVDB::KVDB(const std::string &dbName, const std::string &folder)
    : m_name(dbName)
    , m_path(folder + dbName)
    , m_db(nullptr)
    , m_txndb(nullptr)
    , m_state(State::Invalid)
{
    rocksdb::Status s;
    std::vector<std::string> CFNames;
    std::vector<rocksdb::ColumnFamilyHandle *> CFHandles;
    s = rocksdb::DB::ListColumnFamilies(kOptions.open, m_path, &CFNames);
    if (s.ok())
    {
        for (auto CFName : CFNames)
        {
            CFDescriptors.push_back(
                rocksdb::ColumnFamilyDescriptor(CFName, kOptions.CF));
        }
    }
    else
    {
        CFDescriptors.push_back(
            rocksdb::ColumnFamilyDescriptor(DEFAULT_CF_NAME, kOptions.CF));
    }

    s = rocksdb::TransactionDB::Open(kOptions.open,
                                     kOptions.TX,
                                     m_path,
                                     CFDescriptors,
                                     &CFHandles,
                                     &m_txndb);
    if (s.ok())
    {
        m_db = m_txndb->GetBaseDB();
        for (auto CFHandle : CFHandles)
        {
            m_CFHandlesMap[CFHandle->GetName()] = CFHandle;
        }
        m_state = State::Open;
    }
    else
    {
        WAZUH_LOG_ERROR("Couldn't open DB [{}], error: [{}]",
                        m_name,
                        s.ToString());
        m_state = State::Error;
        // TODO: Investigate the reason of this:
        // RocksDB creates a DB even if the option create_if_missing is false.
        // The open operation fails, but the DB is created anyway.
        // A possibility is to first open the DB and after that open the transaction.
        if (s.IsInvalidArgument()) {
            rocksdb::DestroyDB(m_path, rocksdb::Options(), CFDescriptors);
        }
    }
}

/**
 * @brief Destroy the KVDB object
 *
 */
KVDB::~KVDB()
{
    close();
}

/**
 * @brief DB closing cleaning all elements used to acces it
 *
 * @return true succesfully closed
 * @return false unsuccesfully closed
 */
bool KVDB::close()
{
    std::unique_lock lk(m_mtx);
    bool ret = true;
    if (m_txndb)
    {
        rocksdb::Status s;
        for (auto item : m_CFHandlesMap)
        {
            s = m_db->DestroyColumnFamilyHandle(item.second);
            if (!s.ok())
            {
                WAZUH_LOG_WARN("Couldn't destroy family handler from DB [{}], error: [{}]",
                               m_name,
                               s.ToString());
                ret = false;
            }
        }
        m_CFHandlesMap.clear();

        s = m_db->Close();
        if (!s.ok())
        {
            WAZUH_LOG_ERROR("Couldn't close DB [{}], error: [{}]",
                            m_name,
                            s.ToString());
            ret = false;
        }

        delete m_txndb;
    }
    m_txndb = nullptr;
    m_db = nullptr;

    if (m_deleteOnClose && !deleteFile())
    {
        ret = false;
    }

    return ret;
}

/**
 * @brief Db destruction cleaning all files and data related to it
 *
 * @return true successfully destructed
 * @return false unsuccessfully destructed
 */
bool KVDB::deleteFile()
{
    rocksdb::Status s =
        rocksdb::DestroyDB(m_path, rocksdb::Options(), CFDescriptors);
    if (!s.ok())
    {
        WAZUH_LOG_ERROR("Couldn't destroy DB [{}], error: [{}]",
                        m_name,
                        s.ToString());
        m_state = State::Error;
        return false;
    }
    return true;
}

/**
 * @brief write a key into the DB
 *
 * @param key the key that will be written
 * @param columnName column where to write the key-value
 * @return true If the proccess finished successfully
 * @return false If the proccess didn't finished successfully
 */
bool KVDB::writeKeyOnly(const std::string &key, const std::string &columnName)
{
    return write(key, "", columnName);
}

/**
 * @brief write a key-value into the DB
 *
 * @param key the key that will be written
 * @param value the value that will be written
 * @param columnName column where to write the key-value
 * @return true If the proccess finished successfully
 * @return false If the proccess didn't finished successfully
 */
bool KVDB::write(const std::string &key,
                 const std::string &value,
                 const std::string &columnName)
{
    if (m_state != State::Open)
    {
        WAZUH_LOG_ERROR("DB [{}] should be open for execution", m_name);
        return false;
    }

    std::shared_lock lk(m_mtx);
    auto cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("Couldn't write to DB [{}] unknown column name [{}]",
                        m_name,
                        columnName);
        return false;
    }

    rocksdb::Status s = m_db->Put(kOptions.write,
                                  cfh->second,
                                  rocksdb::Slice(key),
                                  rocksdb::Slice(value));
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

/**
 * @brief read a value from a key inside a CF without value copying
 *
 * @param key where to find the value
 * @param value that the result of the proccess will modify
 * @param columnName where to search the key
 * @return value read If the proccess finished successfully
 * @return empty string If the proccess didn't finished successfully
 */
std::string KVDB::read(const std::string &key, const std::string &columnName)
{
    if (m_state != State::Open)
    {
        WAZUH_LOG_ERROR("DB [{}] should be open for reading", m_name);
        return {};
    }

    std::shared_lock lk(m_mtx);
    auto cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("Couldn't read DB [{}] unknown column name [{}]",
                        m_name,
                        columnName);
        return {};
    }

    std::string result, value;
    rocksdb::Status s =
        m_db->Get(kOptions.read, cfh->second, rocksdb::Slice(key), &value);
    if (s.ok())
    {
        WAZUH_LOG_DEBUG("Value obtained OK [{},{}] from DB [{}] CF [{}]",
                        key,
                        value,
                        m_name,
                        columnName);
        result = value;
    }
    else
    {
        WAZUH_LOG_ERROR("Couldn't read value from DB [{}] CF [{}], error: [{}]",
                        m_name,
                        columnName,
                        s.ToString());
        result.clear();
    }
    return result;
}

/**
 * @brief delete a key of a CF
 *
 * @param key that will be deleted
 * @param columnName where to search for the key
 * @return true if the key was successfully deleted
 * @return false if the key wasn't successfully deleted
 */
bool KVDB::deleteKey(const std::string &key, const std::string &columnName)
{
    if (m_state != State::Open)
    {
        WAZUH_LOG_ERROR("DB [{}] should be open for execution", m_name);
        return false;
    }

    std::shared_lock lk(m_mtx);
    auto cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR(
            "Couldn't delete key in DB [{}] unknown column name [{}]",
            m_name,
            columnName);
        return false;
    }

    rocksdb::Status s =
        m_db->Delete(kOptions.write, cfh->second, rocksdb::Slice(key));
    if (s.ok())
    {
        WAZUH_LOG_INFO("Key [{}] deleted OK from DB [{}]", key, m_name);
        return true;
    }
    WAZUH_LOG_ERROR(
        "Couldn't delete key [{}] from DB [{}] CF [{}], error: [{}]",
        key,
        m_name,
        columnName,
        s.ToString());
    return false;
}

/**
 * @brief Create a Column object
 *
 * @param columnName name of the object that will be created
 * @return true successfull creation of Column in DB
 * @return false unsuccessfull creation or already created object
 */
bool KVDB::createColumn(const std::string &columnName)
{
    if (m_state != State::Open)
    {
        WAZUH_LOG_ERROR("DB [{}] should be open for execution", m_name);
        return false;
    }

    std::unique_lock lk(m_mtx);
    auto cfh = m_CFHandlesMap.find(columnName);
    if (cfh != m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR(
            "Couldn't create CF [{}] in DB [{}], name already taken",
            columnName,
            m_name);
        return false;
    }

    rocksdb::ColumnFamilyHandle *handler;
    rocksdb::Status s =
        m_db->CreateColumnFamily(kOptions.CF, columnName, &handler);
    if (s.ok())
    {
        CFDescriptors.push_back(
            rocksdb::ColumnFamilyDescriptor(columnName, kOptions.CF));
        m_CFHandlesMap.insert({handler->GetName(), handler});
        return true;
    }

    WAZUH_LOG_ERROR("Couldn't create CF [{}] in DB [{}], error: ",
                    columnName,
                    m_name,
                    s.ToString());
    return false;
}

/**
 * @brief Delete a Column object
 *
 * @param columnName name of the object that will be deleted
 * @return true successfull deletion of Column in DB
 * @return false unsuccessfull creation or object not found
 */
bool KVDB::deleteColumn(const std::string &columnName)
{
    if (m_state != State::Open)
    {
        WAZUH_LOG_ERROR("DB [{}] should be open for execution",
                        m_name);
        return false;
    }

    std::unique_lock lk(m_mtx);
    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("Couldn't delete CF [{}] from DB [{}], unknown column name",
                        columnName,
                        m_name);
        return false;
    }

    rocksdb::Status s = m_db->DropColumnFamily(cfh->second);
    if (s.ok())
    {
        m_CFHandlesMap.erase(cfh);
        for (int i = 0; i < CFDescriptors.size(); i++)
        {
            if (!columnName.compare(CFDescriptors.at(i).name))
            {
                CFDescriptors.erase(CFDescriptors.begin() + i);
                break;
            }
        }
        return true;
    }

    WAZUH_LOG_ERROR("Couldn't delete column [{}] from DB [{}], error: [{}]",
                    columnName,
                    m_name,
                    s.ToString());
    return false;
}

/**
 * @brief cleaning of all elements in Column
 //TODO: when trying to clean a default CF rocksdb doesn't allow it: <return
 Status::InvalidArgument("Can't drop default column family")> this needs to be
 fixed differently in order to avoid costly proccess on large DBs.
 * @param columnName that will be cleaned
 * @return true when successfully cleaned
 * @return false when unsuccessfully cleaned
 */
bool KVDB::cleanColumn(const std::string &columnName)
{
    if (columnName == DEFAULT_CF_NAME)
    {
        rocksdb::Iterator *iter = m_db->NewIterator(kOptions.read);
        iter->SeekToFirst();
        while (iter->Valid())
        {
            deleteKey(iter->key().ToString());
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

/**
 * @brief write vector of pair key values to DB in a pessimistic transaction
 * manner.
 * @param pairsVector input data of string pairs
 * @param columnName where the data will be written to
 * @return true when written and commited without any problem
 * @return false when one or more items weren't succesfully written.
 */
bool KVDB::writeToTransaction(
    const std::vector<std::pair<std::string, std::string>> &pairsVector,
    const std::string &columnName)
{
    if (m_state != State::Open)
    {
        WAZUH_LOG_ERROR("DB [{}] should be open for execution", m_name);
        return false;
    }

    if (!pairsVector.size())
    {
        WAZUH_LOG_ERROR(
            "Couldn't write transaction to DB [{}], need at least 1 element",
            m_name);
        return false;
    }

    if (m_state != State::Open)
    {
        WAZUH_LOG_ERROR("DB [{}] should be open for execution", m_name);
        return false;
    }

    std::shared_lock lk(m_mtx);
    auto cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("Couldn't write transaction to DB [{}] unknown "
                        "column name [{}]",
                        m_name,
                        columnName);
        return false;
    }

    rocksdb::Transaction *txn = m_txndb->BeginTransaction(kOptions.write);
    if (!txn)
    {
        WAZUH_LOG_ERROR("Couldn't begin in transaction in DB [{}]",
                        m_name);
        return false;
    }

    bool txnOk = true;
    for (auto pair : pairsVector)
    {
        std::string const key = pair.first;
        std::string const value = pair.second;
        if (key.empty())
        {
            WAZUH_LOG_ERROR("Discarding tuple [{},{}] in DB [{}] because key is empty",
                            key,
                            value,
                            m_name);
            continue;
        }
        // Write a key-value in this transaction
        rocksdb::Status s = txn->Put(cfh->second, key, value);
        if (!s.ok())
        {
            txnOk = false;
            WAZUH_LOG_ERROR("Couldn't execute Put in transaction for DB [{}], error: [{}]",
                            m_name,
                            s.ToString());
        }
    }
    rocksdb::Status s = txn->Commit();
    if (!s.ok())
    {
        txnOk = false;
        WAZUH_LOG_ERROR("Couldn't commit in transaction in DB [{}], error: [{}]",
                        m_name,
                        s.ToString());
    }

    delete txn;
    return txnOk;
}

/**
 * @brief check key existence in Column
 *
 * @param key used to check existence
 * @param columnName where to look for the key
 * @return true if key was found
 * @return false if key wasn't found
 */
bool KVDB::hasKey(const std::string &key, const std::string &columnName)
{
    std::shared_lock lk(m_mtx);
    auto cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("Couldn't read from DB [{}], unknown column name [{}]",
                        m_name,
                        columnName);
        return false;
    }

    if (m_state != State::Open)
    {
        WAZUH_LOG_ERROR("DB [{}] should be open for execution", m_name);
    }
    std::string value;
    return m_db->KeyMayExist(
        kOptions.read, cfh->second, rocksdb::Slice(key), &value);
}

/**
 * @brief
 * //TODO: this should be returning a PinnableSlice and the consumer should
 * reset it and read it's value. Check what methods should we add in order to
 * decouple rocksdb library from the client, wrapping all the functions and
 * objects needed.
 * @param key key where to find the value
 * @param value value that the result of the proccess will modify
 * @param ColumnName where to search the key
 * @return true If the proccess finished successfully
 * @return false If the proccess didn't finished successfully
 */
bool KVDB::readPinned(const std::string &key,
                      std::string &value,
                      const std::string &ColumnName)
{
    std::shared_lock lk(m_mtx);
    if (m_state != State::Open)
    {
        WAZUH_LOG_ERROR("DB [{}] should be open for execution", m_name);
        return false;
    }

    auto cfh = m_CFHandlesMap.find(ColumnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR(
            "Couldn't read value from DB [{}], unknown column name [{}]",
            m_name,
            ColumnName);
        return false;
    }

    rocksdb::PinnableSlice pinnable_val;
    rocksdb::Status s = m_db->Get(
        kOptions.read, cfh->second, rocksdb::Slice(key), &pinnable_val);
    if (s.ok())
    {
        value = pinnable_val.ToString();
        WAZUH_LOG_DEBUG("Successfull read pinned value [{},{}] from DB [{}]",
                        key,
                        value,
                        m_name);
        pinnable_val.Reset();
        return true;
    }

    WAZUH_LOG_ERROR("Couldn't read pinned value from DB [{}], error: [{}]",
                    m_name,
                    s.ToString());
    return false;
}

/**
 * @brief Check if the DB is able to be used.
 *
 * @return true if the DB can be used
 * @return false if the DB can´t be used
 */
bool KVDB::isReady()
{
    return (m_state == State::Open);
}

bool KVDB::isValid()
{
    return (m_state != State::Invalid);
}
