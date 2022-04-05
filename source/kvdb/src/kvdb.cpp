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
        CFDescriptors.push_back(rocksdb::ColumnFamilyDescriptor(
            DEFAULT_CF_NAME, kOptions.CF));
    }

    rocksdb::Status st = rocksdb::TransactionDB::Open(kOptions.open,
                                                      kOptions.TX,
                                                      m_path,
                                                      CFDescriptors,
                                                      &CFHandles,
                                                      &m_txndb);
    if (st.ok())
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
        WAZUH_LOG_ERROR("couldn't open db, error: [{}]", s.ToString());
        m_state = State::Error;
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
    bool ret = true;
    if (m_txndb)
    {
        rocksdb::Status s;
        for (auto item : m_CFHandlesMap)
        {
            s = m_db->DestroyColumnFamilyHandle(item.second);
            if (!s.ok())
            {
                WAZUH_LOG_WARN("couldn't destroy family handler, error: [{}]",
                               s.ToString());
                ret = false;
            }
        }
        m_CFHandlesMap.clear();

        s = m_db->Close();
        if (!s.ok())
        {
            WAZUH_LOG_ERROR("couldn't close db, error: [{}]", s.ToString());
            ret = false;
        }

        delete m_txndb;
    }
    m_txndb = nullptr;
    m_db = nullptr;

    if (m_destroyOnClose && !destroy()) {
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
bool KVDB::destroy()
{
    rocksdb::Status s =
        rocksdb::DestroyDB(m_path, rocksdb::Options(), CFDescriptors);
    if (!s.ok())
    {
        WAZUH_LOG_ERROR("couldn't destroy db, error: [{}]", s.ToString());
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
bool KVDB::writeKeyOnly(const std::string &key,
                        const std::string &columnName)
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
        WAZUH_LOG_ERROR("DB should be open for execution");
        return false;
    }

    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("couldn't write to DB unknown column name");
        return false;
    }

    rocksdb::Status s = m_db->Put(kOptions.write,
                                cfh->second,
                                rocksdb::Slice(key),
                                rocksdb::Slice(value));
    if (!s.ok())
    {
        WAZUH_LOG_ERROR("couldn't insert value into CF, error: [{}]",
                        s.ToString());
        return false;
    }

    WAZUH_LOG_DEBUG("value insertion OK [{},{}] into CF name : [{}]",
                key,
                value,
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
std::string KVDB::read(const std::string &key, const std::string &ColumnName)
{
    std::string result, value;

    if (m_state != State::Open)
    {
        WAZUH_LOG_ERROR("DB should be open for execution");
        return result;
    }

    CFHMap::const_iterator cfh = m_CFHandlesMap.find(ColumnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("Couldn't read DB unknown column name");
        return result;
    }

    // Get CF handle
    rocksdb::Status s =
        m_db->Get(kOptions.read, cfh->second, rocksdb::Slice(key), &value);
    if (s.ok())
    {
        WAZUH_LOG_DEBUG("Value obtained OK [{},{}] into CF name : [{}]",
                        key,
                        value,
                        ColumnName);
        result = value;
    }
    else
    {
        WAZUH_LOG_ERROR("Couldn't read value, error: ",
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
 * @return true if the key was succesfully deleted
 * @return false if the key wasn't succesfully deleted
 */
bool KVDB::deleteKey(const std::string &key, const std::string &columnName)
{
    if (m_state != State::Open)
    {
        WAZUH_LOG_ERROR("DB should be open for execution");
        return false;
    }

    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("couldn't delete key in DB unknown column name");
        return false;
    }

    rocksdb::Status s =
        m_db->Delete(kOptions.write, cfh->second, rocksdb::Slice(key));
    if (s.ok())
    {
        WAZUH_LOG_INFO("key deleted OK [{}]", key);
        return true;
    }
    WAZUH_LOG_ERROR("couldn't delete value in CF, error: [{}]",
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
        WAZUH_LOG_ERROR("DB should be open for execution");
        return false;
    }

    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh != m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("couldn't create CF, name already taken");
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

    WAZUH_LOG_ERROR("couldn't create CF, error: ", s.ToString());
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
        WAZUH_LOG_ERROR("DB should be open for execution");
        return false;
    }

    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("couldn't delete CF unknown column name");
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

    WAZUH_LOG_ERROR("couldn't delete Column, error: [{}]",
                    s.ToString());
    return false;
}

/**
 * @brief cleaning of all elements in Column
 //TODO: when trying to clean a default CF rocksdb doesn't allow it: <return
 Status::InvalidArgument("Can't drop default column family")> this needs to be
 fixed differently in order to avoid costly proccess on large DBs.
 * @param columnName that will be cleaned
 * @return true when succesfully cleaned
 * @return false when unsuccesfully cleaned
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
    const std::vector<std::pair<std::string, std::string>>& pairsVector,
    const std::string &columnName)
{
    if (m_state != State::Open)
    {
        WAZUH_LOG_ERROR("DB should be open for execution");
        return false;
    }

    if (!pairsVector.size())
    {
        WAZUH_LOG_ERROR(
            "Couldn't write transaction to DB, need at least 1 element");
        return false;
    }

    if (m_state != State::Open)
    {
        WAZUH_LOG_ERROR("DB should be open for execution");
        return false;
    }

    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("Couldn't write transaction to DB unknown column name");
        return false;
    }

    rocksdb::Transaction *txn = m_txndb->BeginTransaction(kOptions.write);
    if (!txn)
    {
        WAZUH_LOG_ERROR("Couldn't begin in transaction");
        return false;
    }

    bool txnOk = true;
    for (auto pair : pairsVector)
    {
        std::string const key = pair.first;
        std::string const value = pair.second;
        if (key.empty())
        {
            WAZUH_LOG_ERROR("Discarding tuple because key is empty: [{}:{}]",
                            key, value);
            continue;
        }
        // Write a key-value in this transaction
        rocksdb::Status s = txn->Put(cfh->second, key, value);
        if (!s.ok())
        {
            txnOk = false;
            WAZUH_LOG_ERROR("Couldn't execute Put in transaction, error: [{}]",
                            s.ToString());
        }
    }
    rocksdb::Status s = txn->Commit();
    if (!s.ok())
    {
        txnOk = false;
        WAZUH_LOG_ERROR("couldn't commit in transaction, error: [{}]",
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
    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("couldn't read DB unknown column name");
        return false;
    }

    if (m_state != State::Open)
    {
        WAZUH_LOG_ERROR("DB should be open for execution");
    }
    std::string value;
    return m_db->KeyMayExist(kOptions.read, cfh->second, rocksdb::Slice(key), &value);
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
    if (m_state != State::Open)
    {
        WAZUH_LOG_ERROR("DB should be open for execution");
        return false;
    }

    CFHMap::const_iterator cfh = m_CFHandlesMap.find(ColumnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("couldn't read value in DB unknown column name");
        return false;
    }

    rocksdb::PinnableSlice pinnable_val;
    rocksdb::Status s = m_db->Get(
        kOptions.read, cfh->second, rocksdb::Slice(key), &pinnable_val);
    if (s.ok())
    {
        value = pinnable_val.ToString();
        WAZUH_LOG_DEBUG("read pinned value OK [{},{}]", key, value);
        pinnable_val.Reset();
        return true;
    }

    WAZUH_LOG_ERROR("couldn't read pinned value, error: [{}]",
                    s.ToString());
    return false;
}

/**
 * @brief Check if the DB is able to be used.
 *
 * @return true if the DB can be used
 * @return false if the DB can´t be used
 */
bool KVDB::isReady() {
    return (m_state == State::Open);
}
