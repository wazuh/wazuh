#include <kvdb/kvdb.hpp>

#include <assert.h>
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
    return ret;
}

/**
 * @brief Db destruction cleaning all files and data related to it
 *
 * @return true succesfully destructed
 * @return false unsuccesfully destructed
 */
bool KVDB::destroy()
{
    close();
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
 * @brief write a value from to a key inside a CF without value copying
 *
 * @param key where to write the value
 * @param value the value that will be writen
 * @param columnName where to write the key
 * @return true If the proccess finished successfully
 * @return false If the proccess didn't finished successfully
 */
bool KVDB::write(const std::string &key,
                 const std::string &value,
                 const std::string &columnName)
{
    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("couldn't write to DB unknown column name");
        return false;
    }

    if (m_state == State::Open)
    {
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

        WAZUH_LOG_INFO("value insertion OK [{},{}] into CF name : [{}]",
                       key,
                       value,
                       columnName);
        return true;
    }
    else
    {
        WAZUH_LOG_ERROR("DB should be open for execution");
    }
    return false;
}

/**
 * @brief read a value from a key inside a CF without value copying
 *
 * @param key where to find the value
 * @param value that the result of the proccess will modify
 * @param columnName where to search the key
 * @return true If the proccess finished successfully
 * @return false If the proccess didn't finished successfully
 */
std::string KVDB::read(const std::string &key, const std::string &ColumnName)
{
    std::string result, value;
    CFHMap::const_iterator cfh = m_CFHandlesMap.find(ColumnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("couldn't read DB unknown column name");
        return result;
    }

    if (m_state == State::Open)
    {
        // Get CF handle
        rocksdb::Status s =
            m_db->Get(kOptions.read, cfh->second, rocksdb::Slice(key), &value);
        if (s.ok())
        {
            WAZUH_LOG_INFO("value obtained OK [{},{}] into CF name : [{}]",
                           key,
                           value,
                           ColumnName);
            result = value;
        }
        else
        {
            WAZUH_LOG_ERROR("couldn't insert value into CF, error: ",
                            s.ToString());
        }
    }
    else
    {
        WAZUH_LOG_ERROR("DB should be open for execution");
    }
    return value;
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
    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("couldn't delete key in DB unknown column name");
        return false;
    }

    if (m_state == State::Open)
    {
        rocksdb::Status s =
            m_db->Delete(kOptions.write, cfh->second, rocksdb::Slice(key));
        if (s.ok())
        {
            WAZUH_LOG_INFO("key deleted OK [{}]", key);
            return true;
        }
        else
        {
            WAZUH_LOG_ERROR("couldn't delete value in CF, error: [{}]",
                            s.ToString());
            return false;
        }
    }
    else
    {
        WAZUH_LOG_ERROR("DB should be open for execution");
    }
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
    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh != m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("couldn't create CF, name already taken");
        return false;
    }

    if (m_state == State::Open)
    {
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
    }
    else
    {
        WAZUH_LOG_ERROR("DB should be open for execution");
    }
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
    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("couldn't delete CF unknown column name");
        return false;
    }

    if (m_state == State::Open)
    {
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
        else
        {
            WAZUH_LOG_ERROR("couldn't delete Column, error: [{}]",
                            s.ToString());
        }
    }
    else
    {
        WAZUH_LOG_ERROR("DB should be open for execution");
    }
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
 * @brief write vector of pair key values to DB in a pessimisitc transaction
 * manner.
 * @param pairsVector input data of string pairs
 * @param columnName where the data will be writen to
 * @return true when written and commited wiithout any problem
 * @return false when one or more items wheren't succesfully writen.
 */
bool KVDB::writeToTransaction(
    const std::vector<std::pair<std::string, std::string>> pairsVector,
    const std::string &columnName)
{
    if (!pairsVector.size())
    {
        WAZUH_LOG_ERROR(
            "couldn't write transaction to DB, nedd at least 1 element");
        return false;
    }

    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("couldn't write transaction to DB unknown column name");
        return false;
    }

    if (m_state == State::Open)
    {
        rocksdb::Transaction *txn = m_txndb->BeginTransaction(kOptions.write);
        if (txn)
        {
            for (auto pair : pairsVector)
            {
                std::string const key = pair.first;
                std::string const value = pair.second;
                if (key.empty())
                {
                    WAZUH_LOG_ERROR("can't write to a Transaction to a family "
                                    "column with no key.");
                    return false;
                }
                // Write a key in this transaction
                rocksdb::Status s = txn->Put(cfh->second, key, value);
                if (s.ok())
                {
                    continue;
                }
                else
                {
                    WAZUH_LOG_ERROR("couldn't execute Put in transaction "
                                    "-breaking loop-, error: [{}]",
                                    s.ToString());
                    return false;
                }
            }
            rocksdb::Status s = txn->Commit();
            if (s.ok())
            {
                WAZUH_LOG_INFO("transaction commited OK");
                delete txn;
                return true;
            }
            else
            {
                WAZUH_LOG_ERROR("couldn't commit in transaction, error: [{}]",
                                s.ToString());
                return false;
            }
        }
        else
        {
            WAZUH_LOG_ERROR("couldn't begin in transaction");
            return false;
        }
    }
    else
    {
        WAZUH_LOG_ERROR("DB should be open for execution");
        return false;
    }
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
    // TODO: this should be done with a pinnable read
    std::string result = read(key, columnName);
    return !result.empty();
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
    CFHMap::const_iterator cfh = m_CFHandlesMap.find(ColumnName);
    if (cfh == m_CFHandlesMap.end())
    {
        WAZUH_LOG_ERROR("couldn't read value in DB unknown column name");
        return false;
    }

    if (m_state == State::Open)
    {
        rocksdb::PinnableSlice pinnable_val;
        rocksdb::Status s = m_db->Get(
            kOptions.read, cfh->second, rocksdb::Slice(key), &pinnable_val);
        if (s.ok())
        {
            value = pinnable_val.ToString();
            WAZUH_LOG_INFO("read pinned value OK [{},{}]", key, value);
            pinnable_val.Reset();
            return true;
        }
        else
        {
            WAZUH_LOG_ERROR("couldn't read pinned value, error: [{}]",
                            s.ToString());
            return false;
        }
    }
    else
    {
        WAZUH_LOG_ERROR("DB should be open for execution");
        return false;
    }
}
