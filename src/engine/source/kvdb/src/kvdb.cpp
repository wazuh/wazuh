#include <assert.h>
#include <iostream>
#include <unordered_map>

#include <fmt/format.h>
#include <logging/logging.hpp>
#include "rocksdb/db.h"
#include "rocksdb/options.h"
#include "rocksdb/slice.h"
#include "rocksdb/utilities/transaction.h"

#include "kvdb.hpp"

/**
 * @brief Construct a new KVDB empty object
 *
 */
KVDB::KVDB() {
    m_name = "Invalid";
    m_db = nullptr;
    m_txndb = nullptr;
    m_state = State::Invalid;
}

/**
 * @brief Construct a new KVDB::KVDB object
 *
 * @param dbName name of the DB
 * @param folder where the DB will be stored
 */
KVDB::KVDB(const std::string &dbName, const std::string &folder)
{
    m_name = dbName;
    m_path = folder + dbName;
    m_db = nullptr;
    m_txndb = nullptr;
    m_state = State::Invalid;

    ROCKSDB::Status s;
    std::vector<std::string> CFNames;
    std::vector<ROCKSDB::ColumnFamilyHandle *> CFHandles;
    s = ROCKSDB::DB::ListColumnFamilies(options.open, m_path, &CFNames);
    if (s.ok())
    {
        for (auto CFName : CFNames)
        {
            CFDescriptors.push_back(
                ROCKSDB::ColumnFamilyDescriptor(CFName, options.CF));
        }
    }
    else {
        CFDescriptors.push_back(
                ROCKSDB::ColumnFamilyDescriptor("default", options.CF));
    }

    ROCKSDB::Status st = ROCKSDB::TransactionDB::Open(options.open,
                                                        options.TX,
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
        auto msg =
            fmt::format("couldn't open db, error: [{}]", s.ToString());
        WAZUH_LOG_ERROR("{}",msg);
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
bool KVDB::close() {
    bool ret = true;
    if (m_txndb)
    {
        ROCKSDB::Status s;
        for (auto item : m_CFHandlesMap)
        {
            s = m_db->DestroyColumnFamilyHandle(item.second);
            if (!s.ok())
            {
                auto msg =
                    fmt::format("couldn't destroy family handler, error: [{}]",
                                s.ToString());
                WAZUH_LOG_WARN("{}",msg);
                ret = false;
            }
        }
        m_CFHandlesMap.clear();

        s = m_db->Close();
        if (!s.ok())
        {
            auto msg =
                fmt::format("couldn't close db, error: [{}]", s.ToString());
            WAZUH_LOG_ERROR("{}",msg);
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
bool KVDB::destroy() {
    close();
    ROCKSDB::Status s = ROCKSDB::DestroyDB(m_path, ROCKSDB::Options(), CFDescriptors);
    return s.ok();
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
        auto msg = fmt::format("couldn't write to DB unknown column name");
        WAZUH_LOG_ERROR("{}",msg);
        return false;
    }

    if (m_state == State::Open)
    {
        ROCKSDB::Status s = m_db->Put(
            options.write, cfh->second, ROCKSDB::Slice(key), ROCKSDB::Slice(value));
        if (!s.ok())
        {
            auto msg = fmt::format("couldn't insert value into CF, error: [{}]",
                                s.ToString());
            WAZUH_LOG_ERROR("{}",msg);
            return false;
        }

        auto msg = fmt::format("value insertion OK [{},{}] into CF name : [{}]",
                            key,
                            value,
                            columnName);
        WAZUH_LOG_INFO("{}",msg);
        return true;
    }
    else {
        auto msg = fmt::format("DB should be open for execution");
        WAZUH_LOG_ERROR("{}",msg);
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
        auto msg = fmt::format("couldn't read DB unknown column name");
        WAZUH_LOG_ERROR("{}",msg);
        return result;
    }

    if (m_state == State::Open)
    {
        // Get CF handle
        ROCKSDB::Status s =
            m_db->Get(options.read, cfh->second, ROCKSDB::Slice(key), &value);
        if (s.ok())
        {
            auto msg = fmt::format("value obtained OK [{},{}] into CF name : [{}]",
                                key,
                                value,
                                ColumnName);
            WAZUH_LOG_INFO("{}",msg);
            result = value;
        }
        else
        {
            auto msg =
                fmt::format("couldn't insert value into CF, error: ", s.ToString());
            WAZUH_LOG_ERROR("{}",msg);
        }
    }
    else {
        auto msg = fmt::format("DB should be open for execution");
        WAZUH_LOG_ERROR("{}",msg);
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
        auto msg = fmt::format("couldn't delete key in DB unknown column name");
        WAZUH_LOG_ERROR("{}",msg);
        return false;
    }

    if (m_state == State::Open)
    {
        ROCKSDB::Status s =
            m_db->Delete(options.write, cfh->second, ROCKSDB::Slice(key));
        if (s.ok())
        {
            auto msg = fmt::format("key deleted OK [{}]", key);
            WAZUH_LOG_ERROR("{}",msg);
            return true;
        }
        else
        {
            auto msg =
                fmt::format("couldn't delete value in CF, error: ", s.ToString());
            WAZUH_LOG_ERROR("{}",msg);
            return false;
        }
    }
    else {
        auto msg = fmt::format("DB should be open for execution");
        WAZUH_LOG_ERROR("{}",msg);
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
        auto msg = fmt::format("couldn't create CF, name already taken");
        WAZUH_LOG_ERROR("{}",msg);
        return false;
    }

    if (m_state == State::Open)
    {
        ROCKSDB::ColumnFamilyHandle *handler;
        ROCKSDB::Status s =
            m_db->CreateColumnFamily(options.CF, columnName, &handler);
        if (s.ok())
        {
            CFDescriptors.push_back(
                ROCKSDB::ColumnFamilyDescriptor(columnName, options.CF));
            m_CFHandlesMap.insert({handler->GetName(), handler});
            return true;
        }
    }
    else {
        auto msg = fmt::format("DB should be open for execution");
        WAZUH_LOG_ERROR("{}",msg);
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
        auto msg = fmt::format("couldn't delete CF unknown column name");
        WAZUH_LOG_ERROR("{}",msg);
        return false;
    }

    if (m_state == State::Open)
    {
        ROCKSDB::Status s = m_db->DropColumnFamily(cfh->second);
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
    }
    else {
        auto msg = fmt::format("DB should be open for execution");
        WAZUH_LOG_ERROR("{}",msg);
    }
    return false;
}

/**
 * @brief cleaning of all elements in Column
 *
 * @param columnName that will be cleaned
 * @return true when succesfully cleaned
 * @return false when unsuccesfully cleaned
 */
bool KVDB::cleanColumn(const std::string &columnName)
{
    if (deleteColumn(columnName))
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
        auto msg = fmt::format(
            "couldn't write transaction to DB, nedd at least 1 element");
        WAZUH_LOG_ERROR("{}",msg);
        return false;
    }

    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        auto msg =
            fmt::format("couldn't write transaction to DB unknown column name");
        WAZUH_LOG_ERROR("{}",msg);
        return false;
    }

    if(m_state == State::Open)
    {
        ROCKSDB::Transaction *txn = m_txndb->BeginTransaction(options.write);
        if (txn)
        {
            for (auto pair : pairsVector)
            {
                std::string const key = pair.first;
                std::string const value = pair.second;
                if (key.empty())
                {
                    auto msg = fmt::format("can't write to a Transaction to a "
                                        "family column with no key.");
                    WAZUH_LOG_ERROR("{}",msg);
                    return false;
                }
                // Write a key in this transaction
                ROCKSDB::Status s = txn->Put(cfh->second, key, value);
                if (s.ok())
                {
                    continue;
                }
                else
                {
                    auto msg = fmt::format("couldn't execute Put in transaction "
                                        "-breaking loop-, error: [{}]",
                                        s.ToString());
                    WAZUH_LOG_ERROR("{}",msg);
                    return false;
                }
            }
            ROCKSDB::Status s = txn->Commit();
            if (s.ok())
            {
                auto msg = fmt::format("transaction commited OK");
                WAZUH_LOG_INFO("{}",msg);
                delete txn;
                return true;
            }
            else
            {
                auto msg = fmt::format(
                    "couldn't commit in transaction, error: [{}]", s.ToString());
                WAZUH_LOG_ERROR("{}",msg);
                return false;
            }
        }
        else
        {
            auto msg = fmt::format("couldn't begin in transaction");
            WAZUH_LOG_ERROR("{}",msg);
            return false;
        }
    }
    else
    {
        auto msg = fmt::format("DB should be open for execution");
        WAZUH_LOG_ERROR("{}",msg);
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
bool KVDB::existKey(const std::string &key, const std::string &columnName)
{

    //TODO: this should be done with a pinnable read
    std::string result = read(key, columnName);
    return !result.empty();
}

/**
 * @brief
 * //TODO: this should be returning a PinnableSlice and the consumer should be resetting it
 * Check what methods should we add in order to decouple rocksdb library from the client
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
        auto msg = fmt::format("couldn't read value in DB unknown column name");
        WAZUH_LOG_ERROR("{}",msg);
        return false;
    }

    if(m_state == State::Open)
    {
        ROCKSDB::PinnableSlice pinnable_val;
        ROCKSDB::Status s = m_db->Get(
            options.read, cfh->second, ROCKSDB::Slice(key), &pinnable_val);
        if (s.ok())
        {
            value = pinnable_val.ToString();
            auto msg = fmt::format("read pinned value OK [{},{}]", key, value);
            WAZUH_LOG_INFO("{}",msg);
            pinnable_val.Reset();
            return true;
        }
        else
        {
            auto msg =
                fmt::format("couldn't read pinned value, error: ", s.ToString());
            WAZUH_LOG_ERROR("{}",msg);
            return false;
        }
    }
    else
    {
        auto msg = fmt::format("DB should be open for execution");
        WAZUH_LOG_ERROR("{}",msg);
        return false;
    }
}
