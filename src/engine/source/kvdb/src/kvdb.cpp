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

KVDB::KVDB() {
    m_name = "Invalid";
    m_db = nullptr;
    m_txndb = nullptr;
    m_state = State::Invalid;
}

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
        WAZUH_LOG_ERROR(msg);
        m_state = State::Error;
    }
}

KVDB::~KVDB()
{
    close();
}

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
                WAZUH_LOG_WARN(msg);
                ret = false;
            }
        }
        m_CFHandlesMap.clear();

        s = m_db->Close();
        if (!s.ok())
        {
            auto msg =
                fmt::format("couldn't close db, error: [{}]", s.ToString());
            WAZUH_LOG_ERROR(msg);
            ret = false;
        }

        delete m_txndb;
    }
    m_txndb = nullptr;
    m_db = nullptr;
    return ret;
}

bool KVDB::destroy() {
    close();
    ROCKSDB::Status s = ROCKSDB::DestroyDB(m_path, ROCKSDB::Options(), CFDescriptors);
    return s.ok();
}


bool KVDB::write(const std::string &key,
                 const std::string &value,
                 const std::string &columnName)
{
    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        auto msg = fmt::format("couldn't write to DB unknown column name");
        WAZUH_LOG_ERROR(msg);
        return false;
    }

    ROCKSDB::Status s = m_db->Put(
        options.write, cfh->second, ROCKSDB::Slice(key), ROCKSDB::Slice(value));
    if (!s.ok())
    {
        auto msg = fmt::format("couldn't insert value into CF, error: [{}]",
                               s.ToString());
        WAZUH_LOG_ERROR(msg);
        return false;
    }

    auto msg = fmt::format("value insertion OK [{},{}] into CF name : [{}]",
                           key,
                           value,
                           columnName);
    WAZUH_LOG_INFO(msg);
    return true;
}

std::string KVDB::read(const std::string &key, const std::string &ColumnName)
{
    std::string result, value;
    CFHMap::const_iterator cfh = m_CFHandlesMap.find(ColumnName);
    if (cfh == m_CFHandlesMap.end())
    {
        auto msg = fmt::format("couldn't read DB unknown column name");
        WAZUH_LOG_ERROR(msg);
        return result;
    }
    // Get CF handle
    ROCKSDB::Status s =
        m_db->Get(options.read, cfh->second, ROCKSDB::Slice(key), &value);
    if (s.ok())
    {
        auto msg = fmt::format("value obtained OK [{},{}] into CF name : [{}]",
                               key,
                               value,
                               ColumnName);
        WAZUH_LOG_INFO(msg);
        result = value;
    }
    else
    {
        auto msg =
            fmt::format("couldn't insert value into CF, error: ", s.ToString());
        WAZUH_LOG_ERROR(msg);
    }

    return value;
}

bool KVDB::deleteKey(const std::string &key, const std::string &columnName)
{
    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        auto msg = fmt::format("couldn't delete key in DB unknown column name");
        WAZUH_LOG_ERROR(msg);
        return false;
    }

    ROCKSDB::Status s =
        m_db->Delete(options.write, cfh->second, ROCKSDB::Slice(key));
    if (s.ok())
    {
        auto msg = fmt::format("key deleted OK [{}]", key);
        WAZUH_LOG_ERROR(msg);
        return true;
    }
    else
    {
        auto msg =
            fmt::format("couldn't delete value in CF, error: ", s.ToString());
        WAZUH_LOG_ERROR(msg);
        return false;
    }
}

bool KVDB::createColumn(const std::string &columnName)
{
    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh != m_CFHandlesMap.end())
    {
        auto msg = fmt::format("couldn't create CF, name already taken");
        WAZUH_LOG_ERROR(msg);
        return false;
    }

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
    return false;
}

bool KVDB::deleteColumn(const std::string &columnName)
{
    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        auto msg = fmt::format("couldn't delete CF unknown column name");
        WAZUH_LOG_ERROR(msg);
        return false;
    }

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
    return false;
}

bool KVDB::cleanColumn(const std::string &columnName)
{
    if (deleteColumn(columnName))
    {
        return createColumn(columnName);
    }
    return false;
}

bool KVDB::writeToTransaction(
    const std::vector<std::pair<std::string, std::string>> pairsVector,
    const std::string &columnName)
{
    if (!pairsVector.size())
    {
        auto msg = fmt::format(
            "couldn't write transaction to DB, nedd at least 1 element");
        WAZUH_LOG_ERROR(msg);
        return false;
    }

    CFHMap::const_iterator cfh = m_CFHandlesMap.find(columnName);
    if (cfh == m_CFHandlesMap.end())
    {
        auto msg =
            fmt::format("couldn't write transaction to DB unknown column name");
        WAZUH_LOG_ERROR(msg);
        return false;
    }

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
                WAZUH_LOG_ERROR(msg);
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
                WAZUH_LOG_ERROR(msg);
                return false;
            }
        }
        ROCKSDB::Status s = txn->Commit();
        if (s.ok())
        {
            auto msg = fmt::format("transaction commited OK");
            WAZUH_LOG_INFO(msg);
            delete txn;
            return true;
        }
        else
        {
            auto msg = fmt::format(
                "couldn't commit in transaction, error: [{}]", s.ToString());
            WAZUH_LOG_ERROR(msg);
            return false;
        }
    }
    else
    {
        auto msg = fmt::format("couldn't begin in transaction");
        WAZUH_LOG_ERROR(msg);
        return false;
    }
}

bool KVDB::existKey(const std::string &key, const std::string &columnName)
{
    std::string result = read(key, columnName);
    return !result.empty();
}

bool KVDB::readPinned(const std::string &key,
                      std::string &value,
                      const std::string &ColumnName)
{
    CFHMap::const_iterator cfh = m_CFHandlesMap.find(ColumnName);
    if (cfh == m_CFHandlesMap.end())
    {
        auto msg = fmt::format("couldn't read value in DB unknown column name");
        WAZUH_LOG_ERROR(msg);
        return false;
    }

    ROCKSDB::PinnableSlice pinnable_val;
    ROCKSDB::Status s = m_db->Get(
        options.read, cfh->second, ROCKSDB::Slice(key), &pinnable_val);
    if (s.ok())
    {
        value = pinnable_val.ToString();
        auto msg = fmt::format("read pinned value OK [{},{}]", key, value);
        WAZUH_LOG_INFO(msg);
        pinnable_val.Reset();
        return true;
    }
    else
    {
        auto msg =
            fmt::format("couldn't read pinned value, error: ", s.ToString());
        WAZUH_LOG_ERROR(msg);
        return false;
    }
}
