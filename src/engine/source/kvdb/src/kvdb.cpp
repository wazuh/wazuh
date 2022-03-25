#include <assert.h>
#include <iostream>
#include <unordered_map>

#include "rocksdb/db.h"
#include "rocksdb/options.h"
#include "rocksdb/slice.h"
#include "rocksdb/utilities/transaction.h"

#include "kvdb.hpp"

KVDB::KVDB(const std::string &DBName, const std::string &path)
{
    auto DBPath = path + DBName;

    name = DBName;
    ROCKSDB::Status s;
    std::vector<std::string> CFNames;
    s = ROCKSDB::DB::ListColumnFamilies(options.open, DBPath, &CFNames);
    if (s.ok())
    {
        for (auto CFName : CFNames)
        {
            CFDescriptors.push_back(
                ROCKSDB::ColumnFamilyDescriptor(CFName, options.CF));
        }
        // TODO: should we open both? can we procede with only the transaction
        // one does it allows all the other uses without any issue?
        s = ROCKSDB::DB::Open(
            options.open, DBPath, CFDescriptors, &CFHandles, &m_db);

        ROCKSDB::Status st = ROCKSDB::TransactionDB::Open(options.open,
                                                          options.TX,
                                                          DBPath,
                                                          CFDescriptors,
                                                          &CFHandles,
                                                          &m_txndb);
        if (s.ok() && st.ok())
        {
            for (auto CFHandle : CFHandles)
            {
                CFHandlesMap[CFHandle->GetName()] = CFHandle;
            }
            state = State::Open;
        }
        else
        {
            // Log
            state = State::Error;
        }
    }
    else
    {
        // Log
        state = State::Error;
    }
}

bool KVDB::write(const std::string &key,
                 const std::string &value,
                 const std::string &columnName)
{
    CFHMap::const_iterator cfh = CFHandlesMap.find(columnName);
    if (cfh == CFHandlesMap.end())
    {
        // LOG Invalid CF
        return false;
    }

    ROCKSDB::Status s = m_db->Put(
        options.write, cfh->second, ROCKSDB::Slice(key), ROCKSDB::Slice(value));
    if (!s.ok())
    {
        // LOG(ERROR) << "[" << __func__ << "]" << " couldn't insert value into
        // CF, error: " << s.ToString() << std::endl;
        return false;
    }

    // LOG(DEBUG) << "[" << __func__ << "]" << " value insertion OK {" << key <<
    // ","<< value << "} into CF name : " << columnFamily << std::endl;
    return true;
}

std::string KVDB::read(const std::string &key, const std::string &ColumnName)
{
    std::string result, value;
    CFHMap::const_iterator cfh = CFHandlesMap.find(ColumnName);
    if (cfh == CFHandlesMap.end())
    {
        // LOG Invalid CF
        return result;
    }
    // Get CF handle
    ROCKSDB::Status s =
        m_db->Get(options.read, cfh->second, ROCKSDB::Slice(key), &value);
    if (s.ok())
    {
        // LOG(INFO) << "[" << __func__ << "]" << " value obtained OK {" << key
        // << ","<< value << "} from CF name : " << columnFamily << std::endl;
        result = value;
    }
    else
    {
        // LOG(ERROR) << "[" << __func__ << "]" << " couldn't insert value into
        // CF, error: " << s.ToString() << std::endl;
    }

    return value;
}

bool KVDB::deleteKey(const std::string &key, const std::string &columnName)
{
    CFHMap::const_iterator cfh = CFHandlesMap.find(columnName);
    if (cfh == CFHandlesMap.end())
    {
        // LOG Invalid CF
        return false;
    }

    ROCKSDB::Status s =
        m_db->Delete(options.write, cfh->second, ROCKSDB::Slice(key));
    if (s.ok())
    {
        // LOG(INFO) << "[" << __func__ << "]" << " key deleted OK {" << key <<
        // "} from CF name : " << column_family_name << std::endl;
        return true;
    }
    else
    {
        // LOG(ERROR) << "[" << __func__ << "]" << " couldn't delete value from
        // CF, error: " << s.ToString() << std::endl;
        return false;
    }
}

bool KVDB::createColumn(const std::string &columnName)
{
    CFHMap::const_iterator cfh = CFHandlesMap.find(columnName);
    if (cfh != CFHandlesMap.end())
    {
        // LOG Invalid CF
        return false;
    }

    // TODO: not neccesary!
    // ROCKSDB::ColumnFamilyOptions options;
    // options.create_missing_column_families = true;
    // setCFOptions(options);

    ROCKSDB::ColumnFamilyHandle *handler;
    ROCKSDB::Status s =
        m_db->CreateColumnFamily(options.CF, columnName, &handler);
    if (s.ok())
    {
        CFDescriptors.push_back(
            ROCKSDB::ColumnFamilyDescriptor(columnName, options.CF));
        CFHandlesMap.insert({handler->GetName(), handler});
        return true;
    }
    return false;
}

bool KVDB::deleteColumn(const std::string &columnName)
{
    CFHMap::const_iterator cfh = CFHandlesMap.find(columnName);
    if (cfh == CFHandlesMap.end())
    {
        // LOG Invalid CF
        return false;
    }

    ROCKSDB::Status s = m_db->DropColumnFamily(cfh->second);
    if (s.ok())
    {
        CFHandlesMap.erase(cfh);
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
        // LOG(ERROR) << "[" << __func__ << "]" << " can't write to a
        // Transaction without any pair." << std::endl;
        return false;
    }

    CFHMap::const_iterator cfh = CFHandlesMap.find(columnName);
    if (cfh == CFHandlesMap.end())
    {
        // LOG Invalid CF
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
                // LOG(ERROR) << "[" << __func__ << "]" << " can't write to a
                // Transaction to a family column with no key." << std::endl;
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
                // LOG(ERROR) << "[" << __func__ << "]" << " couldn't execute
                // Put in transaction -breaking loop-, error: " << s.code() <<
                // std::endl;
                return false;
            }
        }
        ROCKSDB::Status s = txn->Commit();
        if (s.ok())
        {
            // LOG(ERROR) << "[" << __func__ << "]" << " transaction commited
            // OK" << std::endl;
            delete txn;
            return true;
        }
        else
        {
            // LOG(ERROR) << "[" << __func__ << "]" << " couldn't commit
            // transaction, error: " << s.code() << std::endl;
            return false;
        }
    }
    else
    {
        // LOG(ERROR) << "[" << __func__ << "]" << " couldn't begin transaction,
        // error: " << s.code() << std::endl;
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
    CFHMap::const_iterator cfh = CFHandlesMap.find(ColumnName);
    if (cfh == CFHandlesMap.end())
    {
        // LOG Invalid CF
        return false;
    }

    ROCKSDB::PinnableSlice pinnable_val;
    ROCKSDB::Status s = m_db->Get(
        options.read, cfh->second, ROCKSDB::Slice(key), &pinnable_val);
    if (s.ok())
    {
        value = pinnable_val.ToString();
        // LOG(INFO) << "[" << __func__ << "]" << " value obtained OK {" << key
        // << ","
        // << value << "} from CF name : " << column_family_name << std::endl;
        pinnable_val.Reset();
        return true;
    }
    else
    {
        // LOG(ERROR) << "[" << __func__ << "]" << " couldn't insert value into
        // CF without copy, error: " << s.ToString() << std::endl;
        return false;
    }
}
