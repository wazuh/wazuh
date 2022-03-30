#ifndef _KVDB_H
#define _KVDB_H

#include <string>
#include <vector>

#include "rocksdb/db.h"
#include "rocksdb/utilities/transaction_db.h"

namespace ROCKSDB = ROCKSDB_NAMESPACE;

class KVDB
{
public:
    KVDB();
    KVDB(const std::string &dbName, const std::string &folder);
    KVDB(KVDB const&) = delete;
    void operator=(KVDB const&)  = delete;
    ~KVDB();

    std::string &getName()
    {
        return m_name;
    }
    enum State
    {
        Closed,
        Open,
        Locked,
        Error,
        Invalid,
    };
    State getState() {
        return m_state;
    }
    bool createColumn(const std::string &columnName);
    bool deleteColumn(const std::string &columnName = ROCKSDB_NAMESPACE::kDefaultColumnFamilyName);
    bool cleanColumn(const std::string &columnName = ROCKSDB_NAMESPACE::kDefaultColumnFamilyName);
    bool write(const std::string &key,
               const std::string &value,
               const std::string &columnName = ROCKSDB_NAMESPACE::kDefaultColumnFamilyName);
    bool writeToTransaction(
        const std::vector<std::pair<std::string, std::string>> pairsVector,
        const std::string &columnName = ROCKSDB_NAMESPACE::kDefaultColumnFamilyName);
    bool exist(const std::string &key,
                  const std::string &columnName = ROCKSDB_NAMESPACE::kDefaultColumnFamilyName);
    std::string read(const std::string &key,
                     const std::string &columnName = ROCKSDB_NAMESPACE::kDefaultColumnFamilyName);
    bool readPinned(const std::string &key,
                    std::string &val,
                    const std::string &columnName = ROCKSDB_NAMESPACE::kDefaultColumnFamilyName);

    bool deleteKey(const std::string &key, const std::string &columnName = ROCKSDB_NAMESPACE::kDefaultColumnFamilyName);
    bool close();
    bool destroy();

private:
    std::string m_name;
    std::string m_path;
    State m_state;

    ROCKSDB::DB *m_db;
    ROCKSDB::TransactionDB *m_txndb;
    struct Option
    {
        ROCKSDB::ReadOptions read = ROCKSDB::ReadOptions();
        ROCKSDB::WriteOptions write = ROCKSDB::WriteOptions();
        ROCKSDB::DBOptions open = ROCKSDB::DBOptions();
        ROCKSDB::ColumnFamilyOptions CF = ROCKSDB::ColumnFamilyOptions();
        ROCKSDB::TransactionDBOptions TX = ROCKSDB::TransactionDBOptions();
    } options;
    std::vector<ROCKSDB::ColumnFamilyDescriptor> CFDescriptors;
    using CFHMap = std::map<std::string, ROCKSDB::ColumnFamilyHandle *>;
    CFHMap m_CFHandlesMap;
};

#endif // _KVDB_H
