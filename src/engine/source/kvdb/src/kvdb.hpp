#ifndef _KVDB_H
#define _KVDB_H

#include <string>
#include <vector>

#include "rocksdb/db.h"
#include "rocksdb/utilities/transaction_db.h"

namespace ROCKSDB = ROCKSDB_NAMESPACE;

class KVDB
{
    std::string name;
    ROCKSDB::DB *m_db;
    ROCKSDB::TransactionDB *m_txndb;
    enum State
    {
        Closed,
        Open,
        Locked,
        Error,
        Invalid,
    } state;
    struct Option
    {
        ROCKSDB::ReadOptions read = ROCKSDB::ReadOptions();
        ROCKSDB::WriteOptions write = ROCKSDB::WriteOptions();
        ROCKSDB::DBOptions open = ROCKSDB::DBOptions();
        ROCKSDB::ColumnFamilyOptions CF = ROCKSDB::ColumnFamilyOptions();
        ROCKSDB::TransactionDBOptions TX = ROCKSDB::TransactionDBOptions();
    } options;
    std::vector<ROCKSDB::ColumnFamilyDescriptor> CFDescriptors;
    std::vector<ROCKSDB::ColumnFamilyHandle *>
        CFHandles; // TODO: move to a local scope when needed
    using CFHMap = std::map<std::string, ROCKSDB::ColumnFamilyHandle *>;
    CFHMap CFHandlesMap;

public:
    KVDB(const std::string &DBName, const std::string &path);
    // TODO: hacer destructor q cierre correctamente ~KVDB();

    std::string &getName()
    {
        return name;
    }
    bool createColumn(const std::string &columnName);
    bool deleteColumn(const std::string &columnName = "default");
    bool cleanColumn(const std::string &columnName = "default");
    bool existKey(const std::string &key,
                  const std::string &columnName = "default");
    std::string read(const std::string &key,
                     const std::string &columnName = "default");
    bool readPinned(const std::string &key,
                    std::string &val,
                    const std::string &columnName = "default");
    bool write(const std::string &key,
               const std::string &value,
               const std::string &columnName = "default");
    bool writeToTransaction(
        const std::vector<std::pair<std::string, std::string>> pairsVector,
        const std::string &columnName = "default");
    bool deleteKey(const std::string &key, const std::string &columnName);

    // Configuration
    void setOpenOptions(ROCKSDB::DBOptions option);
    void setWriteOptions(ROCKSDB::WriteOptions option);
    void setReadOptions(ROCKSDB::ReadOptions option);
    void setCFOptions(ROCKSDB::ColumnFamilyOptions option);
};

#endif // _KVDB_H
