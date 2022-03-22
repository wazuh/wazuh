#ifndef _KVDB_H
#define _KVDB_H

#include <string>
#include <vector>

#include "rocksdb/db.h"
//#include "rocksdb/rocksdb_namespace.h"

namespace ROCKSDB = ROCKSDB_NAMESPACE;

class KVDB {
    std::string name;
    ROCKSDB::DB* db;
    enum State {
        Closed,
        Open,
        Locked,
        Error,
        Invalid,
    } state;
    struct Option {
        ROCKSDB::ReadOptions read = ROCKSDB::ReadOptions();
        ROCKSDB::WriteOptions write = ROCKSDB::WriteOptions();
        ROCKSDB::DBOptions open = ROCKSDB::DBOptions();
        ROCKSDB::ColumnFamilyOptions CF = ROCKSDB::ColumnFamilyOptions();
    } options;
    std::vector<ROCKSDB::ColumnFamilyDescriptor> CFDescriptors;
    std::vector<ROCKSDB::ColumnFamilyHandle*> CFHandles;
    using CFHMap = std::map<std::string, ROCKSDB::ColumnFamilyHandle*>;
    CFHMap CFHandlesMap;

public:
    KVDB(const std::string& DBName, const std::string& path);
    std::string& getName() {return name;}
    std::string read(const std::string& key, const std::string& columnName = "default");
    const std::string& readPinned(const std::string& key, const std::string& columnName = "default");
    bool exist(const std::string& key, const std::string& columnName = "default");
    bool write(const std::string& key, const std::string& value, const std::string& columnName = "default");
    bool createColumn(const std::string& columnName);
    bool deleteColumn(const std::string& columnName = "default"); // TODO Is required to flush or only with drop we are ok?
    void setOpenOptions(ROCKSDB::DBOptions option);
    void setWriteOptions(ROCKSDB::WriteOptions option);
    void setReadOptions(ROCKSDB::ReadOptions option);
    void setCFOptions(ROCKSDB::ColumnFamilyOptions option);
};

#endif // _KVDB_H
