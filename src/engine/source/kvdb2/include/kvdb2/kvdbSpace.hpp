#ifndef _KVDBSPACE_H
#define _KVDBSPACE_H

#include <kvdb2/iKVDBHandler.hpp>
#include <kvdb2/kvdbManagedHandler.hpp>

#include "rocksdb/db.h"

namespace kvdbManager
{

class IKVDBHandlerManager;

class KVDBSpace
    : public IKVDBHandler
    , public KVDBManagedHandler
{
public:
    KVDBSpace(IKVDBHandlerManager* manager,
              rocksdb::DB* db,
              rocksdb::ColumnFamilyHandle* cfHandle,
              const std::string& spaceName,
              const std::string& scopeName);
    ~KVDBSpace();
    std::variant<bool, base::Error> set(const std::string& key, const std::string& value) override;
    std::variant<bool, base::Error> add(const std::string& key) override;
    std::variant<bool, base::Error> remove(const std::string& key) override;
    std::variant<bool, base::Error> contains(const std::string& key) override;
    std::variant<std::string, base::Error> get(const std::string& key) override;
    std::variant<std::unordered_map<std::string, std::string>, base::Error> dump() override;

protected:
    rocksdb::ColumnFamilyHandle* m_pCFhandle;
    rocksdb::DB* m_pRocksDB;
};

} // namespace kvdbManager

#endif // _KVDBSPACE_H
