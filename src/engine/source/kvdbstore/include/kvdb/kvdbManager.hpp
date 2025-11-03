// kvdbManager.hpp
#ifndef _KVDB_STORE_MANAGER_H
#define _KVDB_STORE_MANAGER_H

#include <kvdb/ikvdbhandler.hpp>
#include <kvdb/ikvdbmanager.hpp>

namespace kvdbStore
{

class KVDBManager final : public IKVDBManager
{
public:
    KVDBManager() = default;
    ~KVDBManager() = default;
};

} // namespace kvdbStore

#endif // _KVDB_STORE_MANAGER_H
