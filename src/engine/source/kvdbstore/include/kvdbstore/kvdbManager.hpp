// kvdbManager.hpp
#ifndef _KVDB_STORE_MANAGER_H
#define _KVDB_STORE_MANAGER_H

#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include <cmstore/icmstore.hpp>
#include <cmstore/types.hpp>

#include <kvdbstore/ikvdbhandler.hpp>
#include <kvdbstore/ikvdbmanager.hpp>
#include <kvdbstore/kvdbHandler.hpp>

namespace kvdbstore
{

using DBMap = std::unordered_map<std::string /*dbName*/, std::weak_ptr<const KVMap>>;
using Registry = std::unordered_map<cm::store::NamespaceId, DBMap>;

class KVDBManager final : public IKVDBManager
{
public:
    KVDBManager() = default;
    ~KVDBManager() = default;

    // Non-copyable / non-movable
    KVDBManager(const KVDBManager&) = delete;
    KVDBManager& operator=(const KVDBManager&) = delete;
    KVDBManager(KVDBManager&&) = delete;
    KVDBManager& operator=(KVDBManager&&) = delete;

    std::shared_ptr<IKVDBHandler> getKVDBHandler(const cm::store::ICMStoreNSReader& nsReader,
                                                 const std::string& dbName) override;

private:
    std::shared_mutex m_mutex;
    Registry m_registry;
};

} // namespace kvdbstore

#endif // _KVDB_STORE_MANAGER_H
