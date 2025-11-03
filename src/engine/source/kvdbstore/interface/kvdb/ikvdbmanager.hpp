#ifndef _KVDB_IKVDBMANAGER_H
#define _KVDB_IKVDBMANAGER_H

#include <memory>
#include <string>

#include <cmstore/icmstore.hpp>

#include <kvdb/ikvdbhandler.hpp>

namespace kvdbStore
{
/**
 * @brief Interface for namespace-scoped key-value database access.
 *
 * This interface defines the contract for components that expose logical
 * key-value databases (KVDBs) grouped by namespace and database name.
 *
 * Implementations are responsible for:
 *  - accepting KVDB content provided by upper layers,
 *  - making that content available to consumers through typed handlers, and
 *  - enforcing the namespace + dbName addressing model.
 *
 * The goal is to provide a stable, engine-facing API that helpers/builders
 * can use to resolve KV entries.
 */
class IKVDBManager
{
public:
    virtual ~IKVDBManager() = default;

    /**
     * @brief Get a read-only handler bound to a specific (namespace, dbName).
     *
     * The returned handler is the access point for helpers. If the pair (ns, dbName)
     * does not exist, this method must return nullptr.
     *
     * @param nsReader Content Manager namespace-scoped reader.
     * @param dbName Name of the KVDB in that namespace.
     * @return Shared handler on success; nullptr if not found.
     */
    virtual std::shared_ptr<IKVDBHandler> getKVDBHandler(const cm::store::ICMStoreNSReader& nsReader,
                                                         const std::string& dbName) const noexcept = 0;
};

} // namespace kvdbStore

#endif // _KVDB_IKVDBMANAGER_H
