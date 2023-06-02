#ifndef _I_KVDB_SCOPE_H
#define _I_KVDB_SCOPE_H

#include <memory>

#include <kvdb/iKVDBHandler.hpp>

namespace kvdbManager
{

/**
 * @brief Interface for the KVDBScope class.
 * A Scope if a simple identifier of any entity using the KVDBManager.
 * A Scope might be the API, the Builder, the CLI, etc.
 * This is useful to track who is using the DBs and how many references they own.
 * This offers as much granularity as needed.
 */
class IKVDBScope
{
public:
    /**
     * @brief Gets a KVDB Handler given the provided DB name.
     *
     * @param dbName Name of the DB.
     * @return std::variant<std::unique_ptr<IKVDBHandler>, base::Error> A KVDBHandler or specific error.
     */
    virtual std::variant<std::unique_ptr<IKVDBHandler>, base::Error> getKVDBHandler(const std::string& dbName) = 0;
};

} // namespace kvdbManager

#endif // _I_KVDB_SCOPE_H
