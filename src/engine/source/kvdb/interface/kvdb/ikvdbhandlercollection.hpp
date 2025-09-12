#ifndef _I_KVDB_HANDLER_COLLECTION_H
#define _I_KVDB_HANDLER_COLLECTION_H

#include <string>

namespace kvdbManager
{

/**
 * @brief Collection of KVDB Handlers for a given DB and the Scopes referencing them.
 *
 */
class IKVDBHandlerCollection
{
public:
    /**
     * @brief Registers a KVDB Handler and manage the reference counters and mappings.
     *
     * @param dbName Name of the DB.
     * @param scopeName Name of the Scope.
     *
     */
    virtual void addKVDBHandler(const std::string& dbName, const std::string& scopeName) = 0;

    /**
     * @brief Removes a KVDB Handler given the provided DB name and scope name.
     * This automatically manage the reference counters and mappings.
     *
     * @param dbName Name of the DB.
     * @param scopeName Name of the Scope.
     *
     */
    virtual void removeKVDBHandler(const std::string& dbName, const std::string& scopeName) = 0;
};

} // namespace kvdbManager

#endif // _I_KVDB_HANDLER_COLLECTION_H
