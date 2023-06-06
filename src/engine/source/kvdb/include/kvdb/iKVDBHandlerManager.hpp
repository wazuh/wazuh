#ifndef _I_KVDB_HANDLER_MANAGER_H
#define _I_KVDB_HANDLER_MANAGER_H

#include <kvdb/iKVDBHandler.hpp>
#include <memory>
#include <string>

namespace kvdbManager
{
/**
 * @brief Subset interface of Manager that deals with KVDB Handlers only.
 *
 */
class IKVDBHandlerManager
{
public:
    /**
     * @brief Gets a KVDB Handler given the provided DB name and scope name.
     *
     * @param dbName Name of the DB.
     * @param scopeName Name of the Scope.
     * @return std::variant<std::shared_ptr<IKVDBHandler>, base::Error> A KVDBHandler or specific error.
     */
    virtual std::variant<std::shared_ptr<IKVDBHandler>, base::Error> getKVDBHandler(const std::string& dbName, const std::string& scopeName) = 0;

    /**
     * @brief Removes a KVDB Handler given the provided DB name and scope name.
     *
     * @param dbName Name of the DB.
     * @param scopeName NMame of the Scope.
     */
    virtual void removeKVDBHandler(const std::string& dbName, const std::string& scopeName) = 0;

    /**
     * @brief Returns if the Manager is in Shutdown mode.
     * If Manager is shutting down, handlers will not auto remove.
     *
     * @return true The Manager is shutting down.
     * @return false The Manager is not shutting down.
     */
    virtual bool skipAutoRemoveEnabled() = 0;
};

} // namespace kvdbManager

#endif // _I_KVDB_HANDLER_MANAGER_H
