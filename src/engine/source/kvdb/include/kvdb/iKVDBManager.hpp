#ifndef _I_KVDB_MANAGER_H
#define _I_KVDB_MANAGER_H

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <kvdb/iKVDBScope.hpp>

namespace kvdbManager
{

/**
 * @brief Reference information for a KVDB Scope or Handler.
 * Typically used to get the number of references to a Scope or Handler.
 */
using RefInfo = std::map<std::string, unsigned int>;

/**
 * @brief Interface for the KVDBManager class.
 *
 */
class IKVDBManager
{
public:
    /**
     * @brief Gets a KVDB Scope given the provided scope name.
     * This will create the scope if it does not exist and will return the existing one otherwise.
     * @param scopeName Name of the Scope.
     * @return std::shared_ptr<IKVDBScope> A KVDBScope.
     *
     */
    virtual std::shared_ptr<IKVDBScope> getKVDBScope(const std::string& scopeName) = 0;

    /**
     * @brief Returns a list of all the DBs in the Manager.
     *
     * @param loaded Show only loaded DBs.
     * @return std::vector<std::string> List of DBs.
     *
     */
    virtual std::vector<std::string> listDBs(const bool loaded) = 0;

    /**
     * @brief Try to delete a DB if there are no references to it.
     *
     * @param name Name of the DB.
     * @return std::variant<base::Error> If base::Error not exists the DB was deleted successfully. Specific error otherwise.
     *
     */
    virtual std::optional<base::Error> deleteDB(const std::string& name) = 0;

    /**
     * @brief Creates a DB with the provided name.
     *
     * @param name Name of the DB.
     * @return std::variant<base::Error> If base::Error not exists the DB was created successfully. Specific error otherwise.
     *
     */
    virtual std::optional<base::Error> createDB(const std::string& name, const std::string& path) = 0;

    /**
     * @brief Checks if a DB exists.
     *
     * @param name Name of the DB.
     * @return true The DB exists.
     * @return false The DB does not exist.
     *
     */
    virtual bool existsDB(const std::string& name) = 0;

    /**
     * @brief Returns a map of all Scopes in the Manager and the DBs they reference.
     *
     * @return std::map<std::string, RefInfo> Map of Scopes and their DBs.
     *
     */
    virtual std::map<std::string, RefInfo> getKVDBScopesInfo() = 0;

    /**
     * @brief Returns a map of all DBs in the Manager and the scopes referencing them.
     *
     * @return std::map<std::string, RefInfo> Map of DBs and their scopes.
     *
     */
    virtual std::map<std::string, RefInfo> getKVDBHandlersInfo() = 0;
};

} // namespace kvdbManager

#endif // _I_KVDB_MANAGER_H
