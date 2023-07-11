#ifndef _I_KVDB_MANAGER_H
#define _I_KVDB_MANAGER_H

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <kvdb/iKVDBHandler.hpp>

#include <utils/baseMacros.hpp>

namespace kvdbManager
{

/**
 * @brief Reference information for a KVDB Scope or Handler.
 * Typically used to get the number of references to a Scope or Handler.
 */
using RefInfo = std::map<std::string, uint32_t>;

/**
 * @brief Interface for the KVDBManager class.
 *
 */
class IKVDBManager
{
public:
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
     * @return std::variant<base::Error> If base::Error not exists the DB was deleted successfully. Specific error
     * otherwise.
     *
     */
    virtual std::optional<base::Error> deleteDB(const std::string& name) = 0;

    /**
     * @brief Creates a DB with the provided name.
     *
     * @param name Name of the DB.
     * @return std::variant<base::Error> If base::Error not exists the DB was created successfully. Specific error
     * otherwise.
     *
     */
    virtual std::optional<base::Error> createDB(const std::string& name) = 0;

    /**
     * @brief Load a DB with the provided file path.
     *
     * @param name Name of the DB.
     * @param path Path of file to load.
     * @return std::variant<base::Error> If base::Error not exists the DB was created successfully. Specific error
     * otherwise.
     *
     */
    virtual std::optional<base::Error> loadDBFromFile(const std::string& name, const std::string& path) = 0;

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
    virtual std::map<std::string, RefInfo> getKVDBHandlersInfo() const = 0;

    /**
     * @brief Gets a KVDB Handler given the provided DB name and scope name.
     *
     * @param dbName Name of the DB.
     * @param scopeName Name of the Scope.
     * @return std::variant<std::shared_ptr<IKVDBHandler>, base::Error> A KVDBHandler or specific error.
     */
    virtual std::variant<std::shared_ptr<IKVDBHandler>, base::Error> getKVDBHandler(const std::string& dbName,
                                                                                    const std::string& scopeName) = 0;

    /**
     * @brief Returns count of handlers for a given database.
     *
     * @param dbName Name of the DB.
     * @return uint32_t count of handlers.
     *
     */
    virtual uint32_t getKVDBHandlersCount(const std::string& dbName) const = 0;
};

} // namespace kvdbManager

#endif // _I_KVDB_MANAGER_H
