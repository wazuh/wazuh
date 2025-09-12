#ifndef _I_KVDB_MANAGER_H
#define _I_KVDB_MANAGER_H

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <kvdb/ikvdbhandler.hpp>
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
     * @brief Initialize the KVDBManager.
     * Setup options, filesystem, RocksDB internals, etc.
     *
     */
    virtual void initialize() = 0;

    /**
     * @brief Finalize the KVDBManager.
     *
     */
    virtual void finalize() = 0;

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
     * @return base::OptError If base::Error not exists the DB was deleted successfully. Specific error
     * otherwise.
     *
     */
    virtual base::OptError deleteDB(const std::string& name) = 0;

    /**
     * @brief Creates a DB with the provided name.
     *
     * @param name Name of the DB.
     * @return base::OptError If base::Error not exists the DB was created successfully. Specific error
     * otherwise.
     *
     */
    virtual base::OptError createDB(const std::string& name) = 0;

    /**
     * @brief Creates a DB with the provided name from a json file.
     *
     * @param name Name of the DB.
     * @param path Path of the json file.
     * @return base::OptError If base::Error not exists the DB was created successfully. Specific error
     * otherwise.
     *
     */
    virtual base::OptError createDB(const std::string& name, const std::string& path) = 0;

    /**
     * @brief Load a DB with the provided file path.
     *
     * @param name Name of the DB.
     * @param content Content to save
     * @return base::OptError If base::Error not exists the DB was created successfully. Specific error
     * otherwise.
     *
     */
    virtual base::OptError loadDBFromJson(const std::string& name, const json::Json& content) = 0;

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
     * @return base::RespOrError<std::shared_ptr<IKVDBHandler>> A KVDBHandler or specific error.
     */
    virtual base::RespOrError<std::shared_ptr<IKVDBHandler>> getKVDBHandler(const std::string& dbName,
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
