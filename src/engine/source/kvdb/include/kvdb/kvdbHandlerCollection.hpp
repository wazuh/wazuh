#ifndef _KVDB_HANDLER_COLLECTION_H
#define _KVDB_HANDLER_COLLECTION_H

#include <kvdb/ikvdbhandlercollection.hpp>

#include <map>
#include <memory>
#include <set>
#include <shared_mutex>

#include <kvdb/kvdbHandler.hpp>
#include <kvdb/refCounter.hpp>

namespace kvdbManager
{

/**
 * @brief Helper class to manage the reference counters for a given DB.
 * This is used to track how many scopes are using a given DB.
 *
 */
class KVDBHandlerInstance
{
public:
    /**
     * @brief Add a new scope to the reference counter.
     *
     * @param scopeName Name of the Scope.
     *
     */
    void addScope(const std::string& scopeName);

    /**
     * @brief Remove a scope from the reference counter.
     *
     * @param scopeName Name of the Scope.
     */
    void removeScope(const std::string& scopeName);

    /**
     * @brief Returns if there are no scopes referencing this DB.
     *
     * @return true No scopes are referencing this DB.
     * @return false Some scopes are referencing this DB.
     */
    bool emptyScopes(void);

    /**
     * @brief Get the list of scopes referencing this DB.
     *
     * @return std::vector<std::string> List of Scope names.
     */
    std::vector<std::string> getRefNames(void);

    /**
     * @brief Get the Ref Map object
     *
     * @return std::map<std::string, uint32_t> Map of DB names and their reference count.
     */
    std::map<std::string, uint32_t> getRefMap(void);

private:
    /**
     * @brief Basically a wrapper to std::map<std::string, int> with some helper functions.
     *
     */
    RefCounter m_scopeCounter;

    /**
     * @brief Mutex to protect the internal counter.
     *
     */
    std::shared_mutex m_mutex;
};

/**
 * @brief Collection of KVDB Handlers for a given DB and the Scopes referencing them.
 *
 */
class KVDBHandlerCollection : public IKVDBHandlerCollection
{
public:
    /**
     * @brief Registers a KVDB Handler and manage the reference counters and mappings.
     *
     * @param dbName Name of the DB.
     * @param scopeName Name of the Scope.
     *
     */
    void addKVDBHandler(const std::string& dbName, const std::string& scopeName) override;

    /**
     * @brief Removes a KVDB Handler given the provided DB name and scope name.
     * This automatically manage the reference counters and mappings.
     *
     * @param dbName Name of the DB.
     * @param scopeName Name of the Scope.
     *
     */
    void removeKVDBHandler(const std::string& dbName, const std::string& scopeName) override;

    /**
     * @brief Returns all the registered Database names.
     *
     * @return std::vector<std::string> List of DB names.
     *
     */
    std::vector<std::string> getDBNames(void);

    /**
     * @brief Get the Reference Count of scopes for a given DB.
     *
     * @param dbName Name of the DB.
     * @return std::map<std::string, uint32_t> Map of Scope names and their reference count.
     */
    std::map<std::string, uint32_t> getRefMap(const std::string& dbName);

private:
    /**
     * @brief Internal map holding DB names and their KVDBHandlerInstance with extra info.
     *
     */
    std::map<std::string, std::shared_ptr<KVDBHandlerInstance>> m_mapInstances;

    /**
     * @brief Mutex to protect the internal map.
     *
     */
    std::shared_mutex m_mutex;
};

} // namespace kvdbManager

#endif // _KVDB_HANDLER_COLLECTION_H
