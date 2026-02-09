#ifndef _KVDBIOC_IMANAGER_HPP
#define _KVDBIOC_IMANAGER_HPP

#include <memory>
#include <string_view>
#include <vector>

#include <base/error.hpp>

#include <kvdbioc/iReadOnlyHandler.hpp>
#include <kvdbioc/types.hpp>

namespace kvdbioc
{
/**
 * KVDB Manager Interface
 *
 * Responsibilities:
 * - Manage KVDB lifecycle: init, publish (hot-swap), delete
 * - Provide read-only handlers that follow hot-swaps transparently
 * - Prevent delete while handlers are in use
 *
 * IOC Use Case Flow:
 * 1. initDb("ioc-ips") - Create empty DB handle at startup
 * 2. openReadOnly("ioc-ips") - IOC threads get handlers (work even if DB empty)
 * 3. Scheduler task builds new DB instance from indexer data
 * 4. publishDb("ioc-ips", path) - Hot-swap atomically, handlers see new data
 * 5. IOC threads continue working seamlessly during swap
 */
class IKVDBManager
{
public:
    virtual ~IKVDBManager() = default;

    /**
     * @brief Add/initialize a new database.
     * Creates a new DB in read/write mode, immediately available for reads and writes.
     *
     * @param dbName DB identifier
     * @throws std::runtime_error if DB already exists
     *
     * Use case: IOC sync creates new DB to populate with indexer data.
     */
    virtual void add(std::string_view dbName) = 0;

    /**
     * @brief Add a key-value pair to the DB.
     *
     * @param dbName DB identifier
     * @param key Key string
     * @param value JSON value as string
     * @throws std::runtime_error if DB doesn't exist or on RocksDB errors
     *
     * Use case: IOC sync adds entries incrementally as chunks arrive from indexer.
     * Example: manager->put("ioc-ips", "ip:192.168.1.1", R"({"threat":"malware"})");
     */
    virtual void put(std::string_view dbName, std::string_view key, std::string_view value) = 0;

    /**
     * @brief Perform atomic hot-swap: move instance from source to target.
     * After swap, source DB is invalidated and removed from registry.
     * Target receives the source's instance and becomes queryable.
     *
     * @param sourceDb Source DB identifier (will be invalidated)
     * @param targetDb Target DB identifier
     * @throws std::runtime_error if source/target don't exist or on errors
     *
     * Use case: IOC sync finishes populating staging DB, commits to production.
     */
    virtual void hotSwap(std::string_view sourceDb, std::string_view targetDb) = 0;

    /**
     * @brief Get a single value from the database.
     *
     * @param dbName Database identifier
     * @param key Key to retrieve
     * @return Optional JSON value if key exists, std::nullopt otherwise
     * @throws std::runtime_error if DB doesn't exist or on RocksDB errors
     *
     * Use case: Query IOC database for threat intelligence lookup.
     */
    virtual std::optional<json::Json> get(std::string_view dbName, std::string_view key) const = 0;

    /**
     * @brief Get multiple values from the database in a single operation.
     *
     * @param dbName Database identifier
     * @param keys Vector of keys to retrieve
     * @return Vector of optional JSON values, one per key. std::nullopt for non-existent keys.
     * @throws std::runtime_error if DB doesn't exist or on RocksDB errors
     *
     * Use case: Batch lookup for multiple IPs/domains in IOC database.
     */
    virtual std::vector<std::optional<json::Json>> multiGet(std::string_view dbName,
                                                              const std::vector<std::string_view>& keys) const = 0;

    /**
     * @brief Remove database and all its versions.
     *
     * @param dbName Database identifier to remove
     * @throws std::runtime_error if DB doesn't exist or is still in use
     *
     * Use case: Cleanup old/unused databases from the system.
     */
    virtual void remove(std::string_view dbName) = 0;
};
} // namespace kvdbioc

#endif // _KVDBIOC_IMANAGER_HPP
