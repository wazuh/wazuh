#ifndef _KVDBIOC_IMANAGER_HPP
#define _KVDBIOC_IMANAGER_HPP

#include <memory>
#include <string_view>
#include <vector>

#include <base/error.hpp>

#include <kvdbioc/iReadOnlyHandler.hpp>
#include <kvdbioc/types.hpp>

namespace kvdb
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
     * @brief Add/initialize a DB and start building it.
     * If DB already exists, starts a new version build.
     * If DB doesn't exist, initializes handle and starts build.
     *
     * @param name DB identifier
     * @throws std::runtime_error if a build is already in progress
     *
     * Use case: IOC sync starts building new version from indexer data.
     */
    virtual void add(std::string_view name) = 0;

    /**
     * @brief Add a key-value pair to the DB currently being built.
     *
     * @param name DB identifier
     * @param key Key string
     * @param value JSON value as string
     * @throws std::runtime_error if no build in progress or on RocksDB errors
     *
     * Use case: IOC sync adds entries incrementally as chunks arrive from indexer.
     * Example: manager->put("ioc-ips", "ip:192.168.1.1", R"({"threat":"malware"})");
     */
    virtual void put(std::string_view name, std::string_view key, std::string_view value) = 0;

    /**
     * @brief Finalize build and perform atomic hot-swap.
     * Closes the staging DB, opens as immutable instance, and swaps atomically.
     * Existing handlers immediately see new data.
     *
     * @param name DB identifier
     * @throws std::runtime_error if no build in progress or on errors
     *
     * Use case: IOC sync finishes receiving all data, commits to make it live.
     */
    virtual void hotSwap(std::string_view name) = 0;

    /**
     * @brief Obtain a read-only handler for a DB.
     * Handler follows hot swaps transparently.
     * Can be called even if DB has no instance yet (get() will throw until hotSwap).
     * Returns shared_ptr because all handlers for same DB share the same DbHandle.
     */
    virtual std::shared_ptr<IReadOnlyKVDBHandler> openReadOnly(std::string_view name) = 0;

    /**
     * @brief Remove DB and all its versions.
     * Must fail if there are live handlers for this DB.
     */
    virtual void remove(std::string_view name) = 0;
};
} // namespace kvdb

#endif // _KVDBIOC_IMANAGER_HPP
