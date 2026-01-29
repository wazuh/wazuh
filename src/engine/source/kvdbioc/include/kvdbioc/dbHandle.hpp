#ifndef _KVDBIOC_DBHANDLE_HPP
#define _KVDBIOC_DBHANDLE_HPP

#include <atomic>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include <rocksdb/db.h>

#include <kvdbioc/iReadOnlyHandler.hpp>

namespace kvdb
{
class DbInstance;

struct BuildState
{
    std::filesystem::path dbPath;
    std::unique_ptr<rocksdb::DB> db;
};

/**
 * Stable indirection point for hot swap (RCU-like).
 * Implements IReadOnlyKVDBHandler directly.
 * Also holds optional build state during add->put->hotSwap cycle.
 * C++17: use atomic_load/atomic_store free functions on shared_ptr storage.
 */
class DbHandle : public IReadOnlyKVDBHandler
{
public:
    explicit DbHandle(DbName name)
        : m_name(std::move(name))
    {
    }

    // IReadOnlyKVDBHandler interface
    const DbName& name() const noexcept override { return m_name; }

    json::Json get(std::string_view key) const override;

    std::shared_ptr<const DbInstance> load() const noexcept override { return std::atomic_load(&m_current); }

    void store(std::shared_ptr<const DbInstance> next) noexcept override { std::atomic_store(&m_current, next); }

    bool hasInstance() const noexcept override { return load() != nullptr; }

    // Build state management (thread-safe, internal mutex)
    // These methods are safe to call concurrently

    /**
     * @brief Check if there is a build in progress.
     * @return true if a build is currently in progress, false otherwise.
     * @note Thread-safe.
     */
    bool hasBuild() const;

    /**
     * @brief Get reference to the current build state.
     * @return Reference to the BuildState.
     * @throws std::runtime_error if no build is in progress.
     * @note Thread-safe. Caller must hold the reference while using it.
     */
    BuildState& getBuild();

    /**
     * @brief Start a new build process.
     * @param state The build state containing DB handle and path.
     * @throws std::runtime_error if a build is already in progress.
     * @note Thread-safe.
     */
    void startBuild(BuildState state);

    /**
     * @brief Extract the build state, marking build as complete.
     * @return The extracted BuildState.
     * @throws std::runtime_error if no build is in progress.
     * @note Thread-safe. After extraction, no build is in progress.
     */
    BuildState extractBuild();

    /**
     * @brief Write a key-value pair to the database being built.
     * @param key The key to write.
     * @param value The value to write.
     * @throws std::runtime_error if no build is in progress or write fails.
     * @note Thread-safe. Serializes concurrent writes to RocksDB.
     */
    void putValue(std::string_view key, std::string_view value);

private:
    DbName m_name;
    // Read-only access: lock-free atomic operations
    std::shared_ptr<const DbInstance> m_current;
    // Build state: protected by mutex (doesn't affect reads)
    mutable std::mutex m_buildMutex;
    std::optional<BuildState> m_buildState;
};

} // namespace kvdb

#endif // _KVDBIOC_DBHANDLE_HPP
