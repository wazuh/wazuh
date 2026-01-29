#include <chrono>
#include <stdexcept>

#include <fmt/format.h>
#include <rocksdb/db.h>
#include <rocksdb/options.h>

#include <base/error.hpp>

#include <kvdbioc/dbHandle.hpp>
#include <kvdbioc/dbInstance.hpp>
#include <kvdbioc/manager.hpp>

namespace kvdb
{

KVDBManager::KVDBManager(std::filesystem::path rootDir)
    : m_root(std::move(rootDir))
{
}

KVDBManager::~KVDBManager() = default;

std::filesystem::path KVDBManager::makeNextInstancePath(std::string_view name)
{
    // Use timestamp for unique version directory
    auto now = std::chrono::system_clock::now();
    auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();

    char buf[32];
    std::snprintf(buf, sizeof(buf), "v-%019lld", static_cast<long long>(nanos));
    return m_root / std::string(name) / buf;
}

void KVDBManager::add(std::string_view name)
{
    const std::string key(name);
    std::shared_ptr<DbHandle> handle;

    // Get or create handle (only need manager lock for registry access)
    {
        std::unique_lock<std::shared_mutex> lk(m_mutex);
        auto it = m_handles.find(key);
        if (it != m_handles.end())
        {
            handle = it->second;
        }
        else
        {
            handle = std::make_shared<DbHandle>(key);
            m_handles.emplace(key, handle);
        }
    }
    // Manager lock released - other operations can proceed

    // Create path for new version
    const auto instancePath = makeNextInstancePath(name);

    // Create directory
    std::error_code ec;
    std::filesystem::create_directories(instancePath, ec);
    if (ec)
    {
        throw std::runtime_error(fmt::format("KVDB '{}': failed to create directory: {}", key, ec.message()));
    }

    // Open new RocksDB for writing
    rocksdb::Options options;
    options.create_if_missing = true;
    options.error_if_exists = true;

    rocksdb::DB* rawDb = nullptr;
    auto status = rocksdb::DB::Open(options, instancePath.string(), &rawDb);
    if (!status.ok())
    {
        throw std::runtime_error(fmt::format("KVDB '{}': failed to create RocksDB: {}", key, status.ToString()));
    }

    // Store build state in handle (handle's mutex protects this)
    BuildState buildState;
    buildState.dbPath = instancePath;
    buildState.db.reset(rawDb);

    // startBuild() throws if build already in progress (thread-safe)
    handle->startBuild(std::move(buildState));
}

std::shared_ptr<IReadOnlyKVDBHandler> KVDBManager::openReadOnly(std::string_view name)
{
    const std::string key(name);

    // Try read-only access first (fast path - doesn't block other readers)
    {
        std::shared_lock<std::shared_mutex> lk(m_mutex);
        auto it = m_handles.find(key);
        if (it != m_handles.end())
        {
            return it->second;
        }
    }

    // Need to create new handle (slow path - exclusive lock)
    {
        std::unique_lock<std::shared_mutex> lk(m_mutex);
        // Double-check: another thread might have created it
        auto it = m_handles.find(key);
        if (it != m_handles.end())
        {
            return it->second;
        }

        auto h = std::make_shared<DbHandle>(std::string(name));
        m_handles.emplace(key, h);
        // Return the shared DbHandle directly
        // All handlers for same DB share the same DbHandle for hot-swap to work atomically
        return h;
    }
}

void KVDBManager::put(std::string_view name, std::string_view key, std::string_view value)
{
    const std::string dbKey(name);
    std::shared_ptr<DbHandle> handle;

    // Get handle from registry (only need manager lock for this)
    {
        std::shared_lock<std::shared_mutex> lk(m_mutex);
        auto it = m_handles.find(dbKey);
        if (it == m_handles.end())
        {
            throw std::runtime_error(fmt::format("KVDB '{}': not found, call add() first", dbKey));
        }
        handle = it->second;
    }
    // Manager lock released

    // putValue() is thread-safe and handles locking internally
    try
    {
        handle->putValue(key, value);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("KVDB '{}': {}", dbKey, e.what()));
    }
}

void KVDBManager::hotSwap(std::string_view name)
{
    const std::string key(name);
    std::shared_ptr<DbHandle> handle;

    // Get handle from registry (only need manager lock for this)
    {
        std::shared_lock<std::shared_mutex> lk(m_mutex);
        auto it = m_handles.find(key);
        if (it == m_handles.end())
        {
            throw std::runtime_error(fmt::format("KVDB '{}': not found, call add() first", key));
        }
        handle = it->second;
    }
    // Manager lock released

    // extractBuild() throws if no build in progress (thread-safe via handle's mutex)
    BuildState buildState = handle->extractBuild();
    buildState.db.reset();
    // TODO: Commented section for viewing RC due to rocksdb threads that have not yet been closed
    // Properly close the writable DB:
    // 1. Flush all memtables to disk
    // 2. Wait for background jobs to complete
    // 3. Then close the DB handle
    // if (buildState.db)
    // {
    //     rocksdb::FlushOptions flush_opts;
    //     flush_opts.wait = true;  // Wait for flush to complete
    //     auto status = buildState.db->Flush(flush_opts);
    //     if (!status.ok())
    //     {
    //         // Log warning but continue - data should be recoverable
    //     }

    //     // Close DB (this waits for background jobs to complete)
    //     buildState.db.reset();
    // }

    // Open as read-only DbInstance
    auto instance = std::make_shared<const DbInstance>(buildState.dbPath);

    // Perform hot-swap (atomic, doesn't block reads)
    handle->store(instance);
}

void KVDBManager::remove(std::string_view name)
{
    std::shared_ptr<DbHandle> handle;
    {
        std::unique_lock<std::shared_mutex> lk(m_mutex);
        auto it = m_handles.find(std::string(name));
        if (it == m_handles.end())
        {
            throw std::runtime_error(fmt::format("KVDB '{}': not found", std::string(name)));
        }
        handle = it->second;

        // Remove from registry first
        m_handles.erase(it);
    }

    // If someone else holds the handle (handlers), forbid delete.
    // After removing from map, use_count == 1 means only our local copy exists (no handlers)
    // use_count > 1 means at least one read-only handler still holds a reference
    if (handle.use_count() > 1)
    {
        // Restore the handle to the map since we can't delete
        std::unique_lock<std::shared_mutex> lk(m_mutex);
        m_handles[std::string(name)] = handle;
        throw std::runtime_error(fmt::format("KVDB '{}': cannot delete while in use", std::string(name)));
    }

    // Remove on-disk directory (best effort)
    std::error_code ec;
    std::filesystem::remove_all(m_root / std::string(name), ec);
    if (ec)
    {
        throw std::runtime_error(fmt::format("KVDB '{}': delete failed: {}", std::string(name), ec.message()));
    }
}

} // namespace kvdb
