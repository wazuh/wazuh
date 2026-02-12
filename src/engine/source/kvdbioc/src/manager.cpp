#include <chrono>
#include <stdexcept>
#include <thread>

#include <fmt/format.h>
#include <rocksdb/convenience.h>
#include <rocksdb/db.h>
#include <rocksdb/options.h>

#include <base/error.hpp>
#include <base/json.hpp>
#include <base/logging.hpp>
#include <base/name.hpp>
#include <store/istore.hpp>

#include <kvdbioc/dbHandle.hpp>
#include <kvdbioc/dbInstance.hpp>
#include <kvdbioc/manager.hpp>

namespace
{

const base::Name KVDB_STORE_NAME {"kvdb-ioc/status/0"}; ///< Store document name for KVDB state
/**
 * @brief Represents the persisted state of a KVDB instance
 */
class DBState
{
private:
    std::string m_name;                ///< DB name
    std::string m_currentInstancePath; ///< Path to current active instance
    std::int64_t m_created;            ///< Creation timestamp (unix time)

    static constexpr std::string_view JPATH_NAME = "/name";                   ///< JSON path for DB name
    static constexpr std::string_view JPATH_INSTANCE_PATH = "/instance_path"; ///< JSON path for instance path
    static constexpr std::string_view JPATH_CREATED = "/created";             ///< JSON path for created timestamp

public:
    DBState() = delete;
    explicit DBState(std::string_view name)
        : m_name(name)
        , m_currentInstancePath()
        , m_created(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()))
    {
    }

    DBState(std::string_view name, std::string_view instancePath, std::int64_t created)
        : m_name(name)
        , m_currentInstancePath(instancePath)
        , m_created(created)
    {
    }

    /* Getters and Setters */
    const std::string& getName() const { return m_name; }
    const std::string& getInstancePath() const { return m_currentInstancePath; }
    std::int64_t getCreated() const { return m_created; }
    void setInstancePath(std::string_view path) { m_currentInstancePath = path; }
    void updateCreated() { m_created = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); }
    bool hasInstance() const { return !m_currentInstancePath.empty(); }

    /**
     * @brief Serialize the DBState to a JSON object
     */
    json::Json toJson() const
    {
        json::Json j {};
        j.setString(m_name, JPATH_NAME);
        j.setString(m_currentInstancePath, JPATH_INSTANCE_PATH);
        j.setInt64(m_created, JPATH_CREATED);
        return j;
    }

    /**
     * @brief Deserialize a DBState from a JSON object
     */
    static DBState fromJson(const json::Json& j)
    {
        auto optName = j.getString(JPATH_NAME);
        if (!optName.has_value() || optName->empty())
        {
            throw std::runtime_error("DBState::fromJson: Missing/empty name field");
        }

        auto optPath = j.getString(JPATH_INSTANCE_PATH);
        if (!optPath.has_value())
        {
            throw std::runtime_error("DBState::fromJson: Missing instance_path field");
        }

        auto optCreated = j.getInt64(JPATH_CREATED);
        if (!optCreated.has_value())
        {
            throw std::runtime_error("DBState::fromJson: Missing created field");
        }

        return {*optName, *optPath, *optCreated};
    }
};

} // anonymous namespace

namespace kvdbioc
{

KVDBManager::KVDBManager(std::filesystem::path rootDir, std::shared_ptr<store::IStore> storePtr)
    : m_root(std::move(rootDir))
    , m_store(std::move(storePtr))
{
    if (!m_store)
    {
        throw std::runtime_error("KVDBManager: store pointer cannot be null");
    }

    // Create root directory if it doesn't exist
    std::error_code ec;
    std::filesystem::create_directories(m_root, ec);
    if (ec)
    {
        throw std::runtime_error(fmt::format("Failed to create KVDB root directory: {}", ec.message()));
    }

    if (!m_store->existsDoc(KVDB_STORE_NAME))
    {
        return;
    }

    // Load persisted state if available
    loadStateFromStore();
}

std::filesystem::path KVDBManager::makeNextInstancePath(std::string_view name)
{
    // Use 4-char hex hash derived from current timestamp for uniqueness
    auto now = std::chrono::system_clock::now();
    auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();

    // Generate 4-char hex hash from timestamp
    uint16_t hash = static_cast<uint16_t>(nanos ^ (nanos >> 16) ^ (nanos >> 32) ^ (nanos >> 48));
    char buf[5];
    std::snprintf(buf, sizeof(buf), "%04x", hash);
    return m_root / std::string(name) / buf;
}

std::shared_ptr<DbHandle> KVDBManager::getOrCreateHandle(std::string_view dbName, bool createIfMissing)
{
    const std::string key(dbName);
    std::shared_ptr<DbHandle> handle;

    // Try read-only access first (concurrent with other readers)
    {
        std::shared_lock<std::shared_mutex> lk(m_registryMutex);
        auto it = m_handles.find(key);
        if (it != m_handles.end())
        {
            return it->second;
        }
    }

    // Not found - need exclusive lock to create
    if (createIfMissing)
    {
        std::unique_lock<std::shared_mutex> lk(m_registryMutex);
        // Double-check: another thread might have created it
        auto it = m_handles.find(key);
        if (it != m_handles.end())
        {
            return it->second;
        }

        // Create new handle
        handle = std::make_shared<DbHandle>(std::string(dbName));
        m_handles.emplace(key, handle);
        return handle;
    }

    return nullptr;
}

void KVDBManager::add(std::string_view name)
{
    const std::string key(name);

    // Check if handle already exists - add() is NOT idempotent
    {
        std::shared_lock<std::shared_mutex> lk(m_registryMutex);
        auto it = m_handles.find(key);
        if (it != m_handles.end())
        {
            throw std::runtime_error(fmt::format("KVDB '{}': already exists, cannot add again", key));
        }
    }

    // Create new handle (exclusive lock)
    std::shared_ptr<DbHandle> handle;
    {
        std::unique_lock<std::shared_mutex> lk(m_registryMutex);
        // Double-check: another thread might have created it
        auto it = m_handles.find(key);
        if (it != m_handles.end())
        {
            throw std::runtime_error(fmt::format("KVDB '{}': already exists, cannot add again", key));
        }

        handle = std::make_shared<DbHandle>(std::string(name));
        m_handles.emplace(key, handle);
    }

    // RAII guard to rollback if operation fails
    bool success = false;
    auto rollbackGuard = [&]()
    {
        if (!success)
        {
            // Remove handle from registry on failure
            std::unique_lock<std::shared_mutex> lk(m_registryMutex);
            m_handles.erase(key);
        }
    };
    std::shared_ptr<void> guard(nullptr, [&](void*) { rollbackGuard(); });

    // Lock structural operations for this DB (serializes add/swap/delete)
    std::lock_guard<std::mutex> structuralLock(handle->structuralMutex());

    // Check state - if DELETING, reject (shouldn't happen with new handle)
    auto currentState = handle->state();
    if (currentState == DbState::DELETING)
    {
        throw std::runtime_error(fmt::format("KVDB '{}': cannot add while being deleted", key));
    }

    // Create path for new version
    const auto instancePath = makeNextInstancePath(name);

    // Create directory
    std::error_code ec;
    std::filesystem::create_directories(instancePath, ec);
    if (ec)
    {
        throw std::runtime_error(fmt::format("KVDB '{}': failed to create directory: {}", key, ec.message()));
    }

    // Open new RocksDB in READ/WRITE mode
    rocksdb::Options options;
    options.create_if_missing = true;
    options.error_if_exists = true;

    rocksdb::DB* rawDb = nullptr;
    auto status = rocksdb::DB::Open(options, instancePath.string(), &rawDb);
    if (!status.ok())
    {
        throw std::runtime_error(fmt::format("KVDB '{}': failed to create RocksDB: {}", key, status.ToString()));
    }

    // Create instance and publish directly to m_current
    // DB is created in r/w mode - immediately queryable and writable
    auto newInstance = std::make_shared<DbInstance>(instancePath.string(), rawDb);
    handle->exchange(newInstance);

    // Persist state to store
    try
    {
        saveStateToStore();
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("[KVDB IOC] Failed to persist state after add: {}.", e.what());
    }

    // Mark as successful - prevent rollback
    success = true;

    // Opportunistic cleanup of retired instances
    tryCleanRetired();
}

bool KVDBManager::exists(std::string_view dbName) const
{
    std::shared_lock<std::shared_mutex> lk(m_registryMutex);
    return m_handles.find(std::string(dbName)) != m_handles.end();
}

bool KVDBManager::hasInstance(std::string_view dbName) const
{
    std::shared_lock<std::shared_mutex> lk(m_registryMutex);
    auto it = m_handles.find(std::string(dbName));
    if (it == m_handles.end())
    {
        return false;
    }
    return it->second->hasInstance();
}

std::optional<json::Json> KVDBManager::get(std::string_view dbName, std::string_view key) const
{
    const std::string db(dbName);

    // Get handle from registry (only need shared lock)
    std::shared_ptr<DbHandle> handle;
    {
        std::shared_lock<std::shared_mutex> lk(m_registryMutex);
        auto it = m_handles.find(db);
        if (it == m_handles.end())
        {
            throw std::runtime_error(fmt::format("KVDB '{}': not found, call add() first", db));
        }
        handle = it->second;
    }
    // Registry lock released - handle kept alive via shared_ptr

    // Delegate to handle (lock-free read via atomic load)
    try
    {
        return handle->get(key);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("KVDB '{}': {}", db, e.what()));
    }
}

std::vector<std::optional<json::Json>> KVDBManager::multiGet(std::string_view dbName,
                                                             const std::vector<std::string_view>& keys) const
{
    const std::string db(dbName);

    // Get handle from registry
    std::shared_ptr<DbHandle> handle;
    {
        std::shared_lock<std::shared_mutex> lk(m_registryMutex);
        auto it = m_handles.find(db);
        if (it == m_handles.end())
        {
            throw std::runtime_error(fmt::format("KVDB '{}': not found, call add() first", db));
        }
        handle = it->second;
    }

    // Delegate to handle (captures instance ONCE → consistent reads)
    try
    {
        return handle->multiGet(keys);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("KVDB '{}': {}", db, e.what()));
    }
}

void KVDBManager::put(std::string_view name, std::string_view key, std::string_view value)
{
    const std::string dbKey(name);

    // Get handle from registry
    std::shared_ptr<DbHandle> handle;
    {
        std::shared_lock<std::shared_mutex> lk(m_registryMutex);
        auto it = m_handles.find(dbKey);
        if (it == m_handles.end())
        {
            throw std::runtime_error(fmt::format("KVDB '{}': not found, call add() first", dbKey));
        }
        handle = it->second;
    }

    // Lock structural mutex to serialize with swap
    // Design decision: serialize puts with swap to avoid "write lost" during swap
    std::lock_guard<std::mutex> structuralLock(handle->structuralMutex());

    // Check state
    auto currentState = handle->state();
    if (currentState == DbState::DELETING)
    {
        throw std::runtime_error(fmt::format("KVDB '{}': cannot put while being deleted", dbKey));
    }

    // Perform write
    try
    {
        handle->putValue(key, value);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("KVDB '{}': {}", dbKey, e.what()));
    }
}

void KVDBManager::hotSwap(std::string_view sourceDb, std::string_view targetDb)
{
    const std::string sourceKey(sourceDb);
    const std::string targetKey(targetDb);

    // Prevent swapping to itself
    if (sourceKey == targetKey)
    {
        throw std::runtime_error(fmt::format("KVDB '{}': cannot hot-swap to itself", sourceKey));
    }

    // Get both handles from registry
    std::shared_ptr<DbHandle> targetHandle;
    std::shared_ptr<DbHandle> sourceHandle;
    {
        std::shared_lock<std::shared_mutex> lk(m_registryMutex);

        auto targetIt = m_handles.find(targetKey);
        if (targetIt == m_handles.end())
        {
            throw std::runtime_error(fmt::format("KVDB target '{}': not found, call add() first", targetKey));
        }
        targetHandle = targetIt->second;

        auto sourceIt = m_handles.find(sourceKey);
        if (sourceIt == m_handles.end())
        {
            throw std::runtime_error(fmt::format("KVDB source '{}': not found, call add() first", sourceKey));
        }
        sourceHandle = sourceIt->second;
    }

    // Lock BOTH structural mutexes atomically to avoid deadlock
    std::unique_lock<std::mutex> targetLock(targetHandle->structuralMutex(), std::defer_lock);
    std::unique_lock<std::mutex> sourceLock(sourceHandle->structuralMutex(), std::defer_lock);
    std::lock(targetLock, sourceLock);

    // Validate states
    if (targetHandle->state() == DbState::DELETING)
    {
        throw std::runtime_error(fmt::format("KVDB target '{}': cannot swap, database is being deleted", targetKey));
    }
    if (sourceHandle->state() == DbState::DELETING)
    {
        throw std::runtime_error(fmt::format("KVDB source '{}': cannot swap, database is being deleted", sourceKey));
    }

    // Source must have an instance
    if (!sourceHandle->hasInstance())
    {
        throw std::runtime_error(fmt::format("KVDB source '{}': no instance available for hot-swap", sourceKey));
    }

    // HOT-SWAP STRATEGY (zero-copy):
    // 1. Transfer instance ownership from source to target
    // 2. Directory stays at its original physical location (no move/copy)
    // 3. Target now owns and serves from source's directory
    // 4. Retire old target instance
    // This avoids filesystem operations and is instantaneous

    // Step 1: Atomically transfer instance from source to target
    auto sourceInstance = sourceHandle->exchange(nullptr);
    auto oldTargetInstance = targetHandle->exchange(sourceInstance);

    // Step 2: Enqueue old target instance for safe deletion
    // Capture path before moving the instance
    if (oldTargetInstance)
    {
        auto oldPath = oldTargetInstance->getPath();
        enqueueRetired(std::move(oldTargetInstance), std::move(oldPath));
        // oldTargetInstance is now null, our reference is released
        // GC will clean when all readers finish
    }

    // Remove source from registry since it no longer has an instance
    {
        std::unique_lock<std::shared_mutex> lk(m_registryMutex);
        m_handles.erase(sourceKey);
    }

    // Persist state
    try
    {
        saveStateToStore();
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("[KVDB IOC] Failed to persist state after hot-swap: {}.", e.what());
    }

    // Opportunistic cleanup of retired instances
    tryCleanRetired();
}

void KVDBManager::remove(std::string_view name)
{
    const std::string key(name);
    std::shared_ptr<DbHandle> handle;

    // Remove from registry (exclusive lock)
    {
        std::unique_lock<std::shared_mutex> lk(m_registryMutex);
        auto it = m_handles.find(key);
        if (it == m_handles.end())
        {
            throw std::runtime_error(fmt::format("KVDB '{}': not found", key));
        }
        handle = it->second;

        // Remove from registry immediately (new operations will fail)
        m_handles.erase(it);
    }
    // Registry lock released

    // Lock handle's structural mutex (serialize with swap/add)
    std::lock_guard<std::mutex> structuralLock(handle->structuralMutex());

    // Try to transition to DELETING state
    if (!handle->tryEnterDeleting())
    {
        throw std::runtime_error(fmt::format("KVDB '{}': already being deleted", key));
    }

    // Phase 1: Unpublish instance
    auto oldInstance = handle->exchange(nullptr);

    // Phase 2: Enqueue for safe deletion
    if (oldInstance)
    {
        enqueueRetired(oldInstance, oldInstance->getPath());
    }

    // Persist state to store
    try
    {
        saveStateToStore();
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("[KVDB IOC] Failed to persist state after removal: {}.", e.what());
    }

    // Opportunistic cleanup of retired instances
    tryCleanRetired();

    // Note: handle will be destroyed when this function returns (last shared_ptr)
    // Retired instances will be cleaned opportunistically in future operations
}

// === Retired Queue (Opportunistic Cleanup) ===

void KVDBManager::enqueueRetired(std::shared_ptr<const DbInstance> instance, std::filesystem::path path)
{
    // Mark this instance for deletion when destroyed
    const_cast<DbInstance*>(instance.get())->markForDeletion();

    std::lock_guard<std::mutex> lk(m_retiredMutex);
    m_retiredQueue.push_back({std::move(instance), std::move(path)});
    // Note: Will be cleaned opportunistically during next structural operation
}

size_t KVDBManager::tryCleanRetired()
{
    std::lock_guard<std::mutex> lk(m_retiredMutex);

    size_t cleaned = 0;
    auto it = m_retiredQueue.begin();

    while (it != m_retiredQueue.end())
    {
        // Check if only we hold the reference (use_count == 1)
        if (it->instance.use_count() == 1)
        {
            // Safe to delete: no readers remain
            // Destructor will close DB and delete directory
            it->instance.reset();

            // Remove from queue
            it = m_retiredQueue.erase(it);
            ++cleaned;
        }
        else
        {
            // Still in use by readers, skip for now
            ++it;
        }
    }

    return cleaned;
}

// === Persistence ===

void KVDBManager::loadStateFromStore()
{
    try
    {
        auto optDoc = m_store->readDoc(KVDB_STORE_NAME);
        if (base::isError(optDoc))
        {
            throw std::runtime_error(
                fmt::format("Failed to read KVDB state from store: {}", base::getError(optDoc).message));
        }

        const auto& j = base::getResponse(optDoc);
        auto optArray = j.getArray();
        if (!optArray.has_value())
        {
            throw std::runtime_error("Invalid KVDB state: expected JSON array");
        }

        for (const auto& jState : *optArray)
        {
            auto dbState = DBState::fromJson(jState);

            try
            {
                auto handle = std::make_shared<DbHandle>(dbState.getName());

                // Convert relative path to absolute
                auto absPath = m_root / dbState.getInstancePath();

                // Load instance if it exists on disk
                if (dbState.hasInstance() && std::filesystem::exists(absPath))
                {
                    // Open DB in READ/WRITE mode
                    rocksdb::DB* rawDb = nullptr;
                    auto status = rocksdb::DB::Open(rocksdb::Options {}, absPath.string(), &rawDb);
                    if (status.ok())
                    {
                        auto instance = std::make_shared<DbInstance>(absPath.string(), rawDb);
                        handle->exchange(instance);
                    }
                    else
                    {
                        LOG_WARNING("[KVDB IOC] Failed to open DB '{}': {}.", dbState.getName(), status.ToString());
                    }
                }

                // Add to registry
                m_handles.emplace(dbState.getName(), handle);
            }
            catch (const std::exception& e)
            {
                LOG_WARNING("[KVDB IOC] Failed to restore DB '{}' from '{}': {}.",
                            dbState.getName(),
                            dbState.getInstancePath(),
                            e.what());
            }
        }
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("[KVDB IOC] Failed to load persisted state: {}. Starting fresh.", e.what());
    }
}

void KVDBManager::saveStateToStore()
{
    json::Json j {};
    j.setArray();

    std::unordered_map<std::string, std::string> previousInstancePaths;
    try
    {
        auto optDoc = m_store->readDoc(KVDB_STORE_NAME);
        if (!base::isError(optDoc))
        {
            const auto& persisted = base::getResponse(optDoc);
            if (auto optArray = persisted.getArray(); optArray.has_value())
            {
                for (const auto& jState : *optArray)
                {
                    auto dbState = DBState::fromJson(jState);
                    if (dbState.hasInstance())
                    {
                        previousInstancePaths.emplace(dbState.getName(), dbState.getInstancePath());
                    }
                }
            }
        }
    }
    catch (const std::exception& e)
    {
        LOG_DEBUG("[KVDB IOC] Could not preload previous persisted paths: {}.", e.what());
    }

    {
        std::shared_lock<std::shared_mutex> lk(m_registryMutex);
        for (const auto& [name, handle] : m_handles)
        {
            DBState dbState(name);

            if (handle->hasInstance())
            {
                auto instance = handle->load();
                if (instance)
                {
                    auto absPath = std::filesystem::path(instance->path());
                    auto relPath = std::filesystem::relative(absPath, m_root);
                    dbState.setInstancePath(relPath.string());
                }
            }
            else
            {
                auto it = previousInstancePaths.find(name);
                if (it != previousInstancePaths.end())
                {
                    dbState.setInstancePath(it->second);
                }
            }

            dbState.updateCreated();
            j.appendJson(dbState.toJson());
        }
    }

    if (auto optErr = m_store->upsertDoc(KVDB_STORE_NAME, j); base::isError(optErr))
    {
        throw std::runtime_error(fmt::format("Failed to save KVDB state to store: {}", base::getError(optErr).message));
    }
}

} // namespace kvdbioc
