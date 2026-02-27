#ifndef _KVDBIOC_MANAGER_HPP
#define _KVDBIOC_MANAGER_HPP

#include <atomic>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <rocksdb/db.h>

#include <kvdbioc/iManager.hpp>

namespace store
{
class IStore;
}

namespace kvdbioc
{
class DbHandle;
class DbInstance;

/**
 * KVDB Manager - Lifecycle and Hot-Swap Coordinator
 *
 * Concurrency Design:
 * 1. Registry access: shared_mutex (concurrent reads, exclusive writes)
 * 2. Structural ops per-DB: DbHandle::structuralMutex (swap, delete, add)
 * 3. Reads: lock-free via atomic shared_ptr in DbHandle
 * 4. Safe delete: two-phase with retired queue + opportunistic cleanup
 *
 * Key Guarantees:
 * - Readers never block on swap/delete
 * - No UAF: shared_ptr lifecycle management
 * - Swap is O(1) atomic exchange
 * - Delete only occurs when safe (no active readers)
 * - Cleanup happens opportunistically during structural operations
 */
class KVDBManager final : public IKVDBManager
{
public:
    KVDBManager(std::filesystem::path rootDir, std::shared_ptr<store::IStore> storePtr);
    ~KVDBManager() = default;

    void add(std::string_view dbName) override;

    bool exists(std::string_view dbName) const noexcept override;

    void put(std::string_view dbName, std::string_view key, std::string_view value) override;

    void hotSwap(std::string_view sourceDb, std::string_view targetDb) override;

    std::optional<json::Json> get(std::string_view dbName, std::string_view key) const override;

    std::vector<std::optional<json::Json>> multiGet(std::string_view dbName,
                                                    const std::vector<std::string_view>& keys) const override;

    void remove(std::string_view dbName) override;

private:
    /**
     * @brief Get or create handle (with idempotency for add).
     * @param dbName Database name.
     * @param createIfMissing If true, create handle if not exists.
     * @return Shared pointer to handle, or nullptr if not found and !createIfMissing.
     * @note Thread-safe with m_registryMutex.
     */
    std::shared_ptr<DbHandle> getOrCreateHandle(std::string_view dbName, bool createIfMissing);

    /**
     * @brief Generate next version path for DB instance.
     */
    std::filesystem::path makeNextInstancePath(std::string_view dbName);

    /**
     * @brief Load persisted state from store.
     * @throw std::runtime_error if state exists but is corrupted.
     */
    void loadStateFromStore();

    /**
     * @brief Save current state to store.
     * @throw std::runtime_error if save operation fails.
     */
    void saveStateToStore();

    // === Retired Queue (opportunistic cleanup, no GC thread) ===

    struct RetiredInstance
    {
        std::shared_ptr<const DbInstance> instance;
        std::filesystem::path path; // For disk cleanup
    };

    /**
     * @brief Enqueue retired instance for safe deletion.
     * @note Thread-safe with m_retiredMutex.
     */
    void enqueueRetired(std::shared_ptr<const DbInstance> instance, std::filesystem::path path);

    /**
     * @brief Attempt to clean retired instances with no remaining readers.
     * Called opportunistically during structural operations.
     * @return Number of instances cleaned.
     * @note Thread-safe with m_retiredMutex.
     */
    size_t tryCleanRetired();

    // === Data Members ===

    std::filesystem::path m_root;
    std::shared_ptr<store::IStore> m_store;

    // Registry: name → DbHandle
    mutable std::shared_mutex m_registryMutex; // Allows concurrent readers
    std::unordered_map<std::string, std::shared_ptr<DbHandle>> m_handles;

    // Retired queue: instances waiting for safe deletion
    // Cleaned opportunistically during structural operations
    std::mutex m_retiredMutex;
    std::deque<RetiredInstance> m_retiredQueue;
};

} // namespace kvdbioc

#endif // _KVDBIOC_MANAGER_HPP
