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
#include <kvdbioc/types.hpp>

namespace kvdbioc
{
class DbInstance;

/**
 * Stable indirection point for hot swap (RCU-like).
 * Implements IReadOnlyKVDBHandler directly.
 *
 * Concurrency Model:
 * - Readers: lock-free atomic load of m_current (never block)
 * - Structural ops (swap/delete/build): serialized via m_structuralMutex
 * - State transitions: protected by m_structuralMutex
 * - Lifecycle: shared_ptr ensures no UAF (use-after-free)
 *
 * Key Design Principles:
 * 1. Readers never take m_structuralMutex → wait-free reads
 * 2. atomic load/store for m_current → RCU-like publication
 * 3. State machine prevents conflicting operations
 * 4. Old instances auto-delete when last reader releases shared_ptr
 */
class DbHandle : public IReadOnlyKVDBHandler
{
public:
    explicit DbHandle(const std::string& name)
        : m_name(std::move(name))
        , m_state(DbState::READY)
    {
    }

    // === IReadOnlyKVDBHandler interface ===

    /**
     * @brief Get the database name this handle is bound to.
     * @return Reference to the database name.
     */
    const std::string& name() const noexcept override { return m_name; }

    /**
     * @brief Get a single value from the database.
     * @param key Key to retrieve
     * @return Optional JSON value if key exists, std::nullopt otherwise
     * @throws std::runtime_error if no instance available or on read errors
     */
    std::optional<json::Json> get(std::string_view key) const override;

    /**
     * @brief Get multiple values from the database in a single operation.
     * @param keys Vector of keys to retrieve
     * @return Vector of optional JSON values, one per key
     * @throws std::runtime_error if no instance available or on read errors
     */
    std::vector<std::optional<json::Json>> multiGet(const std::vector<std::string_view>& keys) const override;

    /**
     * @brief Check if this handle has an active database instance.
     * @return true if instance is loaded, false otherwise
     */
    bool hasInstance() const noexcept override { return load() != nullptr; }

    // === Lifecycle Management (RCU-like, lock-free for readers) ===

    /**
     * @brief Atomically load current published instance (lock-free).
     * @return Shared pointer to current instance (nullptr if unpublished).
     * @note Thread-safe. Readers use this exclusively (no locks).
     */
    std::shared_ptr<DbInstance> load() const noexcept
    {
        return std::atomic_load_explicit(&m_current, std::memory_order_acquire);
    }

    /**
     * @brief Get instance (for hotSwap to copy).
     * @return Current instance.
     * @note Must be called under m_structuralMutex.
     */
    std::shared_ptr<DbInstance> getInstance() const noexcept { return load(); }

    /**
     * @brief Atomically publish new instance (RCU swap).
     * @param next New instance to publish (can be nullptr to unpublish).
     * @return Previous instance (for retirement/cleanup).
     * @note Must be called under m_structuralMutex.
     * @note Old instance auto-deletes when last reader releases it.
     */
    std::shared_ptr<DbInstance> exchange(std::shared_ptr<DbInstance> next) noexcept
    {
        return std::atomic_exchange_explicit(&m_current, next, std::memory_order_acq_rel);
    }

    // === State Machine (protected by structural mutex) ===

    /**
     * @brief Get current state.
     * @note Not thread-safe alone; use under m_structuralMutex for consistency.
     */
    DbState state() const noexcept { return m_state.load(std::memory_order_acquire); }

    /**
     * @brief Mark as DELETING (from READY).
     * @return true if transition successful, false if already DELETING.
     * @note Must be called under m_structuralMutex.
     */
    bool tryEnterDeleting() noexcept
    {
        DbState expected = DbState::READY;
        return m_state.compare_exchange_strong(expected, DbState::DELETING, std::memory_order_acq_rel);
    }

    /**
     * @brief Write a key-value pair to the database.
     * @param key The key to write.
     * @param value The value to write.
     * @throws std::runtime_error if no instance available or write fails.
     * @note Thread-safe. DB is open in r/w mode.
     */
    void putValue(std::string_view key, std::string_view value);

    // === Structural Operations Mutex (for Manager to use) ===

    /**
     * @brief Get mutex for serializing structural operations (add/swap/delete).
     * @return Reference to the per-DB structural mutex.
     * @note Manager uses this to serialize swap vs swap, delete vs add, etc.
     */
    std::mutex& structuralMutex() noexcept { return m_structuralMutex; }

private:
    std::string m_name;

    // === Published instance (RCU-like, lock-free for readers) ===
    std::shared_ptr<DbInstance> m_current; // Use atomic_load/store/exchange

    // === State machine (atomic for lock-free state checks) ===
    std::atomic<DbState> m_state;

    // === Structural operations mutex (not used by readers!) ===
    // Protects: state transitions, swap/delete coordination
    std::mutex m_structuralMutex;
};

} // namespace kvdbioc

#endif // _KVDBIOC_DBHANDLE_HPP
