#ifndef _BASE_STATUS_SNAPSHOT_HPP
#define _BASE_STATUS_SNAPSHOT_HPP

#include <atomic>
#include <memory>
#include <string_view>
#include <vector>

namespace base
{

/**
 * @brief Lock-free, RCU-style snapshot of a list of status entries.
 *
 * A single writer (the sync thread) rebuilds the whole vector and publishes it
 * atomically with store(); readers obtain the current immutable vector with load()
 * (wait-free). Publishing swaps an immutable shared_ptr, so readers never see a
 * half-updated vector and never block.
 *
 * This is the single mechanism used to report synchronization status across the
 * engine (content-manager spaces, IOC databases and geo databases). It satisfies
 * "status collection must be thread-safe and must not block event processing":
 * no mutex is taken on either the read or the publish path.
 *
 * @tparam T Copyable status entry type (e.g. SpaceStatus, IocTypeStatus, GeoDbStatus).
 */
template<typename T>
class StatusSnapshot
{
public:
    using Vector = std::vector<T>;
    using ConstVectorPtr = std::shared_ptr<const Vector>;

    StatusSnapshot()
        : m_data(std::make_shared<const Vector>())
    {
    }

    /**
     * @brief Wait-free read of the current immutable snapshot.
     *
     * @return Shared pointer to an immutable vector; safe to read without locking.
     */
    ConstVectorPtr load() const { return std::atomic_load(&m_data); }

    /**
     * @brief Atomically publish a fully-rebuilt snapshot.
     *
     * The publisher recomputes the whole vector and hands it over; this swaps in a new
     * immutable copy. Readers calling load() either see the previous or the new vector,
     * never a partial state. Intended for a single writer (the sync thread).
     *
     * @param next The new snapshot contents.
     */
    void store(Vector next) { std::atomic_store(&m_data, std::make_shared<const Vector>(std::move(next))); }

private:
    ConstVectorPtr m_data;
};

} // namespace base

#endif // _BASE_STATUS_SNAPSHOT_HPP
