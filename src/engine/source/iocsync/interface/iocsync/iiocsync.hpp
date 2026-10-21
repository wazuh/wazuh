// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef IOCSYNC_IIOCSYNC_HPP
#define IOCSYNC_IIOCSYNC_HPP

#include <string>
#include <string_view>
#include <vector>

#include <base/syncStatus.hpp>

namespace ioc::sync
{

/**
 * @brief Status information for a single IOC database type
 */
struct IocTypeStatus
{
    std::string type;                                  ///< IOC type (e.g., "connection", "url_domain", "hash_md5", ...)
    bool available {false};                            ///< Has a version available for processing
    base::SyncStatus status {base::SyncStatus::READY}; ///< Current state: ready, updating, or failed
    std::string hash;                                  ///< Last known data hash
    uint32_t lastSuccessfulUpdate {0};                 ///< Unix timestamp of last successful sync (0 if never)
};

class IIocSync
{
public:
    virtual ~IIocSync() = default;

    /**
     * @brief Run one content cycle per IOC type and record what came of it.
     *
     * A type whose remote hash moved is downloaded into a staging database and hot-swapped into
     * place, so readers switch to the new data atomically.
     */
    virtual void synchronize() = 0;

    /**
     * @brief Requests graceful shutdown for in-flight or future sync operations.
     */
    virtual void requestShutdown() = 0;

    /**
     * @brief Get the synchronization status of all configured IOC database types.
     *
     * @return Vector of IocTypeStatus, one per configured IOC type.
     */
    virtual std::vector<IocTypeStatus> getIocStatus() const = 0;
};

} // namespace ioc::sync

#endif // IOCSYNC_IIOCSYNC_HPP
