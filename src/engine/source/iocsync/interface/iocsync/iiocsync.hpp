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
    base::SyncStatus status {base::SyncStatus::READY}; ///< Current state: ready, running, or failed
    std::string hash;                                  ///< Last known data hash
    uint32_t lastSuccessfulUpdate {0};                 ///< Unix timestamp of last successful sync (0 if never)
};

class IIocSync
{
public:
    virtual ~IIocSync() = default;

    /**
     * @brief Perform synchronization of all configured IOC databases
     *
     * This method iterates through all IOC types configured for synchronization,
     * checking for updates in the wazuh-indexer. If changes are detected, it
     * downloads the updated IOCs, creates a new database, and performs an atomic
     * hot-swap to ensure readers transparently switch to the new data.
     *
     * Key operations:
     * - Compare local hash vs remote hash for each IOC type
     * - Download full database only if hash has changed
     * - Atomic hot-swap of the active database
     * - Safe cleanup of old database versions
     *
     * @throws std::runtime_error if any step of the synchronization process fails
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

    /**
     * @brief Queue an out-of-band synchronization, off the scheduler.
     *
     * Non-blocking: the request is handed to the content manager's bounded lane and runs on one of
     * its workers, so this is safe to call from an API handler thread. A type whose hash has not
     * moved costs one probe, and a type already syncing is left alone rather than run twice.
     *
     * @param iocType IOC type to update. Empty updates every tracked type.
     */
    virtual void requestOnDemandUpdate(std::string_view iocType = {}) = 0;
};

} // namespace ioc::sync

#endif // IOCSYNC_IIOCSYNC_HPP
