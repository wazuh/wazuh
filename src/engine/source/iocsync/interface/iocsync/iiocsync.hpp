#ifndef IOCSYNC_IIOCSYNC_HPP
#define IOCSYNC_IIOCSYNC_HPP

#include <string>
#include <vector>


namespace ioc::sync
{

class IIocSync {
public:
    virtual ~IIocSync() = default;

    /**
     * @brief Perform synchronization of all configured IOC databases
     *
     * This method iterates through all IOC types configured for synchronization,
     * checking for updates in the remote indexer. If changes are detected, it
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
};

} // namespace ioc::sync

#endif // IOCSYNC_IIOCSYNC_HPP
