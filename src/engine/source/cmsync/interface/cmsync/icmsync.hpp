#ifndef _CMSYNC_ICMSYNC
#define _CMSYNC_ICMSYNC

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <base/syncStatus.hpp>

namespace cm::sync
{

/**
 * @brief Status information for a single content manager space
 */
struct SpaceStatus
{
    std::string name;                                  ///< Space name (e.g., "standard", "custom")
    bool available {false};                            ///< Has been synced at least once
    bool enabled {false};                              ///< Whether the space is enabled in the remote policy
    base::SyncStatus status {base::SyncStatus::READY}; ///< Current state: ready, running, or failed
    std::string hash;                                  ///< Last known content hash
    uint32_t lastSuccessfulUpdate {0};                 ///< Unix timestamp of last successful sync (0 if never)
};

class ICMSync
{
public:
    virtual ~ICMSync() = default;

    /**
     * @brief Request graceful shutdown of in-flight synchronization operations.
     * Idempotent and thread-safe. After calling this, ongoing synchronize() calls
     * will abort at the next checkpoint and return early.
     */
    virtual void requestShutdown() = 0;

    /**
     * @brief Get the synchronization status of all configured spaces.
     *
     * @return Vector of SpaceStatus, one per configured space.
     */
    virtual std::vector<SpaceStatus> getSpacesStatus() const = 0;

    /**
     * @brief Queue an out-of-band synchronization, off the scheduler.
     *
     * Non-blocking: the request is handed to the content manager's bounded lane and runs on one of
     * its workers, so this is safe to call from an API handler thread. A space whose content has
     * not moved costs one hash probe, and a space already syncing is left alone rather than run
     * twice.
     *
     * @param space Space to update. Empty updates every tracked space.
     */
    virtual void requestOnDemandUpdate(std::string_view space = {}) = 0;
};

} // namespace cm::sync

#endif // _CMSYNC_ICMSYNC
