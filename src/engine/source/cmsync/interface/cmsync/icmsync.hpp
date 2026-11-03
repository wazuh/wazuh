// SPDX-License-Identifier: AGPL-3.0-or-later
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
    bool available {false};                            ///< A route serves the space
    bool enabled {false};                              ///< Whether the space is enabled in the remote policy
    base::SyncStatus status {base::SyncStatus::READY}; ///< Current state: ready, updating, or failed
    std::string hash;                                  ///< Hash of the deployed ruleset
    uint32_t lastSuccessfulUpdate {0};                 ///< Unix timestamp of last successful sync (0 if never)
};

class ICMSync
{
public:
    virtual ~ICMSync() = default;

    /**
     * @brief Run one content cycle per tracked space and record what came of it.
     *
     * @return true if a space ended the run without a route although its policy is not known to be disabled
     *         (indexer failure, content not published or consumer not ready yet), so an earlier run is worthwhile.
     */
    virtual bool synchronize() = 0;

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
};

} // namespace cm::sync

#endif // _CMSYNC_ICMSYNC
