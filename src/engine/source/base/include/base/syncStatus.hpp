#ifndef _BASE_SYNC_STATUS_HPP
#define _BASE_SYNC_STATUS_HPP

#include <stdexcept>
#include <string_view>

namespace base
{

/**
 * @brief Status of a synchronizable resource.
 */
enum class SyncStatus
{
    READY,    ///< Up to date, operational
    UPDATING, ///< Loading or updating
    FAILED    ///< Last synchronization attempt failed
};

/**
 * @brief Convert SyncStatus to its string representation.
 */
inline constexpr auto syncStatusToStr(SyncStatus s)
{
    switch (s)
    {
        case SyncStatus::READY: return "ready";
        case SyncStatus::UPDATING: return "updating";
        case SyncStatus::FAILED: return "failed";
        default: throw std::logic_error("Invalid SyncStatus");
    }
}

} // namespace base

#endif // _BASE_SYNC_STATUS_HPP
