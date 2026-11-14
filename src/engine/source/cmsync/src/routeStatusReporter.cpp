// SPDX-License-Identifier: AGPL-3.0-or-later
#include <utility>

#include <base/logging.hpp>

#include <cmsync/routeStatusReporter.hpp>

namespace cm::sync
{

RouteStatusReporter::RouteStatusReporter(std::function<bool()> hasEnabledRoutes, bool firstStart)
    : m_hasEnabledRoutes(std::move(hasEnabledRoutes))
    , m_firstStart(firstStart)
{
}

void RouteStatusReporter::report()
{
    // Queried outside the lock so that requestShutdown() never waits for the router.
    const bool shouldWarn = !m_hasEnabledRoutes();

    // The shutdown check, the state update and the log are atomic with respect to requestShutdown(). The reporter
    // is stopped before the router, so a router emptied by the shutdown is only seen once the flag is set.
    std::lock_guard lock {m_mutex};
    if (m_shutdownRequested)
    {
        return;
    }

    if (m_lastWarned == shouldWarn)
    {
        return;
    }
    m_lastWarned = shouldWarn;

    if (!shouldWarn)
    {
        LOG_INFO("[CMSync] Event processing is now active");
    }
    else if (m_firstStart)
    {
        LOG_INFO("[CMSync] No active routes available. Incoming events will be discarded "
                 "until content synchronization completes");
    }
    else
    {
        LOG_WARNING("[CMSync] No active routes available. Incoming events will be discarded "
                    "until content synchronization completes");
    }
}

void RouteStatusReporter::requestShutdown()
{
    std::lock_guard lock {m_mutex};
    m_shutdownRequested = true;
}

} // namespace cm::sync
