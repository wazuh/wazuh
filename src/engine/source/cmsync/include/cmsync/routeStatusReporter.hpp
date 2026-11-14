// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _CMSYNC_ROUTESTATUSREPORTER
#define _CMSYNC_ROUTESTATUSREPORTER

#include <functional>
#include <mutex>
#include <optional>

namespace cm::sync
{

/**
 * @brief Logs whether incoming events have an enabled route to be processed by.
 *
 * Reports only the transitions between "no enabled route" and "at least one enabled route"; the first report
 * always logs. While stopping, the router is torn down before the content synchronization stops, so the
 * reporter is stopped first and stays silent from then on.
 */
class RouteStatusReporter
{
public:
    /**
     * @brief Construct a new Route Status Reporter.
     *
     * @param hasEnabledRoutes Returns whether the router has at least one enabled route. Called without any
     * lock held by the reporter.
     * @param firstStart Whether this is the first start of the engine: the lack of routes is then expected and
     * logged as INFO instead of WARNING.
     */
    RouteStatusReporter(std::function<bool()> hasEnabledRoutes, bool firstStart);

    /**
     * @brief Log the route status if it changed since the last report.
     *
     * Not re-entrant: it is called from a single scheduled task. Does nothing once requestShutdown() has
     * returned, even if the call started before. Exceptions of the hasEnabledRoutes callback are propagated
     * and leave the reported state unchanged.
     */
    void report();

    /**
     * @brief Stop reporting.
     *
     * Idempotent, thread-safe. Once it returns, no report() call logs anything, including one in progress.
     */
    void requestShutdown();

private:
    std::function<bool()> m_hasEnabledRoutes; ///< Router status source
    const bool m_firstStart;                  ///< First start of the engine (no routes expected yet)

    std::mutex m_mutex;               ///< Serializes the shutdown request with the state update and the log
    bool m_shutdownRequested {false}; ///< Set by requestShutdown(), guarded by m_mutex
    std::optional<bool> m_lastWarned; ///< Last reported "no routes" state, nullopt before the first report
};

} // namespace cm::sync

#endif // _CMSYNC_ROUTESTATUSREPORTER
