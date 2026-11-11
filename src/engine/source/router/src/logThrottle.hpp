// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef ROUTER_LOG_THROTTLE_HPP
#define ROUTER_LOG_THROTTLE_HPP

#include <chrono>
#include <cstdint>
#include <optional>

namespace router
{

/**
 * @brief Decides when a repeated condition deserves a log line.
 *
 * The first occurrence is logged, then at most one occurrence per window; the logged occurrence carries how many
 * were suppressed since the previous line, so no occurrence goes unreported once the condition repeats.
 *
 * Not thread-safe: each worker thread owns its instance.
 */
class LogThrottle
{
public:
    using Clock = std::chrono::steady_clock;

    explicit LogThrottle(Clock::duration window)
        : m_window(window)
    {
    }

    /**
     * @brief Record one occurrence.
     *
     * @param now Time of the occurrence.
     * @return The number of occurrences suppressed since the previous logged one when this occurrence must be
     * logged, std::nullopt when it must be suppressed.
     */
    std::optional<std::uint64_t> record(Clock::time_point now)
    {
        if (m_hasLogged && now - m_lastLog < m_window)
        {
            ++m_suppressed;
            return std::nullopt;
        }

        const auto suppressed = m_suppressed;
        m_suppressed = 0;
        m_lastLog = now;
        m_hasLogged = true;
        return suppressed;
    }

private:
    Clock::duration m_window;       ///< Minimum time between two logged occurrences
    Clock::time_point m_lastLog {}; ///< Time of the last logged occurrence
    bool m_hasLogged {false};       ///< Whether any occurrence was logged yet
    std::uint64_t m_suppressed {0}; ///< Occurrences suppressed since the last logged one
};

} // namespace router

#endif // ROUTER_LOG_THROTTLE_HPP
