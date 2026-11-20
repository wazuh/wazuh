// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _BUILDER_BUILDERS_STAGE_INDEXEROUTPUT_HPP
#define _BUILDER_BUILDERS_STAGE_INDEXEROUTPUT_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include <fmt/format.h>

#include <wiconnector/iwindexerconnector.hpp>

#include "builders/types.hpp"

namespace builder::builders
{

/**
 * @brief Rate limit of the "event not indexed" warning of one output operation.
 *
 * The first occurrence is logged, then at most one per window, carrying how many were suppressed since the previous
 * line. Occurrences suppressed after the last line are reported by pending(), which the operation calls on events it
 * does index, so the tail of a burst is not lost. Shared by every worker thread running the same operation.
 */
class NotIndexedLogThrottle
{
public:
    using Clock = std::chrono::steady_clock;

    /// Minimum time between two logged occurrences.
    static constexpr std::chrono::seconds WINDOW {60};

    /**
     * @brief Record one occurrence.
     *
     * @param now Time of the occurrence (a parameter so tests need not wait a window).
     * @return The number of occurrences suppressed since the previous logged one when this one must be logged,
     * std::nullopt when it must be suppressed.
     */
    std::optional<std::uint64_t> record(Clock::time_point now = Clock::now())
    {
        std::lock_guard lock {m_mutex};
        if (m_hasLogged && now - m_lastLog < WINDOW)
        {
            ++m_suppressed;
            m_pendingAt.store((m_lastLog + WINDOW).time_since_epoch().count(), std::memory_order_relaxed);
            return std::nullopt;
        }

        return report(now);
    }

    /**
     * @brief Occurrences suppressed and still unreported, once the window since the last line has elapsed.
     *
     * The mutex is taken only when a report is due.
     *
     * @param now Current time (a parameter so tests need not wait a window).
     * @return The number of suppressed occurrences to report now, std::nullopt when there is none or the window has
     * not elapsed.
     */
    std::optional<std::uint64_t> pending(Clock::time_point now)
    {
        if (now.time_since_epoch().count() < m_pendingAt.load(std::memory_order_relaxed))
        {
            return std::nullopt;
        }

        std::lock_guard lock {m_mutex};
        if (m_suppressed == 0 || now - m_lastLog < WINDOW)
        {
            return std::nullopt;
        }

        return report(now);
    }

    /**
     * @brief pending() at the current time, for the hot path: it runs on every indexed event.
     *
     * Costs one relaxed atomic load while nothing was suppressed, the steady state; the clock is read only otherwise.
     */
    std::optional<std::uint64_t> pending()
    {
        if (m_pendingAt.load(std::memory_order_relaxed) == NOTHING_PENDING)
        {
            return std::nullopt;
        }

        return pending(Clock::now());
    }

private:
    /// Takes the suppressed count and starts a new window. Call with m_mutex held.
    std::uint64_t report(Clock::time_point now)
    {
        const auto suppressed = m_suppressed;
        m_suppressed = 0;
        m_pendingAt.store(NOTHING_PENDING, std::memory_order_relaxed);
        m_lastLog = now;
        m_hasLogged = true;
        return suppressed;
    }

    std::mutex m_mutex;
    /// No suppressed occurrence awaits a report.
    static constexpr Clock::rep NOTHING_PENDING {std::numeric_limits<Clock::rep>::max()};

    /// When pending() must report (the end of the current window), as a Clock tick count; NOTHING_PENDING while
    /// nothing was suppressed. Written with m_mutex held, read without it.
    std::atomic<Clock::rep> m_pendingAt {NOTHING_PENDING};
    Clock::time_point m_lastLog {};
    bool m_hasLogged {false};
    std::uint64_t m_suppressed {0};
};

/**
 * @brief The log throttle of an output operation, shared by every build of that operation.
 *
 * The policy is built once per router worker, so one output exists as several operations with the same name:
 * they must share one throttle, or each worker would write its own line for the same cause. The throttle
 * lives while an operation holds it; a later build of the same name starts a new one.
 *
 * @param operationName Name of the output operation (write.output(wazuh-indexer/<index>)).
 * @return The throttle for that name.
 */
std::shared_ptr<NotIndexedLogThrottle> notIndexedLogThrottleFor(const std::string& operationName);

/**
 * @brief Build the indexer output stage.
 *
 * @param definition Json definition of the stage.
 * @param buildCtx Build context.
 * @param indexerPtr Indexer connector.
 * @return base::Expression The built stage expression.
 */
base::Expression indexerOutputBuilder(const json::Json& definition,
                                      const std::shared_ptr<const IBuildCtx>& buildCtx,
                                      const std::weak_ptr<wiconnector::IWIndexerConnector>& indexerPtr);

/**
 * @brief Get the Indexer Output Stage Builder.
 *
 * @param indexerPtr Indexer connector.
 * @return StageBuilder The indexer output builder.
 */
StageBuilder getIndexerOutputBuilder(const std::weak_ptr<wiconnector::IWIndexerConnector>& indexerPtr);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_STAGE_INDEXEROUTPUT_HPP
