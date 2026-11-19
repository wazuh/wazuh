// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _BUILDER_BUILDERS_STAGE_INDEXEROUTPUT_HPP
#define _BUILDER_BUILDERS_STAGE_INDEXEROUTPUT_HPP

#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
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
 * line. Shared by every worker thread running the same operation.
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
            return std::nullopt;
        }

        const auto suppressed = m_suppressed;
        m_suppressed = 0;
        m_lastLog = now;
        m_hasLogged = true;
        return suppressed;
    }

private:
    std::mutex m_mutex;
    Clock::time_point m_lastLog {};
    bool m_hasLogged {false};
    std::uint64_t m_suppressed {0};
};

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
