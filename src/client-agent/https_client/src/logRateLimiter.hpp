/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 25, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_LOG_RATE_LIMITER_HPP
#define _HC_LOG_RATE_LIMITER_HPP

#include "sysSeams.hpp"

#include <chrono>
#include <cstdint>

/**
 * @brief Rate-limits a repeated log line to one emission per window, aggregating the
 *        occurrences it suppressed so the emitted line can report them.
 *
 * Same shape/semantics as remoted's own `remoted::common::LogThrottle`
 * (remoted_module/src/common/logThrottle.hpp): the first occurrence always emits, then at
 * most one per window, carrying the suppressed count. Deliberately NOT that class reused
 * directly: it is hard-wired to std::chrono::steady_clock, which a control-thread caller
 * cannot swap for a FakeClock in a unit test, and pulling a manager-side header into an
 * agent library is the wrong direction of dependency.
 *
 * Built on IClock::steadyNow() instead, and deliberately NOT atomic: every caller in this
 * module (ControlStream::updateProducerPause()) runs on the control thread only, so a plain
 * counter is enough. A shared/multi-threaded use (e.g. a single instance called from more
 * than one HTTPS stream) would need LogThrottle's atomic approach instead.
 */
class LogRateLimiter final
{
    public:
        /// One window per condition. 90 s matches LogThrottle::kDefaultWindow's precedent.
        static constexpr std::chrono::nanoseconds kDefaultWindow {std::chrono::seconds {90}};

        /// The same window in whole seconds, for rendering "in the last N s" in the log
        /// message. Kept next to the window itself so the text can never drift from it.
        static constexpr int kDefaultWindowSeconds
        {
            static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(kDefaultWindow).count())};

        explicit LogRateLimiter(IClock& clock, std::chrono::nanoseconds window = kDefaultWindow) noexcept
            : m_clock(clock)
            , m_window(window)
        {
        }

        LogRateLimiter(const LogRateLimiter&) = delete;
        LogRateLimiter& operator=(const LogRateLimiter&) = delete;

        /// @brief What the caller should do about this occurrence.
        struct Decision
        {
            bool emit {false};            ///< True for exactly one caller per window.
            std::uint64_t suppressed {0}; ///< Occurrences NOT logged since the last emission.
            std::uint64_t total {0};      ///< suppressed + 1: how many occurrences this line stands for.

            /// @brief Lets a Decision be used directly in an `if`.
            explicit operator bool() const noexcept
            {
                return emit;
            }
        };

        /**
         * @brief Count this occurrence and decide whether the caller should log it now.
         *
         * The FIRST occurrence since construction or the last reset() always emits (total ==
         * 1): an operator must not have to wait a whole window for the first sign of trouble.
         * Afterwards, at most one caller per window gets `emit == true`, carrying the full
         * count of occurrences its line represents.
         */
        Decision record() noexcept
        {
            ++m_pending;

            const auto now = m_clock.steadyNow();

            if (m_hasEmitted && (now - m_lastEmit) < m_window)
            {
                return {};
            }

            m_hasEmitted = true;
            m_lastEmit = now;

            const auto total = m_pending;
            m_pending = 0;
            return {true, total > 0 ? total - 1 : 0, total};
        }

        /// Clears the window state: the NEXT record() emits immediately, regardless of how
        /// recently the last one did. Called on recovery, so a fresh incident later is
        /// reported at once rather than possibly landing inside the old incident's tail
        /// window.
        void reset() noexcept
        {
            m_hasEmitted = false;
            m_pending = 0;
        }

    private:
        IClock& m_clock;
        const std::chrono::nanoseconds m_window;
        bool m_hasEmitted {false};
        std::chrono::steady_clock::time_point m_lastEmit {};
        std::uint64_t m_pending {0};
};

#endif // _HC_LOG_RATE_LIMITER_HPP
