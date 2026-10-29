/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_COMMON_LOG_THROTTLE_HPP
#define _REMOTED_COMMON_LOG_THROTTLE_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>
#include <string>

namespace remoted::common
{

    /**
     * @brief Rate-limits a repeated log line to one emission per window, aggregating the
     *        occurrences it suppressed so the emitted line can report them.
     *
     * Same shape as remoted's own C throttle (src/remoted/src/secure.c,
     * maybe_log_events_queue_drop), with two deliberate differences:
     *   - steady_clock, not time(NULL): an NTP step backwards must not hold the gate shut, and a
     *     step forwards must not open it early.
     *   - the suppressed occurrences are counted and handed back, so nothing is silently lost.
     *
     * Why this class does NOT log: keeping loggerHelper.h out of a header is a hard constraint in
     * this module (see auth/keystore.cpp for the reason -- Log::GLOBAL_LOG_FUNCTION has hidden
     * visibility and only the .so defines it, so any header pulling loggerHelper.h into the
     * separately-linked test binary fails to link). Deciding here and emitting at the call site
     * also makes the decision unit-testable on its own, which a per-file duplicated static helper
     * would not be.
     *
     * Lock-free and safe to share across threads.
     */
    class LogThrottle final
    {
    public:
        /// One window per condition. 90 s matches remoted's existing C throttles.
        static constexpr std::chrono::nanoseconds kDefaultWindow {std::chrono::seconds {90}};

        /// The same window in whole seconds, for telling the operator how often a line is
        /// summarised. Never for the period a count covers: that is Decision::period().
        static constexpr int kDefaultWindowSeconds {
            static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(kDefaultWindow).count())};

        explicit LogThrottle(std::chrono::nanoseconds window = kDefaultWindow) noexcept
            : m_windowNs {window.count()}
        {
        }

        LogThrottle(const LogThrottle&) = delete;
        LogThrottle& operator=(const LogThrottle&) = delete;

        /// @brief What the caller should do about this occurrence.
        struct Decision
        {
            bool emit {false};            ///< True for exactly one caller per window.
            std::uint64_t suppressed {0}; ///< Occurrences NOT logged since the last emission.
            std::uint64_t total {0};      ///< suppressed + 1: how many occurrences this line stands for.
            /// Whole seconds since the previous emission, i.e. the real period `total` covers
            /// (which can be far longer than the window: suppressed occurrences are only reported
            /// by the next one). -1 for the first emission ever, which covers only itself.
            std::int64_t secondsSinceLastEmit {-1};

            /// @brief Lets a Decision be used directly in an `if`.
            explicit operator bool() const noexcept
            {
                return emit;
            }

            /**
             * @brief The period `total` really covers, worded for a log line ("%llu error(s) %s").
             *
             * "so far" for the first emission (it covers everything since the process started,
             * which is usually just itself), otherwise "in the last N s" with N the real time since
             * the previous emission -- never the window length, which would misattribute the
             * occurrences a quiet stretch carried over.
             */
            std::string period() const
            {
                if (secondsSinceLastEmit < 0)
                {
                    return "so far";
                }
                return "in the last " + std::to_string(secondsSinceLastEmit) + " s";
            }
        };

        /**
         * @brief Count this occurrence and decide whether the caller should log it now.
         *
         * The FIRST occurrence always emits (total == 1): an operator must not have to wait a
         * whole window for the first sign of trouble. Afterwards, at most one caller per window
         * gets `emit == true`, and it receives the full count of occurrences its line represents.
         *
         * @return A Decision; log only when `emit` is true, and report `total`.
         */
        Decision record() noexcept
        {
            m_pending.fetch_add(1, std::memory_order_relaxed);

            const auto now = nowNs();
            auto previous = m_lastEmitNs.load(std::memory_order_relaxed);

            if (now - previous < m_windowNs)
            {
                return {};
            }

            // Exactly one thread wins the emission slot; the losers stay counted in m_pending and
            // are folded into whichever line does get emitted (this one, or the next window's).
            if (!m_lastEmitNs.compare_exchange_strong(previous, now, std::memory_order_relaxed))
            {
                return {};
            }

            // Takes everything counted so far. An occurrence recorded between another thread's
            // fetch_add and this exchange is folded into THIS line; one recorded after it is
            // carried into the next window -- so no occurrence is ever lost or counted twice.
            const auto total = m_pending.exchange(0, std::memory_order_relaxed);
            const std::int64_t sinceLast =
                previous == kNever ? -1 : static_cast<std::int64_t>((now - previous) / 1'000'000'000);
            return {true, total > 0 ? total - 1 : 0, total, sinceLast};
        }

        /// @brief Occurrences counted but not yet reported.
        std::uint64_t pending() const noexcept
        {
            return m_pending.load(std::memory_order_relaxed);
        }

    private:
        // Far enough in the past that the first record() passes the window check, while staying
        // clear of the subtraction overflowing.
        static constexpr std::int64_t kNever {std::numeric_limits<std::int64_t>::min() / 2};

        static std::int64_t nowNs() noexcept
        {
            return std::chrono::steady_clock::now().time_since_epoch().count();
        }

        const std::int64_t m_windowNs;
        std::atomic<std::int64_t> m_lastEmitNs {kNever};
        std::atomic<std::uint64_t> m_pending {0};
    };

} // namespace remoted::common

#endif // _REMOTED_COMMON_LOG_THROTTLE_HPP
