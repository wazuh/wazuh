/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTENT_LOG_THROTTLE_HPP
#define _CONTENT_LOG_THROTTLE_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>

/**
 * @brief Rate-limits a repeated log line to one emission per window, counting what it suppressed.
 *
 * A trimmed twin of `wazuh::uds_http::LogThrottle`. It is duplicated rather than shared because the
 * only thing linking this module to `uds_http_server` was the on-demand responder, and that
 * coupling has moved out to the host that owns the HTTP route; re-adding the include path for one
 * header of rate-limiting arithmetic would put it straight back — and would make every future host
 * of this library inherit it too.
 *
 * `steady_clock`, not wall time: an NTP step backwards must not hold the gate shut, and one forwards
 * must not open it early. Lock-free and safe to share across threads.
 */
class LogThrottle final
{
public:
    /// One window per condition. 90 s matches the manager's existing throttles.
    static constexpr std::chrono::nanoseconds DEFAULT_WINDOW {std::chrono::seconds {90}};

    /// The same window in whole seconds, so the rendered "in the last N s" cannot drift from it.
    static constexpr int DEFAULT_WINDOW_SECONDS {
        static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(DEFAULT_WINDOW).count())};

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

    explicit LogThrottle(std::chrono::nanoseconds window = DEFAULT_WINDOW) noexcept
        : m_windowNs {window.count()}
    {
    }

    LogThrottle(const LogThrottle&) = delete;
    LogThrottle& operator=(const LogThrottle&) = delete;

    /**
     * @brief Count this occurrence and decide whether the caller should log it now.
     *
     * The first occurrence always emits: an operator must not wait a whole window for the first
     * sign of trouble. Afterwards at most one caller per window is told to emit, and it is handed
     * the full count of occurrences its line stands for.
     *
     * @return The decision. Log only when `emit` is true, and report `total`.
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

        // Exactly one thread wins the emission slot; the losers stay counted and are folded into
        // whichever line does get emitted.
        if (!m_lastEmitNs.compare_exchange_strong(previous, now, std::memory_order_relaxed))
        {
            return {};
        }

        const auto total = m_pending.exchange(0, std::memory_order_relaxed);
        return {true, total > 0 ? total - 1 : 0, total};
    }

private:
    /// Far enough in the past that the first record() passes, without the subtraction overflowing.
    static constexpr std::int64_t NEVER {std::numeric_limits<std::int64_t>::min() / 2};

    static std::int64_t nowNs() noexcept
    {
        return std::chrono::steady_clock::now().time_since_epoch().count();
    }

    const std::int64_t m_windowNs;
    std::atomic<std::int64_t> m_lastEmitNs {NEVER};
    std::atomic<std::uint64_t> m_pending {0};
};

#endif // _CONTENT_LOG_THROTTLE_HPP
