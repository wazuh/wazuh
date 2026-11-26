// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _BK_TERM_FAILURE_LOG_HPP
#define _BK_TERM_FAILURE_LOG_HPP

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include <base/baseTypes.hpp>
#include <base/logging.hpp>

namespace bk::detail
{

/// Longest piece of an exception's text that reaches the log.
constexpr std::size_t TERM_FAILURE_WHAT_MAX {256};

/// Minimum time between two WARNING lines about terms that threw, for the whole process.
constexpr std::chrono::seconds TERM_FAILURE_LOG_WINDOW {30};

/**
 * @brief Text of an exception fit for one log line: cut at TERM_FAILURE_WHAT_MAX bytes, control bytes replaced.
 *
 * What an operation throws often quotes the event (a key, a path), and the plain log writes text as it
 * is: a line break in it would start a line the event's author wrote.
 */
inline std::string termFailureText(std::string_view what)
{
    if (what.size() > TERM_FAILURE_WHAT_MAX)
    {
        // Cut between characters: back up over the continuation bytes of a UTF-8 sequence the limit splits.
        auto cut = TERM_FAILURE_WHAT_MAX;
        while (cut > 0 && (static_cast<unsigned char>(what[cut]) & 0xC0) == 0x80)
        {
            --cut;
        }
        what = what.substr(0, cut);
    }
    std::string text {what};
    for (auto& c : text)
    {
        const auto byte = static_cast<unsigned char>(c);
        if (byte < 0x20 || byte == 0x7f)
        {
            c = ' ';
        }
    }
    return text;
}

/**
 * @brief Reports a term whose operation threw while processing an event.
 *
 * The event's author decides how often this happens, and how large the event is: the WARNING names the
 * term and the error only, at most once every TERM_FAILURE_LOG_WINDOW (the first at once, then with the
 * count of the ones held back). The window is one for every term: the count covers the failures of any of
 * them, and the line says so. Each failure, with its event, is logged at debug level when that is enabled.
 *
 * @param name Name of the term.
 * @param what Text of the exception.
 * @param event Event being processed.
 */
inline void logTermFailure(const std::string& name, std::string_view what, const base::Event& event)
{
    using Clock = std::chrono::steady_clock;
    static std::atomic<Clock::rep> nextWarning {Clock::rep {0}};
    static std::atomic<std::uint64_t> heldBack {0};

    const auto text = termFailureText(what);
    const auto now = Clock::now().time_since_epoch();
    auto due = nextWarning.load(std::memory_order_relaxed);

    if (now.count() >= due
        && nextWarning.compare_exchange_strong(
            due, std::chrono::duration_cast<Clock::duration>(now + TERM_FAILURE_LOG_WINDOW).count()))
    {
        LOG_WARNING("[BK::pipeline] Unexpected error processing term: {} in '{}' ({} more failures, of this or "
                    "any other term, since the last report: the debug level logs each one)",
                    text,
                    name,
                    heldBack.exchange(0));
    }
    else
    {
        heldBack.fetch_add(1, std::memory_order_relaxed);
    }

    if (::logging::should_log(::logging::Level::Debug))
    {
        LOG_DEBUG("[BK::pipeline] Unexpected error processing term: {} in '{}' with {}", text, name, event->str());
    }
}

} // namespace bk::detail

#endif // _BK_TERM_FAILURE_LOG_HPP
