/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_COMMON_RESPONSE_BUDGET_HPP
#define _INVSYNC_COMMON_RESPONSE_BUDGET_HPP

/**
 * @file
 * @brief remoted's response budget: how long the caller will still listen for a session's answer.
 *
 * remoted stops listening for a `/stateful` answer when its own response timer or the HTTP
 * request timeout fires; past that point it has already answered the agent 503 + Retry-After and
 * the agent is free to re-send. Work this server does after that point is work nobody is waiting
 * for, and it races the re-send -- possibly on another node.
 *
 * remoted therefore sends what it has left as a RELATIVE budget in milliseconds. This header is
 * the whole vocabulary: the header name, the parse, the deadline stamp, and the two predicates
 * that the dispatch seams use. Everything here is pure and clock-injected, so the behaviour is
 * testable without real waits.
 */

#include <algorithm>
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>

namespace invsync::common
{
    /// @brief The header carrying remoted's remaining response budget, in milliseconds.
    ///
    /// Lower-case: the transport normalizes header names (IUdsHttpServer.hpp), so a handler may
    /// look this up unconditionally -- same reason as the agent-id header's own constant.
    constexpr const char* responseBudgetHeader()
    {
        return "x-wazuh-response-budget-ms";
    }

    /// @brief The body of the refusal: the caller's deadline passed before we could start.
    ///
    /// Lives here, next to refuse(), because both translation units that refuse -- the pipeline and
    /// the VD lane -- must answer byte-identically: the agent tells this apart from the other 503s
    /// by its body alone. No Retry-After rides with it: nothing was applied, so an immediate
    /// re-send is correct.
    constexpr auto DEADLINE_EXPIRED_BODY {R"({"error":"deadline expired","code":503})"};

    /// @brief A clock, injectable so tests can make time pass without sleeping.
    ///
    /// Everything that is compared against a stamped instant must read time through one of these:
    /// mixing an injected clock with steady_clock::now() yields differences of absolute-clock
    /// magnitude, which would silently poison the duration histograms.
    using SteadyNow = std::function<std::chrono::steady_clock::time_point()>;

    /**
     * @brief Parse a response budget header value.
     *
     * Accepts ONLY a run of 1 to 9 digits with a positive value. The 9-digit ceiling is what makes
     * overflow impossible without a wider type: anything longer -- including the 20-digit values a
     * confused caller might send -- is treated as absent rather than as a huge budget. Leading
     * signs, spaces, exponents and empty values are rejected for the same reason: an unparseable
     * budget must leave the session behaving exactly as it did before this header existed.
     *
     * @return The budget, or std::nullopt when the value is not a legal budget.
     */
    inline std::optional<std::chrono::milliseconds> parseBudget(const std::string& value)
    {
        if (value.empty() || value.size() > 9)
        {
            return std::nullopt;
        }

        long long parsed {0};
        for (const char character : value)
        {
            if (character < '0' || character > '9')
            {
                return std::nullopt;
            }
            parsed = parsed * 10 + (character - '0');
        }

        if (parsed <= 0)
        {
            return std::nullopt;
        }

        return std::chrono::milliseconds {parsed};
    }

    /**
     * @brief The slack kept before the deadline: min(1 s, half the budget).
     *
     * A session refused with milliseconds to spare would have been refused for nothing, so the
     * seams stop starting work once less than this is left. It cannot be a flat second:
     * remoted.downstream_stateful_response_timeout accepts 1 s, and a flat second would refuse
     * every session under that configuration. With the 20 s default the margin is the full second.
     */
    inline std::chrono::milliseconds margin(const std::chrono::milliseconds budget)
    {
        return std::min(std::chrono::milliseconds {1000}, budget / 2);
    }

    /// @brief Whether a session must not START work now: less than margin() left before @p deadline.
    inline bool refuse(const std::chrono::steady_clock::time_point deadline,
                       const std::chrono::steady_clock::time_point now,
                       const std::chrono::milliseconds budget)
    {
        return (deadline - now) < margin(budget);
    }

    /// @brief Whether @p now is past @p deadline, i.e. the caller has already stopped listening.
    ///
    /// Equality is NOT past: a session answered exactly at its deadline was still awaited.
    inline bool overran(const std::chrono::steady_clock::time_point deadline,
                        const std::chrono::steady_clock::time_point now)
    {
        return now > deadline;
    }

    /**
     * @brief Anchor the caller's budget to this server's monotonic clock.
     *
     * Pure on purpose: the admission handler calls it, and a test can check the anchoring without
     * reaching into the pipeline's private queues.
     *
     * @param headers  The request's headers, already lower-cased by the transport.
     * @param now      This server's instant for the request, from the injected clock.
     * @param deadline Set to @p now + budget when the header is readable; untouched otherwise.
     * @param budget   Set to the parsed budget when the header is readable; untouched otherwise.
     * @return Whether a deadline was stamped. A false return means "no deadline", which every
     *         seam treats as "behave exactly as before".
     */
    inline bool stampDeadline(const std::unordered_map<std::string, std::string>& headers,
                              const std::chrono::steady_clock::time_point now,
                              std::optional<std::chrono::steady_clock::time_point>& deadline,
                              std::chrono::milliseconds& budget)
    {
        const auto header = headers.find(responseBudgetHeader());
        if (header == headers.end())
        {
            return false;
        }

        const auto parsed = parseBudget(header->second);
        if (!parsed)
        {
            return false;
        }

        budget = *parsed;
        deadline = now + *parsed;
        return true;
    }
} // namespace invsync::common

#endif // _INVSYNC_COMMON_RESPONSE_BUDGET_HPP
