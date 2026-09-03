/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "retry_policy.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace containerimages
{
    RetryPolicy::RetryPolicy(const int maxAttempts,
                             const std::chrono::milliseconds baseDelay,
                             const std::chrono::milliseconds maxDelay)
        : m_maxAttempts {std::max(1, maxAttempts)}
        , m_baseDelay {baseDelay}
        , m_maxDelay {maxDelay}
    {
    }

    bool RetryPolicy::isRetryable(const long status)
    {
        if (status == TRANSPORT_FAILURE)
        {
            // No response at all: a reset connection, a DNS failure, a timeout. Worth one
            // more try, since none of those say the request was wrong.
            return true;
        }

        if (status == 429)
        {
            return true;
        }

        return status == 500 || status == 502 || status == 503 || status == 504;
    }

    std::optional<std::chrono::milliseconds> RetryPolicy::parseRetryAfter(const std::string& value)
    {
        std::string digits;

        for (const auto character : value)
        {
            if (std::isspace(static_cast<unsigned char>(character)) != 0)
            {
                continue;
            }

            if (std::isdigit(static_cast<unsigned char>(character)) == 0)
            {
                // Not a delta-seconds value. An HTTP date lands here and is left to the
                // computed backoff rather than being parsed.
                return std::nullopt;
            }

            digits.push_back(character);

            // A value this long is not a wait anyone intends, and parsing it risks an
            // overflow for no benefit.
            if (digits.size() > 9)
            {
                return std::nullopt;
            }
        }

        if (digits.empty())
        {
            return std::nullopt;
        }

        return std::chrono::milliseconds {std::stoll(digits) * 1000};
    }

    RetryDecision RetryPolicy::evaluate(const long status, const std::string& retryAfter, const int attempt) const
    {
        if (!isRetryable(status))
        {
            return {false, std::chrono::milliseconds {0}, "the registry rejected the request"};
        }

        if (attempt >= m_maxAttempts)
        {
            return {false,
                    std::chrono::milliseconds {0},
                    "gave up after " + std::to_string(attempt) + " attempt(s)"};
        }

        // Doubling from the base: attempt 1 waits base, attempt 2 waits twice that, and
        // so on, capped. Computed in a wide type so the shift cannot overflow before the
        // cap is applied.
        const auto exponent {std::min(attempt - 1, 20)};
        const auto scaled {m_baseDelay.count() * (1LL << exponent)};

        auto delay {std::chrono::milliseconds {std::min<long long>(scaled, m_maxDelay.count())}};

        // The registry asking for a specific wait wins over the computed one, clamped so
        // a hostile or mistaken header cannot stall the scan for an unbounded time.
        if (const auto requested {parseRetryAfter(retryAfter)})
        {
            delay = std::min(*requested, m_maxDelay);
        }

        return {true, delay, {}};
    }
} // namespace containerimages
