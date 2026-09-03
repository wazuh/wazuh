/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RETRY_POLICY_HPP
#define _RETRY_POLICY_HPP

#include <chrono>
#include <optional>
#include <string>

namespace containerimages
{
    /// @brief Status used for a request that never produced an HTTP response.
    constexpr long TRANSPORT_FAILURE {0};

    /// @brief What to do after a request that did not succeed.
    struct RetryDecision
    {
        bool retry {false};
        std::chrono::milliseconds delay {0}; ///< How long to wait before retrying.
        std::string reason;                  ///< Why no retry will happen, when retry is false.
    };

    /// @brief Whether and how long to wait before trying a request again.
    ///
    /// Deliberately without jitter. Jitter exists to spread a thundering herd across many
    /// clients, and one agent scanning a handful of references is not one; a deterministic
    /// schedule is testable, which matters more here.
    class RetryPolicy final
    {
        public:
            /// @param maxAttempts Total attempts, including the first.
            /// @param baseDelay   Delay before the second attempt; doubles thereafter.
            /// @param maxDelay    Ceiling for any single wait, and for a `Retry-After`.
            explicit RetryPolicy(int maxAttempts = 4,
                                 std::chrono::milliseconds baseDelay = std::chrono::milliseconds {1000},
                                 std::chrono::milliseconds maxDelay = std::chrono::milliseconds {30000});

            /// @brief Decide what follows a failed attempt.
            ///
            /// @param status     HTTP status, or @ref TRANSPORT_FAILURE when the request
            ///                   produced no response.
            /// @param retryAfter The `Retry-After` header value, empty when absent. When
            ///                   it names a delay, it wins over the computed one, because
            ///                   it is the registry saying how long to wait.
            /// @param attempt    Attempts already made, starting at 1.
            RetryDecision evaluate(long status, const std::string& retryAfter, int attempt) const;

            /// @brief True when a status is worth trying again at all.
            ///
            /// `429` and the transient server statuses are. Every other `4xx` is the
            /// registry saying the request itself is wrong, and repeating it changes
            /// nothing while still costing the scan its time budget.
            static bool isRetryable(long status);

            /// @brief Parse a `Retry-After` value expressed in seconds.
            ///
            /// The header also allows an HTTP date. That form is not parsed, and the
            /// computed delay is used instead, which is a safe fallback: a date is
            /// answered by waiting the backoff rather than by ignoring the signal.
            static std::optional<std::chrono::milliseconds> parseRetryAfter(const std::string& value);

            int maxAttempts() const
            {
                return m_maxAttempts;
            }

        private:
            int m_maxAttempts;
            std::chrono::milliseconds m_baseDelay;
            std::chrono::milliseconds m_maxDelay;
    };
} // namespace containerimages

#endif // _RETRY_POLICY_HPP
