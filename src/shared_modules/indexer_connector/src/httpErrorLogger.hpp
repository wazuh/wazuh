/*
 * Wazuh - Indexer connector HTTP error logger.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_CONNECTOR_HTTP_ERROR_LOGGER_HPP
#define _INDEXER_CONNECTOR_HTTP_ERROR_LOGGER_HPP

#include "external/nlohmann/json.hpp"
#include "loggerHelper.h"
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace IndexerConnector
{
    /// After the first ERROR for a given (url, status, error) key is logged, identical
    /// repeats are suppressed until this many seconds elapse. This prevents a persistent
    /// failure (e.g. a 403 returned on every request) from flooding ossec.log while still
    /// surfacing the problem and periodically confirming it is still happening.
    constexpr auto HTTP_ERROR_SUPPRESSION_WINDOW_SECONDS {300};

    /// @brief Thread-safe, de-duplicating logger for indexer-connector HTTP errors.
    ///
    /// Every connector request shares a single instance. It enriches the message with the
    /// failing endpoint and the indexer response body (so the request can be identified) and
    /// throttles identical, repeating client/server errors so they do not flood the log.
    class HttpErrorLogger final
    {
    public:
        HttpErrorLogger(const HttpErrorLogger&) = delete;
        HttpErrorLogger& operator=(const HttpErrorLogger&) = delete;

        static HttpErrorLogger& instance()
        {
            static HttpErrorLogger s_instance;
            return s_instance;
        }

        /// @brief Logs an HTTP error, including the endpoint and response detail, with throttling.
        /// @param tag Logger tag (module name).
        /// @param context Optional short description of the failed operation (e.g. "Bulk request").
        /// @param url Endpoint that returned the error.
        /// @param error Error description provided by the HTTP client.
        /// @param statusCode HTTP status code.
        /// @param responseBody Raw response body returned by the indexer (may be empty).
        void log(const std::string& tag,
                 const std::string& context,
                 const std::string& url,
                 const std::string& error,
                 long statusCode,
                 const std::string& responseBody)
        {
            const std::string key = url + '|' + std::to_string(statusCode) + '|' + error;

            std::uint64_t suppressed = 0;
            if (!shouldLogNow(key, std::chrono::steady_clock::now(), suppressed))
            {
                return;
            }

            const std::string detail = buildDetail(context, url, error, statusCode, responseBody);

            if (suppressed > 0)
            {
                logError(tag.c_str(),
                         "%s (%llu identical error(s) suppressed in the last %lld seconds)",
                         detail.c_str(),
                         static_cast<unsigned long long>(suppressed),
                         static_cast<long long>(m_suppressionWindow.count()));
            }
            else
            {
                logError(tag.c_str(), "%s", detail.c_str());
            }
        }

        /// @brief Throttling decision for a given error key. Pure (no logging); exposed for testing.
        /// @param key Identity of the error (url|status|error).
        /// @param now Current time (injectable for tests).
        /// @param[out] suppressedOut Number of occurrences suppressed since the last emitted log.
        /// @return true if the caller should emit a log line now.
        bool shouldLogNow(const std::string& key,
                          std::chrono::steady_clock::time_point now,
                          std::uint64_t& suppressedOut)
        {
            std::scoped_lock lock(m_mutex);
            auto& state = m_state[key];

            bool shouldLog = false;
            if (state.occurrences == 0 || (now - state.lastLogged) >= m_suppressionWindow)
            {
                shouldLog = true;
                suppressedOut = state.suppressedSinceLastLog;
                state.suppressedSinceLastLog = 0;
                state.lastLogged = now;
            }
            else
            {
                suppressedOut = 0;
                ++state.suppressedSinceLastLog;
            }

            ++state.occurrences;
            return shouldLog;
        }

        /// @brief Overrides the suppression window. Intended for tests.
        void setSuppressionWindow(std::chrono::seconds window)
        {
            std::scoped_lock lock(m_mutex);
            m_suppressionWindow = window;
        }

        /// @brief Builds the enriched, single-line error message. Exposed for testing.
        static std::string buildDetail(const std::string& context,
                                       const std::string& url,
                                       const std::string& error,
                                       long statusCode,
                                       const std::string& responseBody)
        {
            std::string message;

            if (!context.empty())
            {
                message += context;
                message += ": ";
            }

            message += error.empty() ? "HTTP error" : error;
            message += ", status code: ";
            message += std::to_string(statusCode);

            if (!url.empty())
            {
                message += ", url: ";
                message += url;
            }

            const std::string reason = extractReason(responseBody);
            if (!reason.empty())
            {
                message += ", response: ";
                message += reason;
            }

            const std::string hint = blockRemediation(responseBody);
            if (!hint.empty())
            {
                message += " | hint: ";
                message += hint;
            }

            return message;
        }

        /// @brief Returns an actionable remediation hint when the indexer text reports that the
        ///        target index is blocked, or an empty string otherwise.
        ///
        /// A write-blocked or read-only index makes the indexer reject every write with the same
        /// 403 on every flush (see issue #37156), so the operator needs to know *which* block is
        /// set and how to clear it rather than just seeing "status code: 403". @p indexerText may be
        /// the raw response body or an already-extracted "type - reason" string.
        static std::string blockRemediation(const std::string& indexerText)
        {
            const auto has = [&indexerText](const char* needle)
            { return indexerText.find(needle) != std::string::npos; };

            // Flood-stage disk watermark: index forced read-only / allow-delete (FORBIDDEN/12).
            if (has("read_only_allow_delete") || has("FORBIDDEN/12") || has("read-only / allow delete"))
            {
                return R"(index is read-only from the disk flood-stage watermark: free disk space on the )"
                       R"(wazuh-indexer nodes, then clear it with PUT <index>/_settings )"
                       R"({"index.blocks.read_only_allow_delete":null})";
            }
            // Explicit read-only block (FORBIDDEN/5). Checked before the generic "blocked by" catch-all
            // below, which would otherwise also match this message.
            if (has("index read-only (api)") || has("FORBIDDEN/5"))
            {
                return R"(index is read-only (index.blocks.read_only): clear it with PUT <index>/_settings )"
                       R"({"index.blocks.read_only":null})";
            }
            // Explicit write block (FORBIDDEN/8) or any other cluster-level block.
            if (has("index write (api)") || has("FORBIDDEN/8") || has("cluster_block_exception") || has("blocked by"))
            {
                return R"(index is write-blocked (index.blocks.write): clear it with PUT <index>/_settings )"
                       R"({"index.blocks.write":null}. Wazuh does not set this block; it is applied on the indexer )"
                       R"(side (disk watermark, a manual setting, or an ISM/snapshot action))";
            }
            return {};
        }

        /// @brief Resets the throttling state. Intended for tests.
        void reset()
        {
            std::scoped_lock lock(m_mutex);
            m_state.clear();
        }

    private:
        HttpErrorLogger() = default;

        struct ErrorState
        {
            std::uint64_t occurrences {0};
            std::uint64_t suppressedSinceLastLog {0};
            std::chrono::steady_clock::time_point lastLogged {};
        };

        /// @brief Extracts a concise reason from an indexer JSON error body, falling back to the
        ///        raw body (truncated) when it is not the expected JSON shape.
        static std::string extractReason(const std::string& responseBody)
        {
            if (responseBody.empty())
            {
                return {};
            }

            const auto json = nlohmann::json::parse(responseBody, nullptr, false);
            if (!json.is_discarded() && json.contains("error"))
            {
                const auto& err = json.at("error");
                if (err.is_object())
                {
                    std::string type;
                    std::string reason;
                    if (err.contains("type") && err.at("type").is_string())
                    {
                        type = err.at("type").get<std::string>();
                    }
                    if (err.contains("reason") && err.at("reason").is_string())
                    {
                        reason = err.at("reason").get<std::string>();
                    }

                    if (!type.empty() && !reason.empty())
                    {
                        return type + " - " + reason;
                    }
                    if (!reason.empty())
                    {
                        return reason;
                    }
                    if (!type.empty())
                    {
                        return type;
                    }
                }
                else if (err.is_string())
                {
                    return err.get<std::string>();
                }
            }

            // Not the expected JSON error shape: include a truncated copy of the raw body.
            constexpr std::size_t MAX_BODY_LENGTH {256};
            if (responseBody.size() > MAX_BODY_LENGTH)
            {
                return responseBody.substr(0, MAX_BODY_LENGTH) + "...";
            }
            return responseBody;
        }

        std::mutex m_mutex;
        std::unordered_map<std::string, ErrorState> m_state;
        std::chrono::seconds m_suppressionWindow {HTTP_ERROR_SUPPRESSION_WINDOW_SECONDS};
    };
} // namespace IndexerConnector

#endif // _INDEXER_CONNECTOR_HTTP_ERROR_LOGGER_HPP
