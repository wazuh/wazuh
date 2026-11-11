// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _IOCSYNC_ERROR_SUMMARY_HPP
#define _IOCSYNC_ERROR_SUMMARY_HPP

#include <cstddef>
#include <string>
#include <string_view>

#include <base/json.hpp>

namespace ioc::sync::detail
{

/// Longest error text a sync log line carries.
inline constexpr std::size_t MAX_ERROR_SUMMARY_LENGTH = 400;
/// Longest indexer `error.reason` kept inside the summary.
inline constexpr std::size_t MAX_ERROR_REASON_LENGTH = 160;

/**
 * @brief Cut a text to at most `maxLength` characters, marking the cut with "...".
 */
inline std::string truncateText(std::string_view text, std::size_t maxLength)
{
    if (text.size() <= maxLength)
    {
        return std::string {text};
    }
    constexpr std::string_view ellipsis {"..."};
    if (maxLength <= ellipsis.size())
    {
        return std::string {text.substr(0, maxLength)};
    }
    return std::string {text.substr(0, maxLength - ellipsis.size())} + std::string {ellipsis};
}

/**
 * @brief Shorten an indexer error message for a log line.
 *
 * Indexer connector errors end with the whole response body (`... failed with status 429: ... Response: {...}`),
 * which for a circuit-breaker rejection is more than a kilobyte, with the root cause repeated. Keep the text before
 * the body (it carries the status) plus the body's `error.type` and `error.reason`, and bound the result.
 *
 * @param message The exception message.
 * @return std::string The summary: never longer than MAX_ERROR_SUMMARY_LENGTH.
 */
inline std::string summarizeError(std::string_view message)
{
    const auto bodyPos = message.find('{');
    if (bodyPos == std::string_view::npos)
    {
        return truncateText(message, MAX_ERROR_SUMMARY_LENGTH);
    }

    // Text before the body, without the trailing "Response:" label and separators
    auto head = message.substr(0, bodyPos);
    const auto trimSeparators = [](std::string_view text)
    {
        while (!text.empty() && (text.back() == ' ' || text.back() == ':' || text.back() == ',' || text.back() == '.'))
        {
            text.remove_suffix(1);
        }
        return text;
    };
    head = trimSeparators(head);
    constexpr std::string_view responseLabel {"Response"};
    if (head.size() >= responseLabel.size() && head.substr(head.size() - responseLabel.size()) == responseLabel)
    {
        head.remove_suffix(responseLabel.size());
        head = trimSeparators(head);
    }

    std::string type;
    std::string reason;
    try
    {
        const json::Json body(message.substr(bodyPos));
        if (body.getString(reason, "/error/reason") != json::RetGet::Success)
        {
            // Some answers carry the error as a plain string
            (void)body.getString(reason, "/error");
        }
        (void)body.getString(type, "/error/type");
    }
    catch (const std::exception&)
    {
        // Not a JSON body (or a truncated one): keep only the text before it
    }

    std::string summary(head.empty() ? std::string_view {"Indexer error"} : head);
    if (!reason.empty() || !type.empty())
    {
        summary += " (";
        summary += type;
        if (!type.empty() && !reason.empty())
        {
            summary += ": ";
        }
        summary += truncateText(reason, MAX_ERROR_REASON_LENGTH);
        summary += ")";
    }

    return truncateText(summary, MAX_ERROR_SUMMARY_LENGTH);
}

} // namespace ioc::sync::detail

#endif // _IOCSYNC_ERROR_SUMMARY_HPP
