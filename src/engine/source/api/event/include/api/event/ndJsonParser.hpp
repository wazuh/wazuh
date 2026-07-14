#ifndef _API_EVENT_NDJSONPARSER_HPP
#define _API_EVENT_NDJSONPARSER_HPP

#include <functional>
#include <memory>
#include <stdexcept>
#include <string_view>

#include <fmt/format.h>

#include <base/json.hpp>

namespace api::event::protocol
{
using IngestEvent = std::pair<std::shared_ptr<const json::Json>, std::string>; // {header, rawEvent}
using EventHook = std::function<void(IngestEvent&&)>;

constexpr auto PARSER_ERROR_MSG = "NDJson parser error, {}";

/**
 * @brief Strip continuation-line indentation from raw event text.
 *
 * The wire format indents every continuation line (line after the first within
 * a multi-line event) with a single space character to prevent false "\nE "
 * delimiter matches inside event content.  This function removes exactly one
 * leading space from each continuation line, restoring the original payload.
 */
inline std::string unindentContinuation(std::string_view indented)
{
    // Fast path: no newlines means nothing to unindent
    if (indented.find('\n') == std::string_view::npos)
    {
        return std::string(indented);
    }

    std::string result;
    result.reserve(indented.size());

    std::size_t pos = 0;
    while (pos < indented.size())
    {
        auto nl = indented.find('\n', pos);
        if (nl == std::string_view::npos)
        {
            result.append(indented.data() + pos, indented.size() - pos);
            break;
        }
        // Append up to and including the newline
        result.append(indented.data() + pos, nl - pos + 1);
        pos = nl + 1;
        // Strip exactly one leading space (the continuation indent)
        if (pos < indented.size() && indented[pos] == ' ')
        {
            ++pos;
        }
    }
    return result;
}

inline void parseNDJson(std::string_view batch, const EventHook& hook)
{
    try
    {
        constexpr std::string_view NEWLINE_TOKEN = "\n";
        constexpr std::size_t NEWLINE_SIZE = NEWLINE_TOKEN.size();
        constexpr std::string_view EVENT_MARKER = "\nE ";

        // ---- Extract header: first line must be "H {json}" ----
        auto firstNewline = batch.find(NEWLINE_TOKEN);
        if (firstNewline == std::string_view::npos)
        {
            throw std::runtime_error {"Missing newline after header"};
        }

        std::string_view headerLine = batch.substr(0, firstNewline);
        if (headerLine.size() < 2 || headerLine[0] != 'H' || headerLine[1] != ' ')
        {
            throw std::runtime_error {"Invalid header format, expected 'H {json}'"};
        }

        std::string_view headerJson = headerLine.substr(2);
        auto header = std::make_shared<const json::Json>(headerJson);

        // ---- Parse events using "\nE " as delimiter ----
        std::size_t pos = firstNewline + NEWLINE_SIZE;

        while (pos < batch.size())
        {
            // Skip empty lines
            while (pos < batch.size() && batch[pos] == '\n')
            {
                pos += NEWLINE_SIZE;
            }

            if (pos >= batch.size())
            {
                break;
            }

            // Expect "E " at event start
            if (pos + 1 >= batch.size() || batch[pos] != 'E' || batch[pos + 1] != ' ')
            {
                throw std::runtime_error {"Expected 'E ' at event start"};
            }

            std::size_t eventStart = pos + 2; // Skip "E "

            // Find next "\nE " or end of batch
            std::size_t nextEventPos = batch.find(EVENT_MARKER, eventStart);
            std::size_t eventEnd = (nextEventPos != std::string_view::npos) ? nextEventPos : batch.size();

            // Trim trailing newlines from event (multilines are preserved inside)
            while (eventEnd > eventStart && batch[eventEnd - 1] == '\n')
            {
                eventEnd -= NEWLINE_SIZE;
            }

            std::string_view rawEvent = batch.substr(eventStart, eventEnd - eventStart);

            if (hook)
            {
                // Remove continuation-line indentation added by the sender
                IngestEvent ingestEvent {header, unindentContinuation(rawEvent)};
                hook(std::move(ingestEvent));
            }

            // Move to next event position
            pos = (nextEventPos != std::string_view::npos) ? (nextEventPos + NEWLINE_SIZE) : batch.size();
        }
    }
    catch (const std::exception& ex)
    {
        throw std::runtime_error {fmt::format(PARSER_ERROR_MSG, ex.what())};
    }
}

} // namespace api::event::protocol

#endif // _API_EVENT_NDJSONPARSER_HPP
