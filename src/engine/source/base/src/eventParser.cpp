#include <base/eventParser.hpp>

#include <mutex>
#include <stdexcept>
#include <string>

#include <unistd.h>

#include <fmt/format.h>

#include <base/logging.hpp>

namespace base::eventParsers
{

namespace
{

constexpr size_t LOCATION_OFFSET = 2; // Given the "q:" prefix.

} // namespace

Event parseLegacyEvent(std::string_view rawEvent, const json::Json& agentMetadata)
{
    auto parseEvent = std::make_shared<json::Json>();

    // "<byte>:a:b" is at least 5 bytes.
    if (rawEvent.size() < 5 || rawEvent[1] != ':')
    {
        throw std::runtime_error("Invalid format: event must be at least 5 bytes (\"<byte>:<location>:<message>\")");
    }

    // Extract the queue identifier
    const int queue = static_cast<unsigned char>(rawEvent[0]);
    parseEvent->setInt(queue, EVENT_QUEUE_ID);

    // Extract location, start searching at index 2 (first character of location).
    std::size_t n = rawEvent.size();
    std::size_t separatorPos = std::string::npos;
    for (std::size_t i = LOCATION_OFFSET; i < n; ++i)
    {
        if (rawEvent[i] == ':' && rawEvent[i - 1] != '|')
        {
            separatorPos = i;
            break;
        }
    }

    if (separatorPos == std::string::npos)
    {
        throw std::runtime_error("Invalid format: missing unescaped ':' between location and message");
    }

    // Extract the raw "location" substring (may contain "|:" sequences).
    auto rawLocView = rawEvent.substr(LOCATION_OFFSET, separatorPos - LOCATION_OFFSET);
    if (rawLocView.empty())
    {
        throw std::runtime_error("Invalid format: location cannot be empty");
    }

    // Unescape "|:" sequences → ':' in the final location.
    std::string rawLocation;
    rawLocation.reserve(rawLocView.size());
    for (size_t i = 0, m = rawLocView.size(); i < m; ++i)
    {
        if (rawLocView[i] == '|' && i + 1 < m && rawLocView[i + 1] == ':')
        {
            rawLocation.push_back(':');
            ++i;
        }
        else
        {
            rawLocation.push_back(rawLocView[i]);
        }
    }

    try
    {
        parseEvent->merge(true, agentMetadata);
    }
    catch (const std::exception& ex)
    {
        throw std::runtime_error(fmt::format("Agent metadata merge failed: {}", ex.what()));
    }

    parseEvent->setString(rawLocation, EVENT_LOCATION_ID);

    // Set the original event message.
    auto msgView = rawEvent.substr(separatorPos + 1);
    parseEvent->setString(msgView, EVENT_MESSAGE_ID);

    return parseEvent;
}

Event parsePublicEvent(uint8_t queue, std::string& location, std::string_view message, const json::Json& agentMetadata)
{
    auto parseEvent = std::make_shared<json::Json>();

    // Queue comes already parsed.
    parseEvent->setInt(static_cast<int>(queue), EVENT_QUEUE_ID);

    if (location.empty())
    {
        throw std::runtime_error("Invalid format: location cannot be empty");
    }

    try
    {
        parseEvent->merge(true, agentMetadata);
    }
    catch (const std::exception& ex)
    {
        throw std::runtime_error(fmt::format("merge failed: {}", ex.what()));
    }

    parseEvent->setString(location, EVENT_LOCATION_ID);

    // Raw message/payload.
    parseEvent->setString(message, EVENT_MESSAGE_ID);

    return parseEvent;
}

} // namespace base::eventParsers
