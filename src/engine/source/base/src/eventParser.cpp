#include <base/eventParser.hpp>
#include <base/logging.hpp>
#include <fmt/format.h>

namespace base::eventParsers
{

namespace
{

constexpr int LOCATION_OFFSET = 2; // Given the "q:" prefix.
constexpr int MINIMUM_EVENT_ALLOWED_LENGTH = 4;

/**
 * @brief If `location` has the form "[$agentID] $agentName->$module", extract
 *        agentID and agentName into `event` and rewrite `location` to just `$module`.
 *        Otherwise, leave `location` untouched.
 *
 * @param location    String potentially of the form "[ID] Name->Module". Will be modified in‐place to "Module" if it
 * matches.
 * @param event Shared pointer to a JSON object where agentID and agentName will be set if the format matches.
 */
void parseLegacyLocation(std::string& location, std::shared_ptr<json::Json>& event)
{
    // Minimum format is "[x] y->z", i.e. at least 7 characters
    if (location.size() < 7 || location.front() != '[')
    {
        return;
    }

    const char* data = location.data();
    size_t n = location.size();

    // Find the closing ']' (agentID end). It must appear somewhere after index 1.
    size_t posBracket = location.find(']');
    if (posBracket == std::string::npos || posBracket < 2)
    {
        return;
    }

    // Check space after ']'
    if (posBracket + 1 >= n || data[posBracket + 1] != ' ')
    {
        return;
    }
    size_t nameStart = posBracket + 2;

    // Find the agentName & module separator "->"
    size_t arrowPos = location.find("->", nameStart + 1);
    if (arrowPos == std::string::npos || arrowPos <= nameStart)
    {
        return;
    }

    // Extract agentID as everything between '[' and ']'
    std::string_view agentID {data + 1, posBracket - 1};
    if (agentID.empty())
    {
        return;
    }

    // Extract agentName as everything between '] ' and "->"
    size_t nameLen = arrowPos - nameStart;
    std::string_view agentName {data + nameStart, nameLen};
    if (agentName.empty())
    {
        return;
    }

    // Extract module  (new location) as everything after "->"
    size_t moduleStart = arrowPos + 2;
    if (moduleStart >= n)
    {
        return;
    }
    std::string_view module {data + moduleStart, n - moduleStart};

    // Set agentID and agentName in the event JSON event
    event->setString(agentID, EVENT_AGENT_ID);
    event->setString(agentName, EVENT_AGENT_NAME);

    // Finally, overwrite location with module
    location.assign(module);
}

} // namespace

Event parseLegacyEvent(std::string&& event)
{
    auto parseEvent = std::make_shared<json::Json>();

    // "<byte>:a:b" is at least 5 bytes.
    if (event.size() < 5 || event[1] != ':')
    {
        throw std::runtime_error("Invalid format: event must be at least 5 bytes (\"<byte>:<location>:<message>\")");
    }

    // Extract the queue identifier
    const int queue = static_cast<unsigned char>(event[0]);
    parseEvent->setInt(queue, EVENT_QUEUE_ID);

    // Extract location, start searching at index 2 (first character of location).
    std::size_t n = event.size();
    std::size_t separatorPos = std::string::npos;
    for (std::size_t i = 2; i < n; ++i)
    {
        if (event[i] == ':' && event[i - 1] != '|')
        {
            separatorPos = i;
            break;
        }
    }

    if (separatorPos == std::string::npos)
    {
        throw std::runtime_error("Invalid format: missing unescaped ':' between location and message");
    }
    event[separatorPos] = '\0'; // Temporarily null-terminate the string for easier parsing.

    // Extract the raw "location" substring (may contain "|:" sequences).
    std::string_view rawLocationView(event.data() + LOCATION_OFFSET, separatorPos - LOCATION_OFFSET);
    if (rawLocationView.empty())
    {
        throw std::runtime_error("Invalid format: location cannot be empty");
    }

    // Unescape "|:" sequences → ':' in the final location.
    std::string rawLocation;
    rawLocation.reserve(rawLocationView.size());
    for (std::size_t i = 0; i < rawLocationView.size(); ++i)
    {
        if (rawLocationView[i] == '|' && (i + 1) < rawLocationView.size() && rawLocationView[i + 1] == ':')
        {
            rawLocation.push_back(':');
            ++i; // skip the ':' after '|'
        }
        else
        {
            rawLocation.push_back(rawLocationView[i]);
        }
    }

    // If the location is in the legacy format "[ID] Name->Module", parse it.
    parseLegacyLocation(rawLocation, parseEvent);
    parseEvent->setString(rawLocation, EVENT_LOCATION_ID);

    // Set the original event message.
    parseEvent->setString(std::string_view(event.data() + separatorPos + 1), EVENT_MESSAGE_ID);

    return parseEvent;
}
} // namespace base::eventParsers
