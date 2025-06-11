#include <base/eventParser.hpp>
#include <base/logging.hpp>
#include <fmt/format.h>

namespace base::eventParsers
{

namespace
{

constexpr int LOCATION_OFFSET = 2; // Given the "q:" prefix.

/**
 * @brief If `location` has the form "[$agentID] ($agentName) $registerIP->$module", extract
 *        agentID, agentName and register IP into `event` and rewrite `location` to just `$module`.
 *        Otherwise, leave `location` untouched.
 *
 * @param location    String potentially of the form "[ID] Name IP->Module". Will be modified in‐place to "Module" if it
 * matches.
 * @param event Shared pointer to a JSON object where agentID and agentName will be set if the format matches.
 */
void parseLegacyLocation(std::string& location, std::shared_ptr<json::Json>& event)
{
    // Minimum format is "[x] (y) z->m", i.e. at least 12 characters
    if (location.size() < 12 || location.front() != '[')
    {
        return;
    }

    const char* data = location.data();
    size_t n = location.size();

    // find closing ']' for agentID
    size_t p1 = location.find(']');
    if (p1 == std::string::npos)
    {
        return;
    }

    // next must be " ("
    if (p1 + 2 >= n || data[p1 + 1] != ' ' || data[p1 + 2] != '(')
    {
        return;
    }

    // find closing ')' for agentName
    size_t p2 = location.find(')', p1 + 3);
    if (p2 == std::string::npos)
    {
        return;
    }

    // next must be space, then registerIP, then "->"
    if (p2 + 2 >= n || data[p2 + 1] != ' ')
    {
        return;
    }
    size_t arrow = location.find("->", p2 + 2);
    if (arrow == std::string::npos)
    {
        return;
    }

    // extract substrings
    std::string_view svID {data + 1, p1 - 1};
    std::string_view svName {data + p1 + 3, p2 - (p1 + 3)};
    std::string_view svRegIP {data + p2 + 2, arrow - (p2 + 2)};
    std::string_view svModule {data + arrow + 2, n - (arrow + 2)};

    if (svID.empty() || svName.empty() || svRegIP.empty() || svModule.empty())
    {
        return;
    }

    // Set the agent ID, name, and register IP in the event.
    event->setString(svID, EVENT_AGENT_ID);
    event->setString(svName, EVENT_AGENT_NAME);
    event->setString(svRegIP, EVENT_REGISTER_IP);

    // Rewrite the location to just the module name.
    location.assign(svModule);
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

    // If the location is in the legacy format "[ID] (Name) IP->Module", parse it.
    parseLegacyLocation(rawLocation, parseEvent);
    parseEvent->setString(rawLocation, EVENT_LOCATION_ID);

    // Set the original event message.
    parseEvent->setString(std::string_view(event.data() + separatorPos + 1), EVENT_MESSAGE_ID);

    return parseEvent;
}
} // namespace base::eventParsers
