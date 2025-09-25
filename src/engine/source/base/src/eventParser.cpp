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

constexpr size_t LOCATION_OFFSET = 2;         // Given the "q:" prefix.

/**
 * @brief If `location` has the form "[$agentID] ($agentName) $registerIP->$module", extract
 *        agentID, agentName and register IP into `event` and rewrite `location` to just `$module`.
 *        Otherwise, leave `location` untouched.
 *
 * @param location    String potentially of the form "[ID] Name IP->Module". Will be modified in‐place to "Module"
 * if it matches.
 * @param event Shared pointer to a JSON object where agentID and agentName will be set if the format matches.
 * @return true if the location was successfully parsed and modified, false otherwise.
 */
bool parseLegacyLocation(std::string& location, std::shared_ptr<json::Json>& event)
{
    // Minimum format is "[x] (y) z->m", i.e. at least 12 characters
    if (location.size() < 12 || location.front() != '[')
    {
        return false;
    }

    const char* data = location.data();
    size_t n = location.size();

    // find closing ']' for agentID
    size_t p1 = location.find(']');
    if (p1 == std::string::npos)
    {
        return false;
    }

    // next must be " ("
    if (p1 + 2 >= n || data[p1 + 1] != ' ' || data[p1 + 2] != '(')
    {
        return false;
    }

    // find closing ')' for agentName
    size_t p2 = location.find(')', p1 + 3);
    if (p2 == std::string::npos)
    {
        return false;
    }

    // next must be space, then registerIP, then "->"
    if (p2 + 2 >= n || data[p2 + 1] != ' ')
    {
        return false;
    }
    size_t arrow = location.find("->", p2 + 2);
    if (arrow == std::string::npos)
    {
        return false;
    }

    // extract substrings
    std::string_view svID {data + 1, p1 - 1};
    std::string_view svName {data + p1 + 3, p2 - (p1 + 3)};
    std::string_view svModule {data + arrow + 2, n - (arrow + 2)};

    if (svID.empty() || svName.empty() || svModule.empty())
    {
        return false;
    }

    // Set the agent ID, name, and register IP in the event.
    event->setString(svID, EVENT_AGENT_ID);
    event->setString(svName, EVENT_AGENT_NAME);

    // Rewrite the location to just the module name.
    location.assign(svModule);

    // return true to indicate successful parsing and modification.
    return true;
}

} // namespace

Event parseLegacyEvent(std::string_view rawEvent, const json::Json& hostInfo)
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

    // If the location is in the legacy agent format "[ID] (Name) IP->Module", parse it.
    if (!parseLegacyLocation(rawLocation, parseEvent))
    {
        try
        {
            parseEvent->merge(true, hostInfo);
        }
        catch (const std::exception& ex)
        {
            throw std::runtime_error(fmt::format("merge failed: {}", ex.what()));
        }
    }
    parseEvent->setString(rawLocation, EVENT_LOCATION_ID);

    // Set the original event message.
    auto msgView = rawEvent.substr(separatorPos + 1);
    parseEvent->setString(msgView, EVENT_MESSAGE_ID);

    return parseEvent;
}
} // namespace base::eventParsers
