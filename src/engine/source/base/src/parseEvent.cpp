#include "parseEvent.hpp"

#include <fmt/format.h>
#include <base/logging.hpp>

namespace base::parseEvent
{

namespace
{

constexpr int LOCATION_OFFSET = 2; // Given the "q:" prefix.
constexpr int MINIMUM_EVENT_ALLOWED_LENGTH = 4;
constexpr char FIRST_FULL_LOCATION_CHAR {'['};
} // namespace

Event parseWazuhEvent(const std::string& event)
{
    int msgStartIndex {0};

    auto parseEvent = std::make_shared<json::Json>();
    parseEvent->setObject();

    if (event.length() <= MINIMUM_EVENT_ALLOWED_LENGTH)
    {
        throw std::runtime_error(fmt::format("Invalid event format, event is too short ({})", event.length()));
    }

    if (':' != event[1])
    {
        throw std::runtime_error("Invalid event format, a colon was expected to be right after the first character");
    }

    const int queue {event[0]};
    parseEvent->setInt(queue, EVENT_QUEUE_ID);
    auto locationIdx = std::string::npos;
    // If we have an IPv6, double dots are preceded by a |
    for (auto i = LOCATION_OFFSET; i < event.size(); ++i)
    {
        if (event[i] == ':' && event[i - 1] != '|')
        {
            locationIdx = i;
            break;
        }
    }

    if (locationIdx == std::string::npos)
    {
        throw std::runtime_error("Invalid event format, a colon was expected to be right after the location");
    }

    std::string location = event.substr(LOCATION_OFFSET, locationIdx - LOCATION_OFFSET);
    {
        size_t pos;
        while ((pos = location.find("|:")) != std::string::npos)
        {
            location.erase(pos, 1);
        }
    }
    parseEvent->setString(location, EVENT_LOCATION_ID);
    parseEvent->setString(event.substr(locationIdx + 1), EVENT_MESSAGE_ID);

    return parseEvent;
}
} // namespace base::parseEvent
