#include "parseEvent.hpp"

#include <fmt/format.h>
#include <logging/logging.hpp>

namespace base::parseEvent
{

namespace
{

constexpr int LOCATION_OFFSET = 2; // Given the "q:" prefix.
constexpr int MINIMUM_EVENT_ALLOWED_LENGTH = 4;
constexpr char FIRST_FULL_LOCATION_CHAR {'['};
} // namespace

Event parseOssecEvent(const std::string& event)
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
        throw std::runtime_error(fmt::format("Invalid event format, a colon was expected "
                                             "to be right after the first character"));
    }

    const int queue {event[0]};
    parseEvent->setInt(queue, EVENT_QUEUE_ID);
    auto locationIdx = event.find(':', LOCATION_OFFSET);
    if (locationIdx == std::string::npos)
    {
        throw std::runtime_error(fmt::format("Invalid event format, a colon was expected "
                                             "to be right after the location"));
    }
    // Check if we have an IPv6
    // It is assumed that, if the ip is an IPv6, it is a full format IPv6.

    // Check the double dots at each position in the IPv6
    auto i = locationIdx + 5;
    auto ipv6EndPosition = i + 30;
    for (; i < ipv6EndPosition; i += 5)
    {
        if (':' != event[i])
        {
            break;
        }
    }
    if (i >= ipv6EndPosition)
    {
        locationIdx = event.find(':', ipv6EndPosition);
    }

    parseEvent->setString(event.substr(LOCATION_OFFSET, locationIdx - LOCATION_OFFSET), EVENT_LOCATION_ID);
    parseEvent->setString(event.substr(locationIdx + 1), EVENT_MESSAGE_ID);

    // TODO Create event here
    return parseEvent;
}
} // namespace base::parseEvent
