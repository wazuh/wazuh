#include "parseEvent.hpp"

#include <fmt/format.h>
#include <logging/logging.hpp>

namespace base::parseEvent
{

namespace
{
enum class IPVersion
{
    UNDEFINED,
    IPV4,
    IPV6
};

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
    // It is assumed that, if the ip is an IPv6, it is a full format IPv6. So, the event must be at least 40 characters
    // long + LOCATION_OFFSET + the last double dots
    // q:<full_ipv6>:<message>
    // And the first double dots must be at 6th position
    if (locationIdx == 6 && event.length() > LOCATION_OFFSET + 41)
    {
        // Check the double dots
        auto i = 10;
        for (; i < 43; i += 4)
        {
            if (':' != event[i])
            {
                break;
            }
        }
        if (i > 42)
        {
            locationIdx = 42;
        }
    }

    parseEvent->setString(event.substr(LOCATION_OFFSET, locationIdx - LOCATION_OFFSET), "/wazuh/location");
    parseEvent->setString(event.substr(locationIdx + 1), "/wazuh/message");

    // TODO Create event here
    return parseEvent;
}
} // namespace base::parseEvent
