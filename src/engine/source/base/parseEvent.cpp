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

    /**
     * There are two possible formats of events:
     *
     * 1st:
     *  <Queue_ID>:[<Agent_ID>] (<Agent_Name>) <Registered_IP>-><Origin>:<Log>
     *
     * 2nd:
     *  <Queue_ID>:<Syslog_Client_IP>:<Log>
     *
     *
     * Notes:
     *
     *  - `Queue_ID` is always 1 byte long.
     *
     *  - `Syslog_Client_IP` and `Registered_IP` and can be either IPv4 or IPv6.
     *
     *  - 2nd Format may be an IPv6 address, which contains ":", so special care has to be
     * taken with this particular case.
     */

    if (event.length() <= MINIMUM_EVENT_ALLOWED_LENGTH)
    {
        throw std::runtime_error(
            fmt::format("Invalid event format, event is too short ({})", event.length()));
    }

    if (':' != event[1])
    {
        throw std::runtime_error(fmt::format("Invalid event format, a colon was expected "
                                             "to be right after the first character"));
    }

    const int queue {event[0]};
    parseEvent->setInt(queue, EVENT_QUEUE_ID);

    const bool isFullLocation = (FIRST_FULL_LOCATION_CHAR == event[2]);

    const auto secondColonIdx {event.find(':', 2)};

    // Case: <Queue_ID>:[<Agent_ID>] (<Agent_Name>) <Registered_IP>-><Origin>:<Log>
    //                  \                                                  /
    //                   \------------------- LOCATION -------------------/
    if (isFullLocation)
    {
        int startIdx = LOCATION_OFFSET;
        int endIdx = LOCATION_OFFSET;
        try
        {
            // Agent_ID index is between '[' and ']'
            // As the format goes like: ...:[<Agent_ID>....
            endIdx = event.find(']', startIdx);
            uint32_t valueSize = (endIdx - startIdx) - 1;
            const auto agentId {event.substr(startIdx + 1, valueSize)};
            parseEvent->setString(agentId, EVENT_AGENT_ID);

            // Agent_Name is between '(' and ')'
            startIdx = endIdx + 2; // As the format goes like: ...] (<Agent_Name>...
            endIdx = event.find(')', startIdx);
            valueSize = (endIdx - startIdx) - 1;
            const auto agentName {event.substr(startIdx + 1, valueSize)};
            parseEvent->setString(agentName, EVENT_AGENT_NAME);

            // Registered_IP is between ' ' (a space) and "->" (an arrow)
            startIdx = endIdx + 1; // As the format goes like: ...) <Registered_IP>...
            endIdx = event.find("->", startIdx);
            valueSize = (endIdx - startIdx) - 1;
            const auto registeredIP {event.substr(startIdx + 1, valueSize)};
            parseEvent->setString(registeredIP, EVENT_REGISTERED_IP);

            // Origin is between "->" (an arrow) and ':'
            startIdx = endIdx + 1; // As the format goes like: ...-><Origin>...
            if (registeredIP.find(':') != std::string::npos)
            {
                // IPv6 case
                endIdx = event.find(':', endIdx + 2);
            }
            else
            {
                endIdx = secondColonIdx;
            }
            valueSize = (endIdx - startIdx) - 1;
            const auto origin {event.substr(startIdx + 1, valueSize)};
            parseEvent->setString(origin, EVENT_ORIGIN);
        }
        catch (std::runtime_error& e)
        {
            throw std::runtime_error(fmt::format(
                "An error occurred while parsing the \"location\" field of the event: {}",
                e.what()));
        }

        msgStartIndex = endIdx + 1;
    }
    // Case: <Queue_ID>:<Syslog_Client_IP>:<Log>
    else
    {
        // It is assumed that, if the ip is an IPv6, it is an EXTENDED IPv6. So, in the
        // sixth position of the event there should be a colon (':'), as the event should
        // have the following format: "q:XXXX:YYYY:ZZZZ:...".
        //                               |   |
        //                            idx=2 idx=6
        const auto ipVersion {(':' == event[6]) ? IPVersion::IPV6 : IPVersion::IPV4};

        if (IPVersion::IPV6 == ipVersion)
        {
            // As using extended IPv6, the actual log should start at the 42th position.
            // IPv6 Event:
            // q:SSSS:TTTT:UUUU:VVVV:WWWW:XXXX:YYYY:ZZZZ:log...
            //   |                                      |
            // idx=2                                 idx=41
            constexpr int LAST_COLON_INDEX = 41;

            if (event.length() < LAST_COLON_INDEX)
            {
                throw std::runtime_error(fmt::format(
                    "Invalid event format, event is too short ({})", event.length()));
            }

            try
            {
                const auto locationLength {LAST_COLON_INDEX - LOCATION_OFFSET};
                const std::string ipv6 = event.substr(LOCATION_OFFSET, locationLength);
                parseEvent->setString(ipv6, EVENT_ORIGIN);
            }
            catch (std::runtime_error& e)
            {
                throw fmt::format("An error occurred while parsing  the \"location\" "
                                  "field of  the event: {}",
                                  e.what());
            }

            msgStartIndex = LAST_COLON_INDEX + 1;
        }
        // IPVersion::IPV4
        else
        {
            try
            {
                const auto locationLength {secondColonIdx - LOCATION_OFFSET};
                const std::string ipv4 = event.substr(LOCATION_OFFSET, locationLength);
                parseEvent->setString(ipv4, EVENT_ORIGIN);
            }
            catch (std::runtime_error& e)
            {
                throw fmt::format("An error occurred while parsing the \"location\" "
                                  "field of the event: {}",
                                  e.what());
            }
            msgStartIndex = secondColonIdx + 1;
        }
    }

    try
    {
        const std::string message = event.substr(msgStartIndex, std::string::npos);
        parseEvent->setString(message, EVENT_LOG);
    }
    catch (std::runtime_error& e)
    {
        throw fmt::format("An error occurred while parsing the \"location\" field of  "
                          "the event: {}",
                          e.what());
    }

    // TODO Create event here
    return parseEvent;
}
} // namespace base
