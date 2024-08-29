
#ifndef _PARSE_EVENT_H
#define _PARSE_EVENT_H

#include <string>

#include <base/baseTypes.hpp>

namespace base::parseEvent
{
constexpr char EVENT_QUEUE_ID[] {"/wazuh/queue"};
constexpr char EVENT_LOCATION_ID[] {"/wazuh/location"};
constexpr char EVENT_MESSAGE_ID[] {"/event/original"};

/**
 * @brief Parse an Wazuh message and extract the queue, location and message
 *
 * @param event Wazuh message
 * @return Event Event object
 */
Event parseWazuhEvent(const std::string& event);

} // namespace base::parseEvent

#endif // _EVENT_UTILS_H
