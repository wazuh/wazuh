#ifndef _PARSE_EVENT_H
#define _PARSE_EVENT_H

#include <string>

#include <base/baseTypes.hpp>

namespace base::eventParsers
{
using ProtocolHandler = std::function<base::Event(std::string_view)>;
// TODO: Add to the schema
constexpr char EVENT_QUEUE_ID[] {"/wazuh/queue"};
constexpr char EVENT_LOCATION_ID[] {"/wazuh/location"};
constexpr char EVENT_MESSAGE_ID[] {"/event/original"};
constexpr char EVENT_AGENT_ID[] {"/agent/id"};
constexpr char EVENT_AGENT_NAME[] {"/agent/name"};
constexpr char EVENT_MANAGER_NAME[] {"/agent/manager_name"};

/**
 * @brief Parse an Wazuh legacy message (4.x) and extract the queue, location and message
 *
 * @param event Wazuh message
 * @return Event Event object
 * @throw std::runtime_error if the message is not a valid Wazuh legacy message
 * @note The message must be in the format: "queue:location:message"
 */
Event parseLegacyEvent(std::string_view event);

} // namespace base::eventParsers

#endif // _EVENT_UTILS_H
