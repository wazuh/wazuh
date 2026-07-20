#ifndef _PARSE_EVENT_H
#define _PARSE_EVENT_H

#include <string>

#include <base/baseTypes.hpp>

namespace base::eventParsers
{
/// @brief Handler for legacy protocol events: (raw_event, agent_metadata) -> Event.
using ProtocolHandler = std::function<base::Event(std::string_view, const json::Json&)>;
/// @brief Handler for public protocol events: (queue, location, message, agent_metadata) -> Event.
using PublicProtocolHandler = std::function<base::Event(uint8_t, std::string&, std::string_view, const json::Json&)>;
// TODO: Add to the schema
constexpr char EVENT_QUEUE_ID[] {"/wazuh/protocol/queue"};     ///< JSON pointer for the queue field.
constexpr char EVENT_LOCATION_ID[] {"/wazuh/protocol/location"}; ///< JSON pointer for the location field.
constexpr char EVENT_MESSAGE_ID[] {"/event/original"};           ///< JSON pointer for the original message field.
constexpr char EVENT_AGENT_ID[] {"/agent/id"};                   ///< JSON pointer for the agent id field.
constexpr char EVENT_AGENT_NAME[] {"/agent/name"};               ///< JSON pointer for the agent name field.

/**
 * @brief Parse an Wazuh legacy message (4.x) and extract the queue, location and message
 *
 * @param event Wazuh message
 * @param agentMetadata Agent metadata information
 * @return Event Event object
 * @throw std::runtime_error if the message is not a valid Wazuh legacy message
 * @note The message must be in the format: "queue:location:message"
 */
Event parseLegacyEvent(std::string_view event, const json::Json& agentMetadata);

/**
 * @brief Parse a Wazuh public message and extract the queue, location and message
 *
 * @param queue Wazuh message queue
 * @param location Wazuh message location
 * @param message Wazuh message content
 * @param agentMetadata Agent metadata information
 * @return Event Event object
 * @throw std::runtime_error if the message is not a valid Wazuh public message
 * @note The message must be in the format: "queue:location:message"
 */
Event parsePublicEvent(uint8_t queue,
                       std::string& location,
                       std::string_view message,
                       const json::Json& agentMetadata);

} // namespace base::eventParsers

#endif // _EVENT_UTILS_H
