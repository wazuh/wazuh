
#ifndef _PARSE_EVENT_H
#define _PARSE_EVENT_H

#include <string>

#include "baseTypes.hpp"

namespace base::parseEvent
{

constexpr char EVENT_AGENT_ID[] {"/agent/id"};
constexpr char EVENT_AGENT_NAME[] {"/agent/name"};
constexpr char EVENT_LOG[] {"/event/original"};
constexpr char EVENT_QUEUE_ID[] {"/wazuh/queue"};
constexpr char EVENT_REGISTERED_IP[] {"/agent/registeredIP"};
constexpr char EVENT_ORIGIN[] {"/wazuh/origin"};
/**
 * @brief generate a json::Document from internal state
 *
 * @return json::Document
 */
Event parseOssecEvent(const std::string& event);

} // namespace base

#endif // _EVENT_UTILS_H