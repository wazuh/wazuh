#ifndef _PROTOCOL_HANDLER_H
#define _PROTOCOL_HANDLER_H

#include <nlohmann/json.hpp>
#include <string>

namespace server::protocolhandler
{
/**
 * @brief Used to differenciate the Wazuh events source
 */
enum MessageQueue
{
    UNKNOWN = 0,
    SYSLOG,
    IDS,
    FIREWALL,
    RSV1,
    RSV2,
    RSV3,
    APACHE,
    SQUID,
    WINDOWS,
    HOST_INFO,
    WAZUH_RULES,
    WAZUH_ALERTS
};

/**
 * @brief Extracts the Queue; Location and Message from the Wazuh event and creates a JSON object with them
 *
 * @param event String to be parsed
 * @return nlohmann::json Object containing the event in JSON format
 */
nlohmann::json parseEvent(const std::string & event);
} // namespace server::protocolhandler

#endif // _PROTOCOL_HANDLER_H
