/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 */

#ifndef _OP_BUILDER_HELPER_ACTIVE_RESPONSE_H
#define _OP_BUILDER_HELPER_ACTIVE_RESPONSE_H

#include <any>

#include <baseTypes.hpp>

#include "expression.hpp"
#include <utils/stringUtils.hpp>

namespace builder::internals::builders
{

namespace ar
{
// TODO: move all the sockets to a shared utils directory
// TODO: when the api is merged these values can be obtained from "base".
constexpr const char* AR_QUEUE_PATH {"/var/ossec/queue/alerts/ar"};

constexpr const char* AGENT_ID_PATH {"/agent/id"};

// TODO: unify these parameters with the api ones
constexpr const char* MODULE_NAME {"wazuh-engine"};

constexpr const char* ORIGIN_NAME {"node01"};

constexpr const char* SUPPORTED_VERSION {"1"};
} // namespace ar

/**
 * @brief Helper Function that allows to send a message through the AR queue
 *
 * @param definition The transformation definition. i.e : `<field>: +ar_send/<str>|$<ref>`
 * @return base::Expression The lifter with the `ar_send` transformation.
 */
base::Expression opBuilderHelperSendAR(const std::any& definition);

/**
 * @brief Helper Function for creating the base event that will be sent through
 * Active Response socket with ar_send
 * ar_message: +ar_create/<command-name>/<location>/<timeout>/<extra-args>
 *  - <command-name> (mandatory) It can be set directly or through a reference.
 *  - <location>     (mandatory) Accepted values are: "LOCAL", "ALL" or a specific agent
 * id. Such values can be passed directly or through a reference.
 *  - <timeout>      (optional) Timeout value in seconds. It can be passed directly or
 * through a reference.
 *  - <extra-args>   (optional) Reference to an array of *strings*.
 *
 * @param definition
 * @return base::Expression
 */
base::Expression opBuilderHelperCreateAR(const std::any& definition);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_ACTIVE_RESPONSE_H
