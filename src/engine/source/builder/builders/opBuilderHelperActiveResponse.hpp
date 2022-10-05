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

/**
 * @brief Helper Function for creating the base event that will be sent through
 * Active Response socket with ar_write
 * _message: +ar_create/<event>/<command-name>/<location>/<timeout>/<$_args>
 *  - <event>        (mandatory) Original event
 *  - <command-name> (mandatory) Any string or reference.
 *  - <location>     (mandatory) LOCAL, AGENT_IT (in integer), ALL.
 *  - <timeout>      (optional) Integer timeout value.
 *  - <$_args>       (optional) Reference to an array of strings.
 *
 * @param definition 
 * @return base::Expression 
 */
base::Expression opBuilderHelperCreateAR(const std::any& definition);
} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_ACTIVE_RESPONSE_H
