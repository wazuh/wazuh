/* Copyright (C) 2015-2023, Wazuh Inc.
 * All rights reserved.
 *
 */

#ifndef _OP_BUILDER_HELPER_UPGRADE_CONFIRMATION_H
#define _OP_BUILDER_HELPER_UPGRADE_CONFIRMATION_H

#include <any>

#include <baseTypes.hpp>

#include "expression.hpp"
#include <utils/stringUtils.hpp>

namespace builder::internals::builders
{

constexpr const char* WM_UPGRADE_SOCK {"/var/ossec/queue/tasks/upgrade"};

/**
 * @brief Sends upgrade confirmation throug UPGRADE_MQ socket
 *
 * @param definition The transformation definition.
 * @return base::Expression The ifter with the transformation.
 */
base::Expression opBuilderHelperSendUpgradeConfirmation(const std::any& definition);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_UPGRADE_CONFIRMATION_H
