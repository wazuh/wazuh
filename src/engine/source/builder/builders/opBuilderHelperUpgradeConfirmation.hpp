/* Copyright (C) 2015-2023, Wazuh Inc.
 * All rights reserved.
 *
 */

#ifndef _OP_BUILDER_HELPER_UPGRADE_CONFIRMATION_H
#define _OP_BUILDER_HELPER_UPGRADE_CONFIRMATION_H

#include <any>

#include <baseTypes.hpp>
#include <defs/idefinitions.hpp>
#include <sockiface/isockFactory.hpp>
#include <utils/stringUtils.hpp>

#include "expression.hpp"
#include "registry.hpp"

namespace builder::internals::builders
{

constexpr const char* WM_UPGRADE_SOCK {"/var/ossec/queue/tasks/upgrade"};

/**
 * @brief Sends upgrade confirmation throug UPGRADE_MQ socket
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression The ifter with the transformation.
 */
HelperBuilder getBuilderHelperSendUpgradeConfirmation(std::shared_ptr<sockiface::ISockFactory> sockFactory);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_UPGRADE_CONFIRMATION_H
