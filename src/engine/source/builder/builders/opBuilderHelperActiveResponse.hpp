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
 * @brief Helper Function that 
 * 
 * @param definition 
 * @return base::Expression 
 */
base::Expression opBuilderHelperActiveResponse(const std::any& definition);
} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_ACTIVE_RESPONSE_H
