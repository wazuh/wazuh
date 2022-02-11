/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OP_BUILDER_HELPER_EXISTS_H
#define _OP_BUILDER_HELPER_EXISTS_H

#include "builderTypes.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds helper exists operation.
 * Checks that a field is present in the event.
 *
 * @param def Definition of the operation to be built
 * @return types::Lifter
 */
types::Lifter opBuilderHelperExists(const types::DocumentValue & def);

/**
 * @brief Builds helper not_exists operation.
 * Checks that a field is not present in the event.
 *
 * @param def Definition of the operation to be built
 * @return types::Lifter
 */
types::Lifter opBuilderHelperNotExists(const types::DocumentValue & def);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_EXISTS_H
