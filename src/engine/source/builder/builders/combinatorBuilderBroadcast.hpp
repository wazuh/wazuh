/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _COMBINATOR_BUILDER_BROADCAST_H
#define _COMBINATOR_BUILDER_BROADCAST_H

#include "builderTypes.hpp"

namespace builder::internals::builders
{

/**
 * @brief Broadcast to multiple lifters
 *
 * @param lifters
 * @return base::Lifter
 */
base::Lifter
combinatorBuilderBroadcast(const std::vector<base::Lifter> &lifters);

} // namespace builder::internals::builders

#endif // _COMBINATOR_BUILDER_BROADCAST_H
