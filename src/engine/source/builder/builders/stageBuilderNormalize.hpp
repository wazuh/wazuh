/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _STAGE_BUILDER_NORMALIZE_H
#define _STAGE_BUILDER_NORMALIZE_H

#include "builderTypes.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds stage check
 *
 * @param def
 * @return types::Lifter
 */
types::Lifter stageBuilderNormalize(const types::DocumentValue & def);

} // namespace builder::internals::builders

#endif // _STAGE_BUILDER_NORMALIZE_H
