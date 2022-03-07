/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ASSET_BUILDER_OUTPUT_H
#define _ASSET_BUILDER_OUTPUT_H

#include "builderTypes.hpp"

namespace builder::internals::builders
{
/**
 * @brief Build output from json.
 *
 * @param def
 * @return types::ConnectableT
 */
types::ConnectableT assetBuilderOutput(const types::Document & def);
} // namespace builder::internals::builders

#endif // _ASSET_BUILDER_OUTPUT_H
