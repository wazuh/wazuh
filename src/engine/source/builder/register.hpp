/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTER_HPP
#define _REGISTER_HPP

#include "builderTypes.hpp"
#include "registry.hpp"

// Add all builders includes here
#include "assetBuilderDecoder.hpp"
#include "assetBuilderFilter.hpp"
#include "assetBuilderOutput.hpp"
#include "assetBuilderRule.hpp"
#include "combinatorBuilderBroadcast.hpp"
#include "combinatorBuilderChain.hpp"
#include "opBuilderCondition.hpp"
#include "opBuilderConditionReference.hpp"
#include "opBuilderConditionValue.hpp"
#include "opBuilderFileOutput.hpp"
#include "OpBuilderHelperFilter.hpp"
#include "opBuilderMap.hpp"
#include "opBuilderMapReference.hpp"
#include "opBuilderMapValue.hpp"
#include "stageBuilderCheck.hpp"
#include "stageBuilderNormalize.hpp"
#include "stageBuilderOutputs.hpp"

namespace builder::internals
{
void registerBuilders()
{
    // Register all builders
    // Operations
    Registry::registerBuilder("map.value", builders::opBuilderMapValue);
    Registry::registerBuilder("map.reference", builders::opBuilderMapReference);
    Registry::registerBuilder("condition.value", builders::opBuilderConditionValue);
    Registry::registerBuilder("condition.reference", builders::opBuilderConditionReference);
    Registry::registerBuilder("file", builders::opBuilderFileOutput);
    // Auxiliary
    Registry::registerBuilder("condition", builders::opBuilderCondition);
    Registry::registerBuilder("map", builders::opBuilderMap);
    // Helpers
    Registry::registerBuilder("helper.exists", builders::opBuilderHelperExists);
    Registry::registerBuilder("helper.not_exists", builders::opBuilderHelperNotExists);
    // Combinators
    Registry::registerBuilder("combinator.chain", builders::combinatorBuilderChain);
    Registry::registerBuilder("combinator.broadcast", builders::combinatorBuilderBroadcast);
    // Stages
    Registry::registerBuilder("check", builders::stageBuilderCheck);
    Registry::registerBuilder("allow", builders::stageBuilderCheck);
    Registry::registerBuilder("normalize", builders::stageBuilderNormalize);
    Registry::registerBuilder("outputs", builders::stageBuilderOutputs);
    // Assets
    Registry::registerBuilder("decoder", builders::assetBuilderDecoder);
    Registry::registerBuilder("filter", builders::assetBuilderFilter);
    Registry::registerBuilder("rule", builders::assetBuilderRule);
    Registry::registerBuilder("output", builders::assetBuilderOutput);
}
} // namespace builder::internals

#endif // _REGISTER_HPP
