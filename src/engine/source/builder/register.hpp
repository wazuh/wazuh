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
#include "opBuilderHelperExists.hpp"
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
    // Needed to initialize the variant type
    types::BuilderVariant c;

    // Register all builders
    c = builders::opBuilderMapValue;
    Registry::registerBuilder("map.value", c);
    c = builders::opBuilderMapReference;
    Registry::registerBuilder("map.reference", c);
    c = builders::opBuilderMap;
    Registry::registerBuilder("map", c);
    c = builders::combinatorBuilderChain;
    Registry::registerBuilder("combinator.chain", c);
    c = builders::combinatorBuilderBroadcast;
    Registry::registerBuilder("combinator.broadcast", c);
    c = builders::opBuilderConditionValue;
    Registry::registerBuilder("condition.value", c);
    c = builders::opBuilderConditionReference;
    Registry::registerBuilder("condition.reference", c);
    c = builders::opBuilderHelperExists;
    Registry::registerBuilder("helper.exists", c);
    c = builders::opBuilderHelperNotExists;
    Registry::registerBuilder("helper.not_exists", c);
    c = builders::opBuilderFileOutput;
    Registry::registerBuilder("file", c);
    c = builders::opBuilderCondition;
    Registry::registerBuilder("condition", c);
    c = builders::stageBuilderNormalize;
    Registry::registerBuilder("normalize", c);
    c = builders::stageBuilderCheck;
    Registry::registerBuilder("check", c);
    Registry::registerBuilder("allow", c);
    c = builders::stageBuilderOutputs;
    Registry::registerBuilder("outputs", c);
    c = builders::assetBuilderDecoder;
    Registry::registerBuilder("decoder", c);
    c = builders::assetBuilderFilter;
    Registry::registerBuilder("filter", c);
    c = builders::assetBuilderRule;
    Registry::registerBuilder("rule", c);
    c = builders::assetBuilderOutput;
    Registry::registerBuilder("output", c);
}
} // namespace builder::internals

#endif // _REGISTER_HPP
