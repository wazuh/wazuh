/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include "testUtils.hpp"

#include "assetBuilderRule.hpp"

#include "combinatorBuilderChain.hpp"
#include "opBuilderCondition.hpp"
#include "opBuilderConditionReference.hpp"
#include "opBuilderConditionValue.hpp"
#include "opBuilderHelperFilter.hpp"
#include "stageBuilderCheck.hpp"

#include "opBuilderMap.hpp"
#include "opBuilderMapReference.hpp"
#include "opBuilderMapValue.hpp"
#include "stageBuilderNormalize.hpp"

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

TEST(AssetBuilderRule, BuildsAllNonRegistered)
{
    Document doc{R"({
        "name": "test",
        "check": [
            {"field": "value"}
        ],
        "normalize": [
            {"mapped.field": "$field"}
        ]
    })"};

    ASSERT_THROW(bld::assetBuilderRule(doc), std::_Nested_exception<std::runtime_error>);
}

TEST(AssetBuilderRule, Builds)
{
    BuilderVariant c = bld::opBuilderMapValue;
    Registry::registerBuilder("map.value", c);
    c = bld::opBuilderMapReference;
    Registry::registerBuilder("map.reference", c);
    c = bld::opBuilderMap;
    Registry::registerBuilder("map", c);
    c = bld::combinatorBuilderChain;
    Registry::registerBuilder("combinator.chain", c);
    c = bld::stageBuilderNormalize;
    Registry::registerBuilder("normalize", c);

    c = bld::opBuilderConditionValue;
    Registry::registerBuilder("condition.value", c);
    c = bld::opBuilderConditionReference;
    Registry::registerBuilder("condition.reference", c);
    c = bld::opBuilderHelperExists;
    Registry::registerBuilder("helper.exists", c);
    c = bld::opBuilderHelperNotExists;
    Registry::registerBuilder("helper.not_exists", c);
    c = bld::opBuilderCondition;
    Registry::registerBuilder("condition", c);
    c = bld::stageBuilderCheck;
    Registry::registerBuilder("check", c);

    Document doc{R"({
        "name": "test",
        "check": [
            {"field": "value"}
        ],
        "normalize": [
            {"mapped.field": "$field"}
        ]
    })"};

    ASSERT_NO_THROW(bld::assetBuilderRule(doc));
}

TEST(AssetBuilderRule, BuildsOperates)
{
    Document doc{R"({
        "name": "test",
        "check": [
            {"field": "value"}
        ],
        "normalize": [
            {"mapped.field": "$field"}
        ]
    })"};

    auto rule = bld::assetBuilderRule(doc);

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // TODO: fix json interface to not throw exception
            s.on_next(createSharedEvent(R"({
                "field1": "value",
                "field2": 2,
                "field3": "value",
                "field4": true,
                "field5": "+exists"
            })"));
            s.on_next(createSharedEvent(R"(
                {"field":"value"}
            )"));
            s.on_next(createSharedEvent(R"({
                "field":"value",
                "field1": "value",
                "field2": 2,
                "field3": "value",
                "field4": true,
                "field5": "+exists",
                "field6": "+exists"
            })"));
            s.on_next(createSharedEvent(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });

    Observable output = rule.connect(input);

    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    for (auto e : expected)
    {
        ASSERT_STREQ(e->getEvent()->get("/mapped/field").GetString(), "value");
    }
}
