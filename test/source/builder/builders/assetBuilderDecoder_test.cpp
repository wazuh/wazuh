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

#include "assetBuilderDecoder.hpp"

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

using namespace builder::internals::builders;

TEST(AssetBuilderDecoder, BuildsAllNonRegistered)
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

    ASSERT_THROW(builders::assetBuilderDecoder(doc), std::_Nested_exception<std::runtime_error>);
}

TEST(AssetBuilderDecoder, Builds)
{
    BuilderVariant c = opBuilderMapValue;
    Registry::registerBuilder("map.value", c);
    c = opBuilderMapReference;
    Registry::registerBuilder("map.reference", c);
    c = opBuilderMap;
    Registry::registerBuilder("map", c);
    c = combinatorBuilderChain;
    Registry::registerBuilder("combinator.chain", c);
    c = stageBuilderNormalize;
    Registry::registerBuilder("normalize", c);

    c = opBuilderConditionValue;
    Registry::registerBuilder("condition.value", c);
    c = opBuilderConditionReference;
    Registry::registerBuilder("condition.reference", c);
    c = opBuilderHelperExists;
    Registry::registerBuilder("helper.exists", c);
    c = opBuilderHelperNotExists;
    Registry::registerBuilder("helper.not_exists", c);
    c = opBuilderCondition;
    Registry::registerBuilder("condition", c);
    c = stageBuilderCheck;
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

    builders::assetBuilderDecoder(doc);
}

TEST(AssetBuilderDecoder, BuildsOperates)
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

    auto dec = builders::assetBuilderDecoder(doc);

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            //TODO: fix json interface to not throw exception
            s.on_next(std::make_shared<json::Document>(R"({
                "field1": "value",
                "field2": 2,
                "field3": "value",
                "field4": true,
                "field5": "+exists"
            })"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"({
                "field":"value",
                "field1": "value",
                "field2": 2,
                "field3": "value",
                "field4": true,
                "field5": "+exists",
                "field6": "+exists"
            })"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });

    Observable output = dec.connect(input);

    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    for (auto e : expected)
    {
        ASSERT_STREQ(e->get("/mapped/field").GetString(), "value");
    }
}
