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

#include "assetBuilderFilter.hpp"

#include "combinatorBuilderChain.hpp"
#include "opBuilderCondition.hpp"
#include "opBuilderConditionReference.hpp"
#include "opBuilderConditionValue.hpp"
#include "opBuilderHelperFilter.hpp"
#include "stageBuilderCheck.hpp"

using namespace builder::internals::builders;

TEST(AssetBuilderFilter, BuildsAllNonRegistered)
{
    Document doc{R"({
        "name": "test",
        "after": [ "decoder" ],
        "allow": [
            {"field": "value"}
        ]
    })"};

    ASSERT_THROW(builders::assetBuilderFilter(doc), std::_Nested_exception<std::runtime_error>);
}

TEST(AssetBuilderFilter, Builds)
{
    BuilderVariant c = opBuilderConditionValue;
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
    Registry::registerBuilder("allow", c);
    c = combinatorBuilderChain;
    Registry::registerBuilder("combinator.chain", c);

    Document doc{R"({
        "name": "test",
        "after": [ "decoder" ],
        "allow": [
            {"field": "value"}
        ]
    })"};

    builders::assetBuilderFilter(doc);
}

TEST(AssetBuilderFilter, BuildsOperates)
{
    Document doc{R"({
        "name": "test",
        "after": [ "decoder" ],
        "allow": [
            {"field": "value"}
        ]
    })"};

    auto filter = builders::assetBuilderFilter(doc);

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
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

    Observable output = filter.connect(input);

    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    for (auto e : expected)
    {
        ASSERT_STREQ(e->get("/field").GetString(), "value");
    }
}
