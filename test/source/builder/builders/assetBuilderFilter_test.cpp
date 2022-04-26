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

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

auto createEvent = [](const char * json){
    return std::make_shared<EventHandler>(std::make_shared<Document>(json));
};

TEST(AssetBuilderFilter, BuildsAllNonRegistered)
{
    Document doc{R"({
        "name": "test",
        "after": [ "decoder" ],
        "allow": [
            {"field": "value"}
        ]
    })"};

    ASSERT_THROW(bld::assetBuilderFilter(doc), std::_Nested_exception<std::runtime_error>);
}

TEST(AssetBuilderFilter, Builds)
{
    BuilderVariant c = bld::opBuilderConditionValue;
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
    Registry::registerBuilder("allow", c);
    c = bld::combinatorBuilderChain;
    Registry::registerBuilder("combinator.chain", c);

    Document doc{R"({
        "name": "test",
        "after": [ "decoder" ],
        "allow": [
            {"field": "value"}
        ]
    })"};

    bld::assetBuilderFilter(doc);
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

    auto filter = bld::assetBuilderFilter(doc);

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createEvent(R"({
                "field1": "value",
                "field2": 2,
                "field3": "value",
                "field4": true,
                "field5": "+exists"
            })"));
            s.on_next(createEvent(R"(
                {"field":"value"}
            )"));
            s.on_next(createEvent(R"({
                "field":"value",
                "field1": "value",
                "field2": 2,
                "field3": "value",
                "field4": true,
                "field5": "+exists",
                "field6": "+exists"
            })"));
            s.on_next(createEvent(R"(
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
        ASSERT_STREQ(e->getEvent()->get("/field").GetString(), "value");
    }
}
