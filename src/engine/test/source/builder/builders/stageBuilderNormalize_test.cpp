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

#include "combinatorBuilderChain.hpp"
#include "opBuilderMap.hpp"
#include "opBuilderMapReference.hpp"
#include "opBuilderMapValue.hpp"
#include "stageBuilderNormalize.hpp"

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

auto createEvent = [](const char * json){
    return std::make_shared<EventHandler>(std::make_shared<Document>(json));
};

TEST(StageBuilderNormalize, BuildsAllNonRegistered)
{
    Document doc{R"({
        "normalize": [
            {"mapped.field1": "value"},
            {"mapped.field2": 2},
            {"mapped.field3": "$field1"},
            {"mapped.field4": true}
        ]
    })"};

    ASSERT_THROW(bld::stageBuilderNormalize(doc.get("/normalize"), tr), std::_Nested_exception<std::runtime_error>);
}

TEST(StageBuilderNormalize, Builds)
{
    BuilderVariant c = bld::opBuilderMapValue;
    Registry::registerBuilder("map.value", c);
    c = bld::opBuilderMapReference;
    Registry::registerBuilder("map.reference", c);
    c = bld::opBuilderMap;
    Registry::registerBuilder("map", c);
    c = bld::combinatorBuilderChain;
    Registry::registerBuilder("combinator.chain", c);

    Document doc{R"({
        "normalize": [
            {"mapped.field1": "value"},
            {"mapped.field2": 2},
            {"mapped.field3": "$field1"},
            {"mapped.field4": true}
        ]
    })"};

    ASSERT_NO_THROW(builders::stageBuilderNormalize(doc.get("/normalize"), tr));
}

TEST(StageBuilderNormalize, BuildsOperates)
{
    Document doc{R"({
        "normalize": [
            {"mapped.field1": "value"},
            {"mapped.field2": 2},
            {"mapped.field3": "$field1"},
            {"mapped.field4": true}
        ]
    })"};

    auto normalize = builders::stageBuilderNormalize(doc.get("/normalize"), tr);

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
            // TODO: fix json interfaces to dont throw
            // s.on_next(createEvent(R"(
            //     {"field":"values"}
            // )"));
            s.on_next(createEvent(R"({
                "field1": "value",
                "field2": 2,
                "field3": "value",
                "field4": true,
                "field5": "+exists",
                "field6": "+exists"
            })"));
            // s.on_next(createEvent(R"(
            //     {"otherfield":1}
            // )"));
            s.on_completed();
        });

    Observable output = normalize(input);

    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    for (auto e : expected)
    {
        ASSERT_STREQ(e->getEvent()->get("/mapped/field1").GetString(), "value");
        ASSERT_EQ(e->getEvent()->get("/mapped/field2").GetInt(), 2);
        ASSERT_STREQ(e->getEvent()->get("/mapped/field3").GetString(), "value");
        ASSERT_TRUE(e->getEvent()->get("/mapped/field4").GetBool());
    }
}
