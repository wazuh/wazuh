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

using namespace builder::internals::builders;

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

    ASSERT_THROW(builders::stageBuilderNormalize(doc.get("/normalize")), std::_Nested_exception<std::runtime_error>);
}

TEST(StageBuilderNormalize, Builds)
{
    BuilderVariant c = opBuilderMapValue;
    Registry::registerBuilder("map.value", c);
    c = opBuilderMapReference;
    Registry::registerBuilder("map.reference", c);
    c = opBuilderMap;
    Registry::registerBuilder("map", c);
    c = combinatorBuilderChain;
    Registry::registerBuilder("combinator.chain", c);

    Document doc{R"({
        "normalize": [
            {"mapped.field1": "value"},
            {"mapped.field2": 2},
            {"mapped.field3": "$field1"},
            {"mapped.field4": true}
        ]
    })"};

    ASSERT_NO_THROW(builders::stageBuilderNormalize(doc.get("/normalize")));
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

    auto normalize = builders::stageBuilderNormalize(doc.get("/normalize"));

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
            // TODO: fix json interfaces to dont throw
            // s.on_next(std::make_shared<json::Document>(R"(
            //     {"field":"values"}
            // )"));
            s.on_next(std::make_shared<json::Document>(R"({
                "field1": "value",
                "field2": 2,
                "field3": "value",
                "field4": true,
                "field5": "+exists",
                "field6": "+exists"
            })"));
            // s.on_next(std::make_shared<json::Document>(R"(
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
        ASSERT_STREQ(e->get("/mapped/field1").GetString(), "value");
        ASSERT_EQ(e->get("/mapped/field2").GetInt(), 2);
        ASSERT_STREQ(e->get("/mapped/field3").GetString(), "value");
        ASSERT_TRUE(e->get("/mapped/field4").GetBool());
    }
}
