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
#include "opBuilderCondition.hpp"
#include "opBuilderConditionReference.hpp"
#include "opBuilderConditionValue.hpp"
#include "opBuilderHelperFilter.hpp"
#include "stageBuilderCheck.hpp"

using namespace builder::internals::builders;

TEST(StageBuilderCheck, BuildsAllNonRegistered)
{
    Document doc{R"({
        "check": [
            {"field1": "value"},
            {"field2": 2},
            {"field3": "$field1"},
            {"field4": true},
            {"field5": "+exists"},
            {"field5": "+not_exists"}
        ]
    })"};

    ASSERT_THROW(builders::stageBuilderCheck(doc.get("/check")), std::_Nested_exception<std::runtime_error>);
}

TEST(StageBuilderCheck, Builds)
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
    c = combinatorBuilderChain;
    Registry::registerBuilder("combinator.chain", c);

    Document doc{R"({
        "check": [
            {"field1": "value"},
            {"field2": 2},
            {"field3": "$field1"},
            {"field4": true},
            {"field5": "+exists"},
            {"field5": "+not_exists"}
        ]
    })"};

    ASSERT_NO_THROW(builders::stageBuilderCheck(doc.get("/check")));
}

TEST(StageBuilderCheck, BuildsOperates)
{
    Document doc{R"({
        "check": [
            {"field1": "value"},
            {"field2": 2},
            {"field3": "$field1"},
            {"field4": true},
            {"field5": "+exists"},
            {"field6": "+not_exists"}
        ]
    })"};

    auto check = builders::stageBuilderCheck(doc.get("/check"));

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
                {"field":"values"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"({
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

    Observable output = check(input);

    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->get("/field1").GetString(), "value");
    ASSERT_EQ(expected[0]->get("/field2").GetInt(), 2);
    ASSERT_STREQ(expected[0]->get("/field3").GetString(), "value");
    ASSERT_TRUE(expected[0]->get("/field4").GetBool());
    ASSERT_NO_THROW(expected[0]->get("/field5"));
    ASSERT_FALSE(expected[0]->exists("/field6"));
}
