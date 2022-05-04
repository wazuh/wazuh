/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "testUtils.hpp"
#include <gtest/gtest.h>

#include <vector>

#include "opBuilderCondition.hpp"

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

TEST(opBuilderConditionReference, Builds)
{
    Document doc{R"({
        "check":
            {"field": "$reference"}
    })"};
    ASSERT_NO_THROW(bld::opBuilderCondition(doc.get("/check"), tr));
}

TEST(opBuilderConditionReference, BuildsOperatesString)
{
    Document doc{R"({
        "check":
            {"otherfield": "$field"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {
                    "field":"value1",
                    "otherfield":"value1"
                }
            )"));
            s.on_next(createSharedEvent(R"(
                {
                    "field":"value1",
                    "otherfield":"value2"
                }
            )"));
            s.on_next(createSharedEvent(R"(
                {
                    "otherfield":"value1"
                }
            )"));
            s.on_next(createSharedEvent(R"(
                {
                    "field":"value1"
                }
            )"));
            s.on_completed();
        });
    Lifter lift = bld::opBuilderCondition(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEvent()->get("/field").GetString(), "value1");
    ASSERT_STREQ(expected[0]->getEvent()->get("/otherfield").GetString(), "value1");
}

TEST(opBuilderConditionReference, BuildsOperatesInt)
{
    Document doc{R"({
        "check":
            {"otherfield": "$field"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {
                    "field":1,
                    "otherfield":1
                }
            )"));
            s.on_next(createSharedEvent(R"(
                {
                    "field":1,
                    "otherfield":2
                }
            )"));
            s.on_next(createSharedEvent(R"(
                {
                    "otherfield":"value1"
                }
            )"));
            s.on_next(createSharedEvent(R"(
                {
                    "field":"value1"
                }
            )"));
            s.on_completed();
        });
    Lifter lift = bld::opBuilderCondition(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEvent()->get("/field").GetInt(), 1);
    ASSERT_EQ(expected[0]->getEvent()->get("/otherfield").GetInt(), 1);
}

TEST(opBuilderConditionReference, BuildsOperatesBool)
{
    Document doc{R"({
        "check":
            {"otherfield": "$field"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {
                    "field":true,
                    "otherfield":true
                }
            )"));
            s.on_next(createSharedEvent(R"(
                {
                    "field":true,
                    "otherfield":false
                }
            )"));
            s.on_next(createSharedEvent(R"(
                {
                    "otherfield":"value1"
                }
            )"));
            s.on_next(createSharedEvent(R"(
                {
                    "field":"value1"
                }
            )"));
            s.on_completed();
        });
    Lifter lift = bld::opBuilderCondition(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_TRUE(expected[0]->getEvent()->get("/field").GetBool());
    ASSERT_TRUE(expected[0]->getEvent()->get("/otherfield").GetBool());
}

TEST(opBuilderConditionReference, BuildsOperatesNull)
{
    Document doc{R"({
        "check":
            {"otherfield": "$field"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {
                    "field":null,
                    "otherfield":null
                }
            )"));
            s.on_next(createSharedEvent(R"(
                {
                    "field":null,
                    "otherfield":false
                }
            )"));
            s.on_next(createSharedEvent(R"(
                {
                    "otherfield":"value1"
                }
            )"));
            s.on_next(createSharedEvent(R"(
                {
                    "field":"value1"
                }
            )"));
            s.on_completed();
        });
    Lifter lift = bld::opBuilderCondition(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEvent()->get("/field"), rapidjson::Value{});
}

TEST(opBuilderConditionReference, BuildsOperatesArray)
{
    Document doc{R"({
        "check":
            {"otherfield": "$field"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {
                    "field":[1, 2],
                    "otherfield":[1, 2]
                }
            )"));
            s.on_next(createSharedEvent(R"(
                {
                    "field":[1, 2],
                    "otherfield":[1, 2, 3]
                }
            )"));
            s.on_next(createSharedEvent(R"(
                {
                    "otherfield":"value1"
                }
            )"));
            s.on_next(createSharedEvent(R"(
                {
                    "field":"value1"
                }
            )"));
            s.on_completed();
        });
    Lifter lift = bld::opBuilderCondition(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_TRUE(expected[0]->getEvent()->get("/field").IsArray());
    ASSERT_EQ(expected[0]->getEvent()->get("/field").GetArray().Size(), expected[0]->getEvent()->get("/otherfield").GetArray().Size());
    for (auto eIt = expected[0]->getEvent()->get("/field").GetArray().Begin(),
              it = expected[0]->getEvent()->get("/otherfield").GetArray().Begin();
         eIt != expected[0]->getEvent()->get("/field").GetArray().End(); ++eIt, ++it)
    {
        ASSERT_EQ(*eIt, *it);
    }
}

TEST(opBuilderConditionReference, BuildsOperatesObject)
{
    Document doc{R"({
        "check":
            {"otherfield": "$field"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
            {
                "field": {
                    "int": 1,
                    "bool": false,
                    "null": null,
                    "string": "value"
                },
                "otherfield": {
                    "int": 1,
                    "bool": false,
                    "null": null,
                    "string": "value"
                }
            }
            )"));
            s.on_next(createSharedEvent(R"(
            {
                "field": {
                    "int": 1,
                    "bool": false,
                    "null": null,
                    "string": "value"
                },
                "otherfield": {
                    "int": 2,
                    "bool": false,
                    "null": null,
                    "string": "value"
                }
            }
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":true}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":1}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"1"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"otherfield":"value"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });
    Lifter lift = bld::opBuilderCondition(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_TRUE(expected[0]->getEvent()->get("/field").IsObject());
    ASSERT_TRUE(expected[0]->getEvent()->get("/otherfield").IsObject());
    for (auto eIt = expected[0]->getEvent()->get("/field").GetObj().MemberBegin(),
              it = expected[0]->getEvent()->get("/otherfield").GetObj().MemberBegin();
         eIt != expected[0]->getEvent()->get("/field").GetObj().MemberEnd(); ++eIt, ++it)
    {
        ASSERT_EQ(eIt->name, it->name);
        ASSERT_EQ(eIt->value, it->value);
    }
}

TEST(opBuilderConditionReference, BuildsOperatesOneLevel)
{
    Document doc{R"({
        "check":
            {"field.level": "$otherfield.level"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":2}
            )"));
            s.on_next(createSharedEvent(R"({
                "field":{"level": 1},
                "otherfield":{"level": 1}
            })"));
            s.on_next(createSharedEvent(R"({
                "field":{"level": 1},
                "otherfield":{"level": 2}
            })"));
            s.on_next(createSharedEvent(R"(
                {"field":{"level": "1"}}
            )"));
            s.on_next(createSharedEvent(R"(
                {"otherfield":"value"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });
    Lifter lift = bld::opBuilderCondition(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEvent()->get("/field/level").GetInt(), expected[0]->getEvent()->get("/otherfield/level").GetInt());
}

TEST(opBuilderConditionReference, BuildsOperatesMultiLevel)
{
    Document doc{R"({
        "check":
            {"field.multi.level": "$otherfield.multi.level"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":2}
            )"));
            s.on_next(createSharedEvent(R"({
                "field":{"multi": {"level": 1}},
                "otherfield":{"multi": {"level": 1}}
            })"));
            s.on_next(createSharedEvent(R"({
                "field":{"multi": {"level": 1}},
                "otherfield":{"multi": {"level": 2}}
            })"));
            s.on_next(createSharedEvent(R"(
                {"field":{"level": "1"}}
            )"));
            s.on_next(createSharedEvent(R"(
                {"otherfield":"value"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });
    Lifter lift = bld::opBuilderCondition(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEvent()->get("/field/multi/level").GetInt(), expected[0]->getEvent()->get("/otherfield/multi/level").GetInt());
}
