/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "testUtils.hpp"

#include <vector>

#include <gtest/gtest.h>

#include "opBuilderConditionValue.hpp"

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

TEST(opBuilderConditionValue, Builds)
{
    Document doc{R"({
        "check": [
            {"string": "value"},
            {"int": 1},
            {"bool": true}
        ]
    })"};
    const auto & arr = doc.begin()->value.GetArray();
    for (auto it = arr.Begin(); it != arr.end(); ++it)
    {
        ASSERT_NO_THROW(bld::opBuilderConditionValue(*it, tr));
    }
}

TEST(opBuilderConditionValue, BuildsOperatesString)
{
    Document doc{R"({
        "check":
            {"field": "value"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":"value"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"values"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"otherfield":"value"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });
    Lifter lift = bld::opBuilderConditionValue(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEvent()->get("/field").GetString(), doc.get("/check").MemberBegin()->value.GetString());
}

TEST(opBuilderConditionValue, BuildsOperatesInt)
{
    Document doc{R"({
        "check":
            {"field": 1}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":2}
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
    Lifter lift = bld::opBuilderConditionValue(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEvent()->get("/field").GetInt(), doc.get("/check").MemberBegin()->value.GetInt());
}

TEST(opBuilderConditionValue, BuildsOperatesBool)
{
    Document doc{R"({
        "check":
            {"field": true}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":false}
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
    Lifter lift = bld::opBuilderConditionValue(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEvent()->get("/field").GetBool(), doc.get("/check").MemberBegin()->value.GetBool());
}

TEST(opBuilderConditionValue, BuildsOperatesNull)
{
    Document doc{R"({
        "check":
            {"field": null}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":null}
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
    Lifter lift = bld::opBuilderConditionValue(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEvent()->get("/field"), rapidjson::Value{});
}

TEST(opBuilderConditionValue, BuildsOperatesArray)
{
    Document doc{R"({
        "check":
            {"field": [1, 2]}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":false}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":[1, 2]}
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
    Lifter lift = bld::opBuilderConditionValue(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_TRUE(expected[0]->getEvent()->get("/field").IsArray());
    ASSERT_EQ(expected[0]->getEvent()->get("/field").GetArray().Size(), doc.get("/check").MemberBegin()->value.GetArray().Size());
    for (auto eIt = expected[0]->getEvent()->get("/field").GetArray().Begin(),
              it = doc.get("/check").MemberBegin()->value.GetArray().Begin();
         eIt != expected[0]->getEvent()->get("/field").GetArray().End(); ++eIt, ++it)
    {
        ASSERT_EQ(*eIt, *it);
    }
}

TEST(opBuilderConditionValue, BuildsOperatesObject)
{
    Document doc{R"({
        "check":
            {"field": {
                "int": 1,
                "bool": false,
                "null": null,
                "string": "value"
            }}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field": {
                    "int": 1,
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
    Lifter lift = bld::opBuilderConditionValue(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_TRUE(expected[0]->getEvent()->get("/field").IsObject());
    for (auto eIt = expected[0]->getEvent()->get("/field").GetObj().MemberBegin(),
              it = doc.get("/check").MemberBegin()->value.GetObj().MemberBegin();
         eIt != expected[0]->getEvent()->get("/field").GetObj().MemberEnd(); ++eIt, ++it)
    {
        ASSERT_EQ(eIt->name, it->name);
        ASSERT_EQ(eIt->value, it->value);
    }
}

TEST(opBuilderConditionValue, BuildsOperatesOneLevel)
{
    Document doc{R"({
        "check":
            {"field.level": 1}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":2}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":{"level": 1}}
            )"));
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
    Lifter lift = bld::opBuilderConditionValue(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEvent()->get("/field/level").GetInt(), doc.get("/check").MemberBegin()->value.GetInt());
}

TEST(opBuilderConditionValue, BuildsOperatesMultiLevel)
{
    Document doc{R"({
        "check":
            {"field.multi.level": 1}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":2}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field": {"multi": {"level": 1}}}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field": {"multi": {"level": "1"}}}
            )"));
            s.on_next(createSharedEvent(R"(
                {"otherfield":"value"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });
    Lifter lift = bld::opBuilderConditionValue(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEvent()->get("/field/multi/level").GetInt(), doc.get("/check").MemberBegin()->value.GetInt());
}
