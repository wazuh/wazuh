/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include <gtest/gtest.h>
#include <testUtils.hpp>
#include <vector>

#include "OpBuilderHelperFilter.hpp"

using namespace builder::internals::builders;

// Build ok
TEST(opBuilderHelperString_ne, Builds)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_ne/test_value"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperString_ne(*doc.get("/check")));
}

// Build incorrect number of arguments
TEST(opBuilderHelperString_ne, BuildsIncorrectNumberOfArguments)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_ne/test_value/test_value2"}
    })"};
    ASSERT_THROW(opBuilderHelperString_ne(*doc.get("/check")), std::runtime_error);
}

// Test ok: static values
TEST(opBuilderHelperString_ne, staticStringOk)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_ne/test_value"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field2check":"not_test_value"}
            )"});
            s.on_next(Event{R"(
                {"field2check":"test_value"}
            )"});
            s.on_next(Event{R"(
                {"otherfield":"value"}
            )"});
            s.on_next(Event{R"(
                {"otherfield":"test_value"}
            )"});
            s.on_next(Event{R"(
                {"field2check":"test_value"}
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperString_ne(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    EXPECT_STRNE(expected[0].get("/field2check")->GetString(), "test_value");
    EXPECT_EQ(expected[1].get("/field2check"), nullptr);
    EXPECT_EQ(expected[2].get("/field2check"), nullptr);

}

// Test ok: static values (numbers, compare as string)
TEST(opBuilderHelperString_ne, staticNumberOk)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_ne/11"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // yes
            s.on_next(Event{R"(
                {"field2check":"not_11"}
            )"});
            // no
            s.on_next(Event{R"(
                {"field2check":"11"}
            )"});
            // yes
            s.on_next(Event{R"(
                {"otherfield":"11"}
            )"});
            // yes
            s.on_next(Event{R"(
                {"otherfield":11}
            )"});
            // no
            s.on_next(Event{R"(
                {"field2check":"11"}
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperString_ne(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    EXPECT_STRNE(expected[0].get("/field2check")->GetString(), "11");
    EXPECT_EQ(expected[1].get("/field2check"), nullptr);
    EXPECT_EQ(expected[2].get("/field2check"), nullptr);

}

// Test ok: dynamic values (string)
TEST(opBuilderHelperString_ne, dynamicsStringOk) {
    Document doc{R"({
        "check":
            {"field2check": "+s_ne/$ref_key"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {
                    "field2check":"not_test_value",
                    "ref_key":"test_value"
                }
            )"});
            s.on_next(Event{R"(
                {
                    "field2check":"test_value",
                    "ref_key":"test_value"
                }
            )"});
            s.on_next(Event{R"(
                {
                    "otherfield":"value",
                    "ref_key":"test_value"
                }
            )"});
            s.on_next(Event{R"(
                {
                    "otherfield":"test_value",
                    "ref_key":"test_value"
                }
            )"});
            s.on_next(Event{R"(
                {
                    "field2check":"test_value",
                    "ref_key":"test_value"
                }
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperString_ne(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STRNE(expected[0].get("/field2check")->GetString(), expected[0].get("/ref_key")->GetString());
    ASSERT_EQ(expected[1].get("/field2check"), nullptr);
    ASSERT_EQ(expected[2].get("/field2check"), nullptr);
}


// Test ok: multilevel dynamic values (string)
TEST(opBuilderHelperString_ne, multiLevelDynamicsStringOk) {
    Document doc{R"({
        "check":
            {"parentObjt_1.field2check": "+s_ne/$parentObjt_2.ref_key"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // yes
            s.on_next(Event{R"(
                {
                    "parentObjt_2": {
                        "field2check": "test_value",
                        "ref_key": "test_value"
                    },
                    "parentObjt_1": {
                        "field2check": "not_test_value",
                        "ref_key": "123_not_test_value"
                    }
                }
            )"});
            // no
            s.on_next(Event{R"(
                {
                    "parentObjt_2": {
                        "field2check": "not_test_value",
                        "ref_key": "test_value"
                    },
                    "parentObjt_1": {
                        "field2check": "test_value",
                        "ref_key": "not_test_value"
                    }
                }
            )"});
            // yes
            s.on_next(Event{R"(
                {
                    "parentObjt_2": {
                        "field2check":"test_value",
                        "ref_key":"test_value"
                    },
                    "parentObjt_1": {
                        "otherfield":"value",
                        "ref_key":"not_test_value"
                    }
                }
            )"});
            // yes
            s.on_next(Event{R"(
                {
                    "parentObjt_2": {
                        "field2check":"test_value",
                        "otherfield":"test_value"
                    },
                    "parentObjt_1": {
                        "field2check":"value",
                        "ref_key":"not_test_value"
                    }
                }
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperString_ne(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) {
        expected.push_back(e);
    });
    ASSERT_EQ(expected.size(), 3);

    ASSERT_STRNE(expected[0].get("/parentObjt_1/field2check")->GetString(),
                 expected[0].get("/parentObjt_2/ref_key")->GetString());

    ASSERT_EQ(expected[1].get("/parentObjt_1/field2check"), nullptr);
    ASSERT_NE(expected[1].get("/parentObjt_2/ref_key"), nullptr);

    ASSERT_NE(expected[2].get("/parentObjt_1/field2check"), nullptr);
    ASSERT_EQ(expected[2].get("/parentObjt_2/ref_key"), nullptr);

}


// Test ok: dynamic values (number)
TEST(opBuilderHelperString_ne, dynamicsNumberOk) {
    Document doc{R"({
        "check":
            {"field2check": "+s_ne/$ref_key"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {
                    "field2check":11,
                    "ref_key":11
                }
            )"});
            s.on_next(Event{R"(
                {
                    "field2check":"11",
                    "ref_key":11
                }
            )"});
            s.on_next(Event{R"(
                {
                    "otherfield":11,
                    "ref_key":11
                }
            )"});
            s.on_next(Event{R"(
                {
                    "field2check":11,
                    "ref_key":"11"
                }
            )"});
            s.on_next(Event{R"(
                {
                    "field2check":"11",
                    "not_ref_key":"11"
                }
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperString_ne(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 5);
    ASSERT_FALSE(expected[0].get("/field2check")->IsString());
    ASSERT_FALSE(expected[0].get("/ref_key")->IsString());

    ASSERT_TRUE(expected[1].get("/field2check")->IsString());
    ASSERT_FALSE(expected[1].get("/ref_key")->IsString());

    ASSERT_EQ(expected[2].get("/field2check"), nullptr);

    ASSERT_FALSE(expected[3].get("/field2check")->IsString());
    ASSERT_TRUE(expected[3].get("/ref_key")->IsString());

}



