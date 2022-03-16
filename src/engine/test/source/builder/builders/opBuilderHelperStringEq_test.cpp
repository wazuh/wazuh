/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <vector>

#include "testUtils.hpp"
#include "opBuilderHelperFilter.hpp"

using namespace builder::internals::builders;

// Build ok
TEST(opBuilderHelperStringEQ, Builds)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_eq/test_value"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperStringEQ(doc.get("/check")));
}

// Build incorrect number of arguments
TEST(opBuilderHelperStringEQ, Builds_incorrect_number_of_arguments)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_eq/test_value/test_value2"}
    })"};
    ASSERT_THROW(opBuilderHelperStringEQ(doc.get("/check")), std::runtime_error);
}

// Test ok: static values
TEST(opBuilderHelperStringEQ, Static_string_ok)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_eq/test_value"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"not_test_value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"test_value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":"value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":"test_value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"test_value"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringEQ(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    ASSERT_STREQ(expected[0]->get("/field2check").GetString(), "test_value");
    ASSERT_STREQ(expected[1]->get("/field2check").GetString(), "test_value");
}

// Test ok: static values (numbers, compare as string)
TEST(opBuilderHelperStringEQ, Static_number_ok)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_eq/11"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"not_11"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"11"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":"11"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":11}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"11"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringEQ(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    ASSERT_STREQ(expected[0]->get("/field2check").GetString(), "11");
    ASSERT_STREQ(expected[1]->get("/field2check").GetString(), "11");
}

// Test ok: dynamic values (string)
TEST(opBuilderHelperStringEQ, Dynamics_string_ok)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_eq/$ref_key"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field2check":"not_test_value",
                    "ref_key":"test_value"
                }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field2check":"test_value",
                    "ref_key":"test_value"
                }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "otherfield":"value",
                    "ref_key":"test_value"
                }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "otherfield":"test_value",
                    "ref_key":"test_value"
                }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field2check":"test_value",
                    "ref_key":"test_value"
                }
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringEQ(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    ASSERT_STREQ(expected[0]->get("/field2check").GetString(), "test_value");
    ASSERT_STREQ(expected[1]->get("/field2check").GetString(), "test_value");
}

// Test ok: multilevel dynamic values (string)
TEST(opBuilderHelperStringEQ, MultiLevel_dynamics_string_ok)
{
    Document doc{R"({
        "check":
            {"parentObjt_1.field2check": "+s_eq/$parentObjt_2.ref_key"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // no
            s.on_next(std::make_shared<json::Document>(R"(
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
            )"));
            // yes
            s.on_next(std::make_shared<json::Document>(R"(
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
            )"));
            // no
            s.on_next(std::make_shared<json::Document>(R"(
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
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringEQ(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);

    ASSERT_STREQ(expected[0]->get("/parentObjt_1/field2check").GetString(),
                 expected[0]->get("/parentObjt_2/ref_key").GetString());

    ASSERT_STRNE(expected[0]->get("/parentObjt_2/field2check").GetString(), "test_value");
    ASSERT_STRNE(expected[0]->get("/parentObjt_1/ref_key").GetString(), "test_value");
}

// Test ok: dynamic values (number)
TEST(opBuilderHelperStringEQ, Dynamics_number_ok)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_eq/$ref_key"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field2check":11,
                    "ref_key":11
                }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field2check":"11",
                    "ref_key":11
                }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "otherfield":11,
                    "ref_key":11
                }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "otherfield":11,
                    "ref_key":11
                }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field2check":11,
                    "ref_key":"11"
                }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field2check":"11",
                    "not_ref_key":"11"
                }
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringEQ(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 0);
}
