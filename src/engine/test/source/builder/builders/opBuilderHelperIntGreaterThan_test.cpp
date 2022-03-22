/* Copyright (C) 2015-2021, Wazuh Inc.
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

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

TEST(opBuilderHelperIntGreaterThan, Builds)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_lt/10"}
    })"};

    ASSERT_NO_THROW(opBuilderHelperIntGreaterThan(doc.get("/check"), tr));
}

TEST(opBuilderHelperIntGreaterThan, Builds_error_bad_parameter)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_lt/test"}
    })"};

    ASSERT_THROW(opBuilderHelperIntGreaterThan(doc.get("/check"), tr),
                 std::invalid_argument);
}

TEST(opBuilderHelperIntGreaterThan, Builds_error_more_parameters)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_lt/10/10"}
    })"};

    ASSERT_THROW(opBuilderHelperIntGreaterThan(doc.get("/check"), tr), std::runtime_error);
}

TEST(opBuilderHelperIntGreaterThan, Exec_greater_than_ok)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_lt/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntGreaterThan(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 1);
    ASSERT_GT(expected[0]->get("/field_test").GetInt(), 10);
}

TEST(opBuilderHelperIntGreaterThan, Exec_greater_than_true)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_lt/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntGreaterThan(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 1);
    ASSERT_GT(expected[0]->get("/field_test").GetInt(), 10);
}

TEST(opBuilderHelperIntGreaterThan, Exec_greater_than_false)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_lt/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":9}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test2":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test3":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":8}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntGreaterThan(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 0);
}

TEST(opBuilderHelperIntGreaterThan, Exec_greater_than_ref_true)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_lt/$field_src"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test": 10,"field_src": 10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src":"10"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":"11","field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":"11","field_src":"10"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src":"10"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src":"test"}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntGreaterThan(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_GT(expected[0]->get("/field_test").GetInt(),
              expected[0]->get("/field_src").GetInt());
    ASSERT_GT(expected[1]->get("/field_test").GetInt(),
              expected[1]->get("/field_src").GetInt());
}

TEST(opBuilderHelperIntGreaterThan, Exec_greater_than_ref_false)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_ne/$field_src"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test2":11,"field_src":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":10,"field_src3":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":10,"field_src4":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test5":10,"field_src":"10"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test6":"10","field_src2":10}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_":"10","field_src":"10"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test":11,"field_src2":"10"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field_test2":10,"field_src2":"test"}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntGreaterThan(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 0);
}

TEST(opBuilderHelperIntGreaterThan, Exec_dynamics_int_ok)
{
    Document doc{R"({
        "check":
            {"field2check": "+i_eq/$ref_key"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // Greater
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field2check":11,
                    "ref_key":10
                }
            )"));
            // Equal
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field2check":10,
                    "ref_key":10
                }
            )"));
            // Less
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field2check":10,
                    "ref_key":11
                }
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperIntGreaterThan(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 1);
    ASSERT_GT(expected[0]->get("/field2check").GetInt(),
              expected[0]->get("/ref_key").GetInt());
}

TEST(opBuilderHelperIntGreaterThan, Exec_multilevel_dynamics_int_ok)
{
    Document doc{R"({
        "check":
            {"parentObjt_1.field2check": "+i_eq/$parentObjt_2.ref_key"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "parentObjt_2": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 11,
                        "ref_key": 11
                    }
                }
            )"));

            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "parentObjt_2": {
                        "field2check": 11,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                }
            )"));

            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "parentObjt_2": {
                        "field2check":10,
                        "ref_key":10
                    },
                    "parentObjt_1": {
                        "otherfield":12,
                        "ref_key":11
                    }
                }
            )"));

            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "parentObjt_2": {
                        "field2check":10,
                        "otherfield":10
                    },
                    "parentObjt_1": {
                        "field2check":12,
                        "ref_key":11
                    }
                }
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperIntGreaterThan(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 1);
    ASSERT_GT(expected[0]->get("/parentObjt_1/field2check").GetInt(),
              expected[0]->get("/parentObjt_2/ref_key").GetInt());
}