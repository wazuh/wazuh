/* Copyright (C) 2015-2021, Wazuh Inc.
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

TEST(opBuilderHelperIntEqual, Builds)
{
    Document doc{R"({
        "check":
            {"field_test": "+int/10"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperIntEqual(*doc.get("/check")));
}

TEST(opBuilderHelperIntEqual, Builds_error_bad_parameter)
{
    Document doc{R"({
        "check":
            {"field_test": "+int/test"}
    })"};
    ASSERT_THROW(opBuilderHelperIntEqual(*doc.get("/check")), std::invalid_argument);
}

TEST(opBuilderHelperIntEqual, Builds_error_more_parameters)
{
    Document doc{R"({
        "check":
            {"field_test": "+int/10/10"}
    })"};
    ASSERT_THROW(opBuilderHelperIntEqual(*doc.get("/check")), std::runtime_error);
}

TEST(opBuilderHelperIntEqual, Exec_equal_ok)
{
    Document doc{R"({
        "check":
            {"field_test": "+int/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field_test":9}
            )"});
            s.on_next(Event{R"(
                {"field_test":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntEqual(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    ASSERT_EQ(expected[0].get("/field_test")->GetInt(),10);
    ASSERT_EQ(expected[1].get("/field_test")->GetInt(),10);

}

TEST(opBuilderHelperIntEqual, Exec_equal_true)
{
    Document doc{R"({
        "check":
            {"field_test": "+int/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field_test":9}
            )"});
            s.on_next(Event{R"(
                {"field_test":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntEqual(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    ASSERT_EQ(expected[0].get("/field_test")->GetInt(),10);
    ASSERT_EQ(expected[1].get("/field_test")->GetInt(),10);

}

TEST(opBuilderHelperIntEqual, Exec_equal_false)
{
    Document doc{R"({
        "check":
            {"field_test": "+int/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field_test":9}
            )"});
            s.on_next(Event{R"(
                {"field_test2":10}
            )"});
            s.on_next(Event{R"(
                {"field_test3":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntEqual(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 0);

}

TEST(opBuilderHelperIntEqual, Exec_equal_ref_true)
{
    Document doc{R"({
        "check":
            {"field_test": "+int/$field_src"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field_test": 9,"field_src": 10}
            )"});
            s.on_next(Event{R"(
                {"field_test":10,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":10,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":10,"field_src":"10"}
            )"});
            s.on_next(Event{R"(
                {"field_test":"10","field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":"10","field_src":"10"}
            )"});
            s.on_next(Event{R"(
                {"field_test":11,"field_src":"10"}
            )"});
            s.on_next(Event{R"(
                {"field_test":10,"field_src":"test"}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntEqual(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    auto str2Int = [](std::string s) {
        return std::stoi(s);
    };

    ASSERT_EQ(expected.size(), 2);
    ASSERT_EQ(expected[0].get("/field_test")->GetInt(),
              expected[0].get("/field_src")->GetInt());
    ASSERT_EQ(expected[1].get("/field_test")->GetInt(),
              expected[0].get("/field_src")->GetInt());

}

TEST(opBuilderHelperIntEqual, Exec_equal_ref_false)
{
    Document doc{R"({
        "check":
            {"field_test": "+int/$field_src"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field_test2":9,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":10,"field_src3":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":10,"field_src4":10}
            )"});
            s.on_next(Event{R"(
                {"field_test5":10,"field_src":"10"}
            )"});
            s.on_next(Event{R"(
                {"field_test6":"10","field_src2":10}
            )"});
            s.on_next(Event{R"(
                {"field_":"10","field_src":"10"}
            )"});
            s.on_next(Event{R"(
                {"field_test":11,"field_src2":"10"}
            )"});
            s.on_next(Event{R"(
                {"field_test2":10,"field_src2":"test"}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntEqual(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    auto str2Int = [](std::string s) {
        return std::stoi(s);
    };

    ASSERT_EQ(expected.size(), 0);

}
