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

#include "OpBuilderHelperMap.hpp"

using namespace builder::internals::builders;

// Build ok
TEST(opBuilderHelperString_up, Builds)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_up/abcd"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperString_up(*doc.get("/check")));
}

// Build incorrect number of arguments
TEST(opBuilderHelperString_up, BuildsIncorrectNumberOfArguments)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_up/test_value/test_value2"}
    })"};
    ASSERT_THROW(opBuilderHelperString_up(*doc.get("/check")), std::runtime_error);
}

// Test ok: static values
TEST(opBuilderHelperString_up, staticStringOk)
{
    Document doc{R"({
        "check":
            {"fieltToCreate": "+s_up/asd123asd"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"not_fieltToCreate": "qwe"}
            )"});
            s.on_next(Event{R"(
                {"not_fieltToCreate": "ASD123asd"}
            )"});
            s.on_next(Event{R"(
                {"not_fieltToCreate": "ASD"}
            )"});

            s.on_completed();
        });

    Lifter lift = opBuilderHelperString_up(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) {expected.push_back(e);});
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0].get("/fieltToCreate")->GetString(), "ASD123ASD");
    ASSERT_STREQ(expected[1].get("/fieltToCreate")->GetString(), "ASD123ASD");
    ASSERT_STREQ(expected[2].get("/fieltToCreate")->GetString(), "ASD123ASD");
}

// Test ok: dynamic values (string)
TEST(opBuilderHelperString_up, dynamicsStringOk) {

    Document doc{R"({
        "check":
            {"fieltToCreate": "+s_up/$srcField"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"srcField": "qwe"}
            )"});
            s.on_next(Event{R"(
                {"srcField": "ASD123asd"}
            )"});
            s.on_next(Event{R"(
                {"srcField": "ASD"}
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperString_up(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) {expected.push_back(e);});
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0].get("/fieltToCreate")->GetString(), "QWE");
    ASSERT_STREQ(expected[1].get("/fieltToCreate")->GetString(), "ASD123ASD");
    ASSERT_STREQ(expected[2].get("/fieltToCreate")->GetString(), "ASD");
}

TEST(opBuilderHelperString_up, multilevelSrc) {
    GTEST_SKIP();
    // TODO
}

TEST(opBuilderHelperString_up, multilevelDst) {
    GTEST_SKIP();
    // TODO
}

TEST(opBuilderHelperString_up, existDst) {
    GTEST_SKIP();
    // TODO
}

TEST(opBuilderHelperString_up, notExistSrc) {
    GTEST_SKIP();
    // TODO
}

TEST(opBuilderHelperString_up, srcNotString) {
    GTEST_SKIP();
    // TODO
}