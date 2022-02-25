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
TEST(opBuilderHelperStringLO, Builds)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_lo/abcd"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperStringLO(*doc.get("/check")));
}

// Build incorrect number of arguments
TEST(opBuilderHelperStringLO, BuildsIncorrectNumberOfArguments)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_lo/test_value/test_value2"}
    })"};
    ASSERT_THROW(opBuilderHelperStringLO(*doc.get("/check")), std::runtime_error);
}

// Test ok: static values
TEST(opBuilderHelperStringLO, staticStringOk)
{
    Document doc{R"({
        "check":
            {"fieltToCreate": "+s_lo/asd123ASD"}
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

    Lifter lift = opBuilderHelperStringLO(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) {expected.push_back(e);});
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0].get("/fieltToCreate")->GetString(), "asd123asd");
    ASSERT_STREQ(expected[1].get("/fieltToCreate")->GetString(), "asd123asd");
    ASSERT_STREQ(expected[2].get("/fieltToCreate")->GetString(), "asd123asd");
}

// Test ok: dynamic values (string)
TEST(opBuilderHelperStringLO, dynamicsStringOk) {

    Document doc{R"({
        "check":
            {"fieltToCreate": "+s_lo/$srcField"}
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

    Lifter lift = opBuilderHelperStringLO(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) {expected.push_back(e);});
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0].get("/fieltToCreate")->GetString(), "qwe");
    ASSERT_STREQ(expected[1].get("/fieltToCreate")->GetString(), "asd123asd");
    ASSERT_STREQ(expected[2].get("/fieltToCreate")->GetString(), "asd");
}

TEST(opBuilderHelperStringLO, multilevelSrc) {
      Document doc{R"({
        "check":
            {"fieltToCreate": "+s_lo/$a.b.c.srcField"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"a": {"b": {"c": {"srcField": "qwe"}}}}
            )"});
            s.on_next(Event{R"(
                {"a": {"b": {"c": {"srcField": "ASD123asd"}}}}
            )"});
            s.on_next(Event{R"(
                {"a": {"b": {"c": {"srcField": "ASD"}}}}
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringLO(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) {expected.push_back(e);});
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0].get("/fieltToCreate")->GetString(), "qwe");
    ASSERT_STREQ(expected[1].get("/fieltToCreate")->GetString(), "asd123asd");
    ASSERT_STREQ(expected[2].get("/fieltToCreate")->GetString(), "asd");
}

TEST(opBuilderHelperStringLO, multilevelDst) {
     Document doc{R"({
        "check":
            {"a.b.fieltToCreate.2": "+s_lo/$a.b.c.srcField"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"a": {"b": {"c": {"srcField": "qwe"}}}}
            )"});
            s.on_next(Event{R"(
                {"a": {"b": {"c": {"srcField": "ASD123asd"}}}}
            )"});
            s.on_next(Event{R"(
                {"a": {"b": {"c": {"srcField": "ASD"}}}}
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringLO(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) {expected.push_back(e);});
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0].get("/a/b/fieltToCreate/2")->GetString(), "qwe");
    ASSERT_STREQ(expected[1].get("/a/b/fieltToCreate/2")->GetString(), "asd123asd");
    ASSERT_STREQ(expected[2].get("/a/b/fieltToCreate/2")->GetString(), "asd");
}

TEST(opBuilderHelperStringLO, existDst) {
  Document doc{R"({
        "check":
            {"a.b": "+s_lo/$a.b.c.srcField"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"a": {"b": {"c": {"srcField": "qwe"}}}}
            )"});
            s.on_next(Event{R"(
                {"a": {"b": {"c": {"srcField": "ASD123asd"}}}}
            )"});
            s.on_next(Event{R"(
                {"a": {"b": {"c": {"srcField": "ASD"}}}}
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringLO(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) {expected.push_back(e);});
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0].get("/a/b")->GetString(), "qwe");
    ASSERT_STREQ(expected[1].get("/a/b")->GetString(), "asd123asd");
    ASSERT_STREQ(expected[2].get("/a/b")->GetString(), "asd");
}

TEST(opBuilderHelperStringLO, notExistSrc) {
 Document doc{R"({
    "check":
            {"a.b": "+s_lo/$srcField"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"a": {"b": "QWE"}}
            )"});
            s.on_next(Event{R"(
                {"c": {"d": "QWE123"}}
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringLO(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) {expected.push_back(e);});
    ASSERT_EQ(expected.size(), 2);
    ASSERT_STREQ(expected[0].get("/a/b")->GetString(), "QWE");
    ASSERT_FALSE(expected[1].exists("/a/b"));
}

TEST(opBuilderHelperStringLO, srcNotString) {
    Document doc{R"({
        "check":
            {"fieltToCreate": "+s_lo/$srcField123"}
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

    Lifter lift = opBuilderHelperStringLO(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) {expected.push_back(e);});
    ASSERT_EQ(expected.size(), 3);
    ASSERT_FALSE(expected[0].exists("/fieltToCreate"));
    ASSERT_FALSE(expected[1].exists("/fieltToCreate"));
    ASSERT_FALSE(expected[2].exists("/fieltToCreate"));
}