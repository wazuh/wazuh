/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include "testUtils.hpp"
#include <vector>

#include "opBuilderHelperMap.hpp"

using namespace builder::internals::builders;

// Build ok
TEST(opBuilderHelperStringTrim, Builds)
{
    Document doc{R"({
        "normalize":
            {"fieldToTranf": "+s_trim/both/t"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperStringTrim(doc.get("/normalize")));
}

// Build incorrect number of arguments
TEST(opBuilderHelperStringTrim, Builds_incorrect_number_of_arguments)
{
    Document doc{R"({
        "normalize":
            {"fieldToTranf": "+s_trim/both/t/t"}
    })"};
    ASSERT_THROW(opBuilderHelperStringTrim(doc.get("/normalize")), std::runtime_error);
}

// Test ok: both trim
TEST(opBuilderHelperStringTrim, BothOk)
{
    Document doc{R"({
        "normalize":
            {"fieldToTranf": "+s_trim/both/-"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": "---hi---"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": "hi---"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": "---hi"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": "hi"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringTrim(doc.get("/normalize"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 4);
    ASSERT_STREQ(expected[0]->get("/fieldToTranf").GetString(), "hi");
    ASSERT_STREQ(expected[1]->get("/fieldToTranf").GetString(), "hi");
    ASSERT_STREQ(expected[2]->get("/fieldToTranf").GetString(), "hi");
}

TEST(opBuilderHelperStringTrim, Start_ok)
{
    Document doc{R"({
        "normalize":
            {"fieldToTranf": "+s_trim/begin/-"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": "---hi---"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": "hi---"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": "---hi"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": "hi"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringTrim(doc.get("/normalize"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 4);
    ASSERT_STREQ(expected[0]->get("/fieldToTranf").GetString(), "hi---");
    ASSERT_STREQ(expected[1]->get("/fieldToTranf").GetString(), "hi---");
    ASSERT_STREQ(expected[2]->get("/fieldToTranf").GetString(), "hi");
    ASSERT_STREQ(expected[3]->get("/fieldToTranf").GetString(), "hi");
}

// Test ok: dynamic values (string)
TEST(opBuilderHelperStringTrim, End_ok)
{
    Document doc{R"({
        "normalize":
            {"fieldToTranf": "+s_trim/end/-"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": "---hi---"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": "hi---"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": "---hi"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": "hi"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringTrim(doc.get("/normalize"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 4);
    ASSERT_STREQ(expected[0]->get("/fieldToTranf").GetString(), "---hi");
    ASSERT_STREQ(expected[1]->get("/fieldToTranf").GetString(), "hi");
    ASSERT_STREQ(expected[2]->get("/fieldToTranf").GetString(), "---hi");
    ASSERT_STREQ(expected[3]->get("/fieldToTranf").GetString(), "hi");
}

TEST(opBuilderHelperStringTrim, Multilevel_src)
{
    Document doc{R"({
        "normalize":
            {"fieldToTranf.a.b": "+s_trim/end/-"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": {"a": {"b": "---hi---"}}}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": {"a": {"b": "hi---"}}}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": {"a": {"b": "---hi"}}}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": {"a": {"b": "hi"}}}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringTrim(doc.get("/normalize"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 4);
    ASSERT_STREQ(expected[0]->get("/fieldToTranf/a/b").GetString(), "---hi");
    ASSERT_STREQ(expected[1]->get("/fieldToTranf/a/b").GetString(), "hi");
    ASSERT_STREQ(expected[2]->get("/fieldToTranf/a/b").GetString(), "---hi");
    ASSERT_STREQ(expected[3]->get("/fieldToTranf/a/b").GetString(), "hi");
}

TEST(opBuilderHelperStringTrim, Not_exist_src)
{
    Document doc{R"({
        "normalize":
            {"fieldToTranf": "+s_trim/end/-"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"not_ext": "---hi---"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringTrim(doc.get("/normalize"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_FALSE(expected[0]->exists("/fieldToTranf"));
}

TEST(opBuilderHelperStringTrim, Src_not_string)
{
    Document doc{R"({
        "normalize":
            {"fieldToTranf": "+s_trim/end/-"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": 15}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringTrim(doc.get("/normalize"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_TRUE(expected[0]->exists("/fieldToTranf"));
    ASSERT_EQ(expected[0]->get("/fieldToTranf").GetInt(), 15);
}

TEST(opBuilderHelperStringTrim, Multilevel)
{
    Document doc{R"({
        "normalize":
            {"fieldToTranf.a.b": "+s_trim/end/-"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": {"a": {"b": "---hi---"}}}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": {"a": {"b": "hi---"}}}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": {"a": {"b": "---hi"}}}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldToTranf": {"a": {"b": "hi"}}}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringTrim(doc.get("/normalize"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 4);
    ASSERT_STREQ(expected[0]->get("/fieldToTranf/a/b").GetString(), "---hi");
    ASSERT_STREQ(expected[1]->get("/fieldToTranf/a/b").GetString(), "hi");
    ASSERT_STREQ(expected[2]->get("/fieldToTranf/a/b").GetString(), "---hi");
    ASSERT_STREQ(expected[3]->get("/fieldToTranf/a/b").GetString(), "hi");
}
