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

TEST(opBuilderHelperNotExists, Builds)
{
    Document doc{R"({
        "check":
            {"field": "+not_exists"}
    })"};

    ASSERT_NO_THROW(opBuilderHelperNotExists(doc.get("/check")));
}

TEST(opBuilderHelperNotExists, Builds_error_bad_parameter)
{
    Document doc{R"({
        "check":
            {"field_test": "+exists/test"}
    })"};

    ASSERT_THROW(opBuilderHelperIntEqual(doc.get("/check")), std::invalid_argument);
}

TEST(opBuilderHelperNotExists, Exec_not_exists_ok)
{
    Document doc{R"({
        "check":
            {"field2check": "+not_exists"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // Greater
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field2check2":11,
                    "ref_key":10
                }
            )"));
            // Equal
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field":10,
                    "ref_key":10
                }
            )"));
            // Less
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "fieldcheck":10,
                    "ref_key":11
                }
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperNotExists(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 3);
    ASSERT_FALSE(expected[0]->exists("/field2check"));
    ASSERT_FALSE(expected[1]->exists("/field2check"));
    ASSERT_FALSE(expected[2]->exists("/field2check"));
}

TEST(opBuilderHelperNotExists, Exec_multilevel_ok)
{
    Document doc{R"({
        "check":
            {"parentObjt_1.field2check": "+not_exits"}
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
                        "field2check2": 11,
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
                        "field": 10,
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

            // true
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

    Lifter lift = opBuilderHelperNotExists(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 3);
    ASSERT_FALSE(expected[0]->exists("/parentObjt_1/field2check"));
    ASSERT_FALSE(expected[1]->exists("/parentObjt_1/field2check"));
    ASSERT_FALSE(expected[2]->exists("/parentObjt_1/field2check"));
}
