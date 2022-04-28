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

#include <baseTypes.hpp>

#include "testUtils.hpp"
#include "opBuilderHelperFilter.hpp"

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

auto createEvent = [](const char * json){
    return std::make_shared<EventHandler>(std::make_shared<Document>(json));
};

TEST(opBuilderHelperExists, Builds)
{
    Document doc{R"({
        "check":
            {"field": "+exists"}
    })"};

    ASSERT_NO_THROW(bld::opBuilderHelperExists(doc.get("/check"), tr));
}

TEST(opBuilderHelperExists, Builds_error_bad_parameter)
{
    Document doc{R"({
        "check":
            {"field_test": "+exists/test"}
    })"};

    ASSERT_THROW(bld::opBuilderHelperIntEqual(doc.get("/check"), tr), std::invalid_argument);
}

TEST(opBuilderHelperExists, Exec_exists_ok)
{
    Document doc{R"({
        "check":
            {"field2check": "+exists"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createEvent(R"(
                {
                    "field2check":11,
                    "ref_key":10
                }
            )"));
            s.on_next(createEvent(R"(
                {
                    "field2check":10,
                    "ref_key":10
                }
            )"));
            s.on_next(createEvent(R"(
                {
                    "field2check":10,
                    "ref_key":11
                }
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperExists(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 3);
    ASSERT_TRUE(expected[0]->getEvent()->exists("/field2check"));
    ASSERT_TRUE(expected[1]->getEvent()->exists("/field2check"));
    ASSERT_TRUE(expected[2]->getEvent()->exists("/field2check"));
}

TEST(opBuilderHelperExists, Exec_multilevel_ok)
{
    Document doc{R"({
        "check":
            {"parentObjt_1.field2check": "+exits"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createEvent(R"(
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

            s.on_next(createEvent(R"(
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

            // false
            s.on_next(createEvent(R"(
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

            s.on_next(createEvent(R"(
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

    Lifter lift = bld::opBuilderHelperExists(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 3);
    ASSERT_TRUE(expected[0]->getEvent()->exists("/parentObjt_1/field2check"));
    ASSERT_TRUE(expected[1]->getEvent()->exists("/parentObjt_1/field2check"));
    ASSERT_TRUE(expected[2]->getEvent()->exists("/parentObjt_1/field2check"));
}
