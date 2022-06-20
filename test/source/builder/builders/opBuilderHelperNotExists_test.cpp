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

#include "opBuilderHelperFilter.hpp"


using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg) {
};

TEST(opBuilderHelperNotExists, Builds)
{
    Document doc {R"({
        "check":
            {"field": "+not_exists"}
    })"};

    ASSERT_NO_THROW(bld::opBuilderHelperNotExists(doc.get("/check"), tr));
}

TEST(opBuilderHelperNotExists, Builds_error_bad_parameter)
{
    Document doc {R"({
        "check":
            {"field_test": "+exists/test"}
    })"};

    ASSERT_THROW(bld::opBuilderHelperIntEqual(doc.get("/check"), tr), std::invalid_argument);
}

TEST(opBuilderHelperNotExists, Exec_not_exists_ok)
{
    Document doc {R"({
        "check":
            {"field2check": "+not_exists"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // Greater
            s.on_next(createSharedEvent(R"(
                {
                    "field2check2":11,
                    "ref_key":10
                }
            )"));
            // Equal
            s.on_next(createSharedEvent(R"(
                {
                    "field":10,
                    "ref_key":10
                }
            )"));
            // Less
            s.on_next(createSharedEvent(R"(
                {
                    "fieldcheck":10,
                    "ref_key":11
                }
            )"));
            s.on_completed();
        });

    Lifter lift = [=](Observable input)
    {
        return input.filter(bld::opBuilderHelperNotExists(doc.get("/check"), tr));
    };
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 3);
    ASSERT_FALSE(expected[0]->getEvent()->exists("/field2check"));
    ASSERT_FALSE(expected[1]->getEvent()->exists("/field2check"));
    ASSERT_FALSE(expected[2]->getEvent()->exists("/field2check"));
}

TEST(opBuilderHelperNotExists, Exec_multilevel_ok)
{
    Document doc {R"({
        "check":
            {"parentObjt_1.field2check": "+not_exits"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
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

            s.on_next(createSharedEvent(R"(
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

            s.on_next(createSharedEvent(R"(
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
            s.on_next(createSharedEvent(R"(
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

    Lifter lift = [=](Observable input)
    {
        return input.filter(bld::opBuilderHelperNotExists(doc.get("/check"), tr));
    };
    Observable output = lift(input);
    vector<Event> expected;

    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 3);
    ASSERT_FALSE(expected[0]->getEvent()->exists("/parentObjt_1/field2check"));
    ASSERT_FALSE(expected[1]->getEvent()->exists("/parentObjt_1/field2check"));
    ASSERT_FALSE(expected[2]->getEvent()->exists("/parentObjt_1/field2check"));
}
