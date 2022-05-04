/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include "testUtils.hpp"

#include "opBuilderCondition.hpp"
#include "opBuilderHelperFilter.hpp"

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

TEST(opBuilderCondition, BuildsAllNonRegistered)
{
    Document doc{R"({
        "check": [
            {"helper1": "+exists"},
            {"helper2": "+not_exists"}
        ]
    })"};
    const auto & arr = doc.begin()->value.GetArray();
    for (auto it = arr.Begin(); it != arr.end(); ++it)
    {
        ASSERT_THROW(bld::opBuilderCondition(*it, tr), invalid_argument);
    }
}

TEST(opBuilderCondition, BuildsValue)
{
    BuilderVariant c = bld::middleBuilderCondition;
    Registry::registerBuilder("middle.condition", c);
    Document doc{R"({
        "check": [
            {"string": "value"},
            {"int": 1},
            {"bool": true}
        ]
    })"};
    const auto & arr = doc.begin()->value.GetArray();
    for (auto it = arr.Begin(); it != arr.end(); ++it)
    {
        ASSERT_NO_THROW(bld::opBuilderCondition(*it, tr));
    }
}

TEST(opBuilderCondition, BuildsReference)
{
    Document doc{R"({"check": {"ref": "$ref"}})"};
    ASSERT_NO_THROW(bld::opBuilderCondition(doc.get("/check"), tr));
}

TEST(opBuilderCondition, BuildsHelperExists)
{
    BuilderVariant c = bld::opBuilderHelperExists;
    Registry::registerBuilder("middle.helper.exists", c);
    Document doc{R"({"check": {"ref": "+exists"}})"};
    ASSERT_NO_THROW(bld::opBuilderCondition(doc.get("/check"), tr));
}

TEST(opBuilderCondition, BuildsHelperNotExists)
{
    BuilderVariant c = bld::opBuilderHelperNotExists;
    Registry::registerBuilder("middle.helper.not_exists", c);
    Document doc{R"({"check": {"ref": "+not_exists"}})"};
    ASSERT_NO_THROW(bld::opBuilderCondition(doc.get("/check"), tr));
}
