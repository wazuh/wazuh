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
#include "opBuilderConditionReference.hpp"
#include "opBuilderConditionValue.hpp"
#include "opBuilderHelperFilter.hpp"

using namespace builder::internals::builders;

TEST(opBuilderCondition, BuildsAllNonRegistered)
{
    Document doc{R"({
        "check": [
            {"string": "value"},
            {"int": 1},
            {"bool": true},
            {"reference": "$field"},
            {"helper1": "+exists"},
            {"helper2": "+not_exists"}
        ]
    })"};
    const auto & arr = doc.begin()->value.GetArray();
    for (auto it = arr.Begin(); it != arr.end(); ++it)
    {
        ASSERT_THROW(opBuilderCondition(*it), invalid_argument);
    }
}

TEST(opBuilderCondition, BuildsValue)
{
    BuilderVariant c = opBuilderConditionValue;
    Registry::registerBuilder("condition.value", c);
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
        ASSERT_NO_THROW(opBuilderCondition(*it));
    }
}

TEST(opBuilderCondition, BuildsReference)
{
    BuilderVariant c = opBuilderConditionReference;
    Registry::registerBuilder("condition.reference", c);
    Document doc{R"({"check": {"ref": "$ref"}})"};
    ASSERT_NO_THROW(opBuilderCondition(doc.get("/check")));
}

TEST(opBuilderCondition, BuildsHelperExists)
{
    BuilderVariant c = opBuilderHelperExists;
    Registry::registerBuilder("helper.exists", c);
    Document doc{R"({"check": {"ref": "+exists"}})"};
    ASSERT_NO_THROW(opBuilderCondition(doc.get("/check")));
}

TEST(opBuilderCondition, BuildsHelperNotExists)
{
    BuilderVariant c = opBuilderHelperNotExists;
    Registry::registerBuilder("helper.not_exists", c);
    Document doc{R"({"check": {"ref": "+not_exists"}})"};
    ASSERT_NO_THROW(opBuilderCondition(doc.get("/check")));
}
