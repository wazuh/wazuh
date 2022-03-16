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

#include "opBuilderMap.hpp"
#include "opBuilderMapReference.hpp"
#include "opBuilderMapValue.hpp"
#include "opBuilderHelperFilter.hpp"

using namespace builder::internals::builders;

TEST(opBuilderMap, BuildsAllNonRegistered)
{
    Document doc{R"({
        "normalize": [
            {"string": "value"},
            {"int": 1},
            {"bool": true},
            {"reference": "$field"}
        ]
    })"};
    const auto & arr = doc.begin()->value.GetArray();
    for (auto it = arr.Begin(); it != arr.end(); ++it)
    {
        ASSERT_THROW(opBuilderMap(*it), invalid_argument);
    }
}

TEST(opBuilderMap, BuildsValue)
{
    BuilderVariant c = opBuilderMapValue;
    Registry::registerBuilder("map.value", c);
    Document doc{R"({
        "normalize": [
            {"string": "value"},
            {"int": 1},
            {"bool": true}
        ]
    })"};
    const auto & arr = doc.begin()->value.GetArray();
    for (auto it = arr.Begin(); it != arr.end(); ++it)
    {
        ASSERT_NO_THROW(opBuilderMap(*it));
    }
}

TEST(opBuilderMap, BuildsReference)
{
    BuilderVariant c = opBuilderMapReference;
    Registry::registerBuilder("map.reference", c);
    Document doc{R"({"normalize": {"ref": "$ref"}})"};
    ASSERT_NO_THROW(opBuilderMap(doc.get("/normalize")));
}
