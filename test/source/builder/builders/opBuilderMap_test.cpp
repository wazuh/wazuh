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

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

auto createEvent = [](const char * json){
    return std::make_shared<EventHandler>(std::make_shared<Document>(json));
};

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
        ASSERT_THROW(bld::opBuilderMap(*it, tr), invalid_argument);
    }
}

TEST(opBuilderMap, BuildsValue)
{
    BuilderVariant c = bld::opBuilderMapValue;
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
        ASSERT_NO_THROW(bld::opBuilderMap(*it, tr));
    }
}

TEST(opBuilderMap, BuildsReference)
{
    BuilderVariant c = bld::opBuilderMapReference;
    Registry::registerBuilder("map.reference", c);
    Document doc{R"({"normalize": {"ref": "$ref"}})"};
    ASSERT_NO_THROW(bld::opBuilderMap(doc.get("/normalize"), tr));
}
