/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "testUtils.hpp"

#include "opBuilderHelperFilter.hpp"
#include "opBuilderMap.hpp"
#include "opBuilderMapReference.hpp"
#include "opBuilderMapValue.hpp"

#include <gtest/gtest.h>

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg) {
};

TEST(opBuilderMap, BuildsAllNonRegistered)
{
    Document doc {R"({
        "map":
        {
            "string": "value",
            "int": 1,
            "bool": true,
            "reference": "$field"
        }
    })"};

    auto docAllocator = doc.getAllocator();
    const auto &obj = doc.begin()->value.GetObject();
    for (auto it = obj.MemberBegin(); it != obj.MemberEnd(); ++it)
    {

        rapidjson::Value pairKeyValue(rapidjson::kObjectType);
        DocumentValue val(it->value, docAllocator);
        DocumentValue key(it->name, docAllocator);
        pairKeyValue.AddMember(key.Move(), val.Move(), docAllocator);

        ASSERT_THROW(opBuilderMap(pairKeyValue, tr), std::invalid_argument);
    }
}

TEST(opBuilderMap, BuildsValue)
{
    BuilderVariant c = bld::opBuilderMapValue;
    Registry::registerBuilder("map.value", c);
    Document doc {R"({
        "map":
        {
            "string": "value",
            "int": 1,
            "bool": true
        }
    })"};

    auto docAllocator = doc.getAllocator();
    const auto &obj = doc.begin()->value.GetObject();
    for (auto it = obj.MemberBegin(); it != obj.MemberEnd(); ++it)
    {

        rapidjson::Value pairKeyValue(rapidjson::kObjectType);
        DocumentValue val(it->value, docAllocator);
        DocumentValue key(it->name, docAllocator);
        pairKeyValue.AddMember(key.Move(), val.Move(), docAllocator);

        ASSERT_NO_THROW(opBuilderMap(pairKeyValue, tr));
    }
}

TEST(opBuilderMap, BuildsReference)
{
    BuilderVariant c = bld::opBuilderMapReference;
    Registry::registerBuilder("map.reference", c);
    Document doc {R"({
        "map":
        {
            "ref": "$ref"
        }
    })"};

    auto docAllocator = doc.getAllocator();
    const auto &obj = doc.begin()->value.GetObject();
    for (auto it = obj.MemberBegin(); it != obj.MemberEnd(); ++it)
    {

        rapidjson::Value pairKeyValue(rapidjson::kObjectType);
        DocumentValue val(it->value, docAllocator);
        DocumentValue key(it->name, docAllocator);
        pairKeyValue.AddMember(key.Move(), val.Move(), docAllocator);

        ASSERT_NO_THROW(opBuilderMap(pairKeyValue, tr));
    }
}
