/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "opBuilderSHAfrom.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderSHAfrom, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"sha1_from"},
                                 std::vector<std::string> {"begin"});

    ASSERT_NO_THROW(bld::opBuilderSHAfrom(tuple));
}

TEST(opBuilderSHAfrom, CorrectExecutionWithSingleString)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"sha1_from"},
                                 std::vector<std::string> {"XXX"});

    auto event1 =
        std::make_shared<json::Json>(R"({"arrayField": ["A","B","C","D","E"]})");

    auto op =
        bld::opBuilderSHAfrom(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);
    ASSERT_EQ("a9674b19f8c56f785c91a555d0a144522bb318e6", result.payload()->getString("/field").value());
}

TEST(opBuilderSHAfrom, CorrectExecutionWithSeveralStrings)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"sha1_from"},
                                 std::vector<std::string> {"word", "world", "worst"});

    auto event1 =
        std::make_shared<json::Json>(R"({"arrayField": ["A","B","C","D","E"]})");

    auto op =
        bld::opBuilderSHAfrom(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);
    ASSERT_EQ("6184625af204bbfc7e751d49cdc1d7c7ee15091a", result.payload()->getString("/field").value());
}

TEST(opBuilderSHAfrom, CorrectExecutionWithReference)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"sha1_from"},
                                 std::vector<std::string> {"$fieldReference","world","worst"});

    auto event1 =
        std::make_shared<json::Json>(R"({"fieldReference": "word"})");

    auto op =
        bld::opBuilderSHAfrom(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);
    ASSERT_EQ("6184625af204bbfc7e751d49cdc1d7c7ee15091a", result.payload()->getString("/field").value());
}
