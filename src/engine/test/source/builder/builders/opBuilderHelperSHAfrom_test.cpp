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

// SHA1 hash results
constexpr char wordWorldWorstHash[] {"6184625af204bbfc7e751d49cdc1d7c7ee15091a"};
constexpr char xxxHash[] {"a9674b19f8c56f785c91a555d0a144522bb318e6"};
constexpr char wordHash[] {"3cbcd90adc4b192a87a625850b7f231caddf0eb3"};
constexpr char abcdeHash[] {"7be07aaf460d593a323d0db33da05b64bfdcb3a5"};

TEST(opBuilderSHAfrom, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"sha1_from"},
                                 std::vector<std::string> {"begin"});

    ASSERT_NO_THROW(bld::opBuilderSHAfrom(tuple));
}

TEST(opBuilderSHAfrom, Correct_execution_with_single_string)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"sha1_from"},
                                 std::vector<std::string> {"XXX"});

    auto event1 =
        std::make_shared<json::Json>(R"({"arrayField": ["A","B","C","D","E"]})");

    auto op = bld::opBuilderSHAfrom(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);
    ASSERT_EQ(xxxHash, result.payload()->getString("/field").value());
}

TEST(opBuilderSHAfrom, Correct_execution_with_several_strings)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"sha1_from"},
                                 std::vector<std::string> {"word", "world", "worst"});

    auto event1 =
        std::make_shared<json::Json>(R"({"arrayField": ["A","B","C","D","E"]})");

    auto op = bld::opBuilderSHAfrom(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);
    ASSERT_EQ(wordWorldWorstHash, result.payload()->getString("/field").value());
}

TEST(opBuilderSHAfrom, Correct_execution_with_reference)
{
    auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"sha1_from"},
                        std::vector<std::string> {"$fieldReference", "world", "worst"});

    auto event1 = std::make_shared<json::Json>(R"({"fieldReference": "word"})");

    auto op = bld::opBuilderSHAfrom(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);
    ASSERT_EQ(wordWorldWorstHash, result.payload()->getString("/field").value());
}

TEST(opBuilderSHAfrom, Correct_execution_with_several_references)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"sha1_from"},
                                 std::vector<std::string> {"$fieldReference",
                                                           "$fieldReference2",
                                                           "$object.fieldReference3"});

    auto event1 = std::make_shared<json::Json>(
        R"({"fieldReference":"word","fieldReference2":"world","object":{"fieldReference3":"worst"}})");

    auto op = bld::opBuilderSHAfrom(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);
    ASSERT_EQ(wordWorldWorstHash, result.payload()->getString("/field").value());
}

TEST(opBuilderSHAfrom, No_parameters_error)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"sha1_from"}, std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(R"({"arrayField": "A"})");

    ASSERT_THROW(bld::opBuilderSHAfrom(tuple), std::runtime_error);
}

TEST(opBuilderSHAfrom, Empty_parameter)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"sha1_from"},
                                 std::vector<std::string> {"$fieldReference", ""});

    auto event1 = std::make_shared<json::Json>(R"({"fieldReference": "word"})");

    auto op = bld::opBuilderSHAfrom(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);
}

TEST(opBuilderSHAfrom, Empty_reference_parameter)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"sha1_from"},
                                 std::vector<std::string> {"$fieldReference"});

    auto event1 = std::make_shared<json::Json>(R"({"fieldReference": ""})");

    auto op = bld::opBuilderSHAfrom(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);
}

TEST(opBuilderSHAfrom, Failed_execution_with_array_reference)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"sha1_from"},
                                 std::vector<std::string> {"$arrayField"});

    auto event1 =
        std::make_shared<json::Json>(R"({"arrayField": ["A","B","C","D","E"]})");

    auto op = bld::opBuilderSHAfrom(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result);
}

TEST(opBuilderSHAfrom, Correct_execution_with_nested_result)
{
    auto tuple = std::make_tuple(std::string {"/object/field"},
                                 std::string {"sha1_from"},
                                 std::vector<std::string> {"A", "B", "C", "D", "E"});

    auto event1 =
        std::make_shared<json::Json>(R"({"object":[{"field":"worst"},{"field2":1}]})");

    auto op = bld::opBuilderSHAfrom(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);
    ASSERT_EQ(abcdeHash, result.payload()->getString("/object/field").value());
}
