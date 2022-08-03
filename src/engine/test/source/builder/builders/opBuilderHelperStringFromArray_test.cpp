/* Copyright (C) 2015-2021, Wazuh Inc.
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

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperStringFromArray, Builds)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"s_from_array"}, std::vector<std::string> {"begin", "t"});

    ASSERT_NO_THROW(bld::opBuilderHelperStringFromArray(tuple));
}

TEST(opBuilderHelperStringFromArray, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"s_from_array"},
                                 std::vector<std::string> {"begin"});

    ASSERT_THROW(bld::opBuilderHelperStringFromArray(tuple), std::out_of_range);
}

TEST(opBuilderHelperStringFromArray, Executes_with_string_from_array_success)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"s_from_array"},
                                 std::vector<std::string> {"-", "$arrayField"});

    auto event1 = std::make_shared<json::Json>(R"({"arrayField": ["A","B","C","D","E"]})");

    auto op = bld::opBuilderHelperStringFromArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("A-B-C-D-E", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringFromArray, Executes_string_from_array_with_reference_success)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"s_from_array"},
                                 std::vector<std::string> {"$separator", "$arrayField"});

    auto event1 = std::make_shared<json::Json>(R"({"separator": ",", "arrayField": ["A","B"]})");

    auto op = bld::opBuilderHelperStringFromArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("A,B", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringFromArray, Failed_parameter_is_not_array)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"s_from_array"},
                                 std::vector<std::string> {"$separator", "$arrayField"});

    auto event1 = std::make_shared<json::Json>(R"({"separator": ",", "arrayField": "A"})");

    auto op = bld::opBuilderHelperStringFromArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperStringFromArray, Failed_array_without_strings)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"s_from_array"},
                                 std::vector<std::string> {"$separator", "$arrayField"});

    auto event1 = std::make_shared<json::Json>(R"({"separator": ",", "arrayField": [1,150]})");

    auto op = bld::opBuilderHelperStringFromArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperStringFromArray, Failed_empty_array)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"s_from_array"},
                                 std::vector<std::string> {"$separator", "$arrayField"});

    auto event1 = std::make_shared<json::Json>(R"({"separator": ",", "arrayField": []})");

    auto op = bld::opBuilderHelperStringFromArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperStringFromArray, Success_with_multi_level_assignment)
{
    auto tuple = std::make_tuple(std::string {"/arrayResult/0/field2check"},
                                 std::string {"s_from_array"},
                                 std::vector<std::string> {"$separator", "$arrayField"});

    auto event1 = std::make_shared<json::Json>(R"({"separator": ".", "arrayField": ["A","B"]})");

    auto op = bld::opBuilderHelperStringFromArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("A.B", result.payload()->getString("/arrayResult/0/field2check").value());
}

TEST(opBuilderHelperStringFromArray, Failed_with_seccond_parameter_not_reference)
{
    auto tuple = std::make_tuple(std::string {"/arrayResult/0/field2check"},
                                 std::string {"s_from_array"},
                                 std::vector<std::string> {"$separator", "[\"A\",\"B\"]"});

    auto event1 = std::make_shared<json::Json>(R"({"separator": ".", "arrayField": ["A","B"]})");

    auto op = bld::opBuilderHelperStringFromArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}
