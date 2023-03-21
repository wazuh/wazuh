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

TEST(opBuilderHelperJsonDeleteField, Builds)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"delete"}, std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperDeleteField(tuple));
}

TEST(opBuilderHelperJsonDeleteField, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"delete"},
                                 std::vector<std::string> {"test", "test"});

    ASSERT_THROW(bld::opBuilderHelperDeleteField(tuple), std::runtime_error);
}

TEST(opBuilderHelperJsonDeleteField, Exec_json_delete_field_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"delete"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(R"({"fieldcheck": 10})");

    auto op = bld::opBuilderHelperDeleteField(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperJsonDeleteField, Exec_json_delete_field_success)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"delete"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10})");

    auto op = bld::opBuilderHelperDeleteField(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_FALSE(result.payload()->exists("/field2check"));
}

TEST(opBuilderHelperJsonDeleteField, Exec_json_delete_field_multilevel_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"delete"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "fieldcheck": 10,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperDeleteField(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperJsonDeleteField, Exec_json_delete_field_multilevel_success)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"delete"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperDeleteField(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_FALSE(result.payload()->exists("/parentObjt_1/field2check"));
}

// TODO This test should not be valid since the key must be unique.
TEST(opBuilderHelperJsonDeleteField, Exec_json_delete_field_multilevel_repeat_success)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"delete"},
                                 std::vector<std::string> {});

    auto event1 =
        std::make_shared<json::Json>(R"({"field2check": 10,"field2check": 20})");

    auto op = bld::opBuilderHelperDeleteField(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_TRUE(result.payload()->exists(
        "/field2check")); // Remove the first occurrence of the path
}
