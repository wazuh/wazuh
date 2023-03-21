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

#include "opBuilderHelperFilter.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperExists, Builds)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"exists"}, std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperExists(tuple));
}

TEST(opBuilderHelperExists, Exec_exists_false)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"exists"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(R"({"fieldcheck": "valid"})");

    auto op = bld::opBuilderHelperExists(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperExists, Exec_exists_true)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"exists"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": "valid"})");

    auto op = bld::opBuilderHelperExists(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperExists, Exec_multilevel_false)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"exists"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "fieldcheck": 11,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperExists(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperExists, Exec_multilevel_true)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"exists"},
                                 std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 11,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperExists(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result.success());
}
