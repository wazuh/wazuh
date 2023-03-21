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

TEST(opBuilderHelperRegexExtract, Builds)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"regex_extract"}, std::vector<std::string> {"$_field", "(regex)"});

    ASSERT_NO_THROW(bld::opBuilderHelperRegexExtract(tuple));
}

TEST(opBuilderHelperRegexExtract, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"test"});

    ASSERT_THROW(bld::opBuilderHelperRegexExtract(tuple), std::runtime_error);
}

TEST(opBuilderHelperRegexExtract, Builds_incorrect_parameter_type)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"test", "(regex)"});

    ASSERT_THROW(bld::opBuilderHelperRegexExtract(tuple), std::runtime_error);
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$fieldcheck", "(test)"});

    auto event1 = std::make_shared<json::Json>(R"({"fieldcheck": "This is a test."})");

    auto op = bld::opBuilderHelperRegexExtract(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_ref_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$otherfield", "(test)"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield2": "This is a test."})");

    auto op = bld::opBuilderHelperRegexExtract(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_fail)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$otherfield", "(regex)"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": "This is a test."})");

    auto op = bld::opBuilderHelperRegexExtract(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_success)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$otherfield", "(test)"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": "This is a test."})");

    auto op = bld::opBuilderHelperRegexExtract(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_multilevel_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$parentObjt_1.fieldcheck", "(test)"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "fieldcheck": "This is a test.",
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperRegexExtract(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/parentObjt_1/field2check").value());
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_multilevel_ref_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_2/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$parentObjt_1.field2check", "(test)"});

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

    auto op = bld::opBuilderHelperRegexExtract(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_multilevel_fail)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$parentObjt_2.field2check", "(regex)"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": "This is a test.",
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperRegexExtract(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperRegexExtract, Exec_regex_extract_multilevel_success)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"regex_extract"},
                                 std::vector<std::string> {"$parentObjt_2.field2check", "(test)"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": "This is a test.",
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperRegexExtract(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("test", result.payload()->getString("/parentObjt_1/field2check").value());
}
