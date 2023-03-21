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

TEST(opBuilderHelperStringConcat, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"Concat", "test"});

    ASSERT_NO_THROW(bld::opBuilderHelperStringConcat(tuple));
}

TEST(opBuilderHelperStringConcat, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"test"});

    ASSERT_THROW(bld::opBuilderHelperStringConcat(tuple), std::runtime_error);
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"concat", "test"});

    auto event1 = std::make_shared<json::Json>(R"({"fieldcheck": 10})");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_success)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"concat", "test"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10})");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("concattest", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_large_success)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"This", "is", "a", "test"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10})");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("Thisisatest", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_ref_field_not_exist)
{
    auto tuple =
        std::make_tuple(std::string {"/field2check"},
                        std::string {"concat"},
                        std::vector<std::string> {"$otherfield", "$otherfield2"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield3": "test",
                                                   "otherfield4": "test"})");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_ref_not_string_or_int)
{
    auto tuple =
        std::make_tuple(std::string {"/field2check"},
                        std::string {"concat"},
                        std::vector<std::string> {"$otherfield", "$otherfield2"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": 2,
                                                   "otherfield2": true})");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_ref_success)
{
    auto tuple =
        std::make_tuple(std::string {"/field2check"},
                        std::string {"concat"},
                        std::vector<std::string> {"$otherfield", "$otherfield2"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": "concat",
                                                   "otherfield2": "test"})");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("concattest", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_ref_success_int)
{
    auto tuple =
        std::make_tuple(std::string {"/field2check"},
                        std::string {"concat"},
                        std::vector<std::string> {"$otherfield", "$otherfield2"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": 10,
                                                   "otherfield2": "test"})");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("10test", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_ref_large_success)
{
    auto tuple = std::make_tuple(
        std::string {"/field2check"},
        std::string {"concat"},
        std::vector<std::string> {
            "$otherfield", "$otherfield2", "$otherfield3", "$otherfield4"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": "This",
                                                   "otherfield2": "is",
                                                   "otherfield3": "a",
                                                   "otherfield4": "test"})");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("Thisisatest", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_ref_large_success_int)
{
    auto tuple = std::make_tuple(
        std::string {"/field2check"},
        std::string {"concat"},
        std::vector<std::string> {
            "$otherfield", "$otherfield2", "$otherfield3", "$otherfield4"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": "This",
                                                   "otherfield2": 10,
                                                   "otherfield3": "a",
                                                   "otherfield4": 20})");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("This10a20", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_mix_ref_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"$otherfield", "test"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10})");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_mix_not_string_or_int)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"test", "$otherfield"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": true,
                                                   "otherfield2": 4})");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_mix_success)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"concat", "$otherfield2"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": 2,
                                                   "otherfield2": "test"})");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("concattest", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_mix_success_int)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"10", "$otherfield2"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": 2,
                                                   "otherfield2": 20})");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("1020", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_mix_large_success)
{
    auto tuple = std::make_tuple(
        std::string {"/field2check"},
        std::string {"concat"},
        std::vector<std::string> {"This", "$otherfield2", "a", "$otherfield4"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": 10,
                                                   "otherfield2": "is",
                                                   "otherfield3": 20,
                                                   "otherfield4": "test"})");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("Thisisatest", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_mix_large_success_int)
{
    auto tuple = std::make_tuple(
        std::string {"/field2check"},
        std::string {"concat"},
        std::vector<std::string> {"This", "$otherfield2", "10", "$otherfield4"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": "This",
                                                   "otherfield2": "is",
                                                   "otherfield3": "a",
                                                   "otherfield4": 20})");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("Thisis1020", result.payload()->getString("/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_multilevel_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"concat", "test"});

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

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("concattest",
              result.payload()->getString("/parentObjt_1/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_multilevel_field_success)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"concat", "test"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": "concat",
                        "ref_key": 11
                    },
                    "parentObjt_4": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_3": {
                        "field2check": "test",
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("concattest",
              result.payload()->getString("/parentObjt/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_multilevel_field_success_int)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"10", "20"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": "concat",
                        "ref_key": 11
                    },
                    "parentObjt_4": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_3": {
                        "field2check": "test",
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("1020",
              result.payload()->getString("/parentObjt/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_multilevel_ref_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"$parentObjt_1/field2check",
                                                           "$parentObjt_2/fieldcheck"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "field2check": 10,
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "fieldcheck": 10,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_multilevel_ref_success)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"$parentObjt_1.field2check",
                                                           "$parentObjt_3.field2check"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": "concat",
                        "ref_key": 11
                    },
                    "parentObjt_4": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_3": {
                        "field2check": "test",
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("concattest",
              result.payload()->getString("/parentObjt/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_multilevel_ref_success_int)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"$parentObjt_1.field2check",
                                                           "$parentObjt_3.field2check"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    },
                    "parentObjt_4": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_3": {
                        "field2check": 20,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("1020",
              result.payload()->getString("/parentObjt/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_multilevel_ref_large_success)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"$parentObjt_1.field2check",
                                                           "$parentObjt_2.field2check",
                                                           "$parentObjt_4.field2check",
                                                           "$parentObjt_3.field2check"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": "is",
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": "This",
                        "ref_key": 11
                    },
                    "parentObjt_4": {
                        "field2check": "a",
                        "ref_key": 10
                    },
                    "parentObjt_3": {
                        "field2check": "test",
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("Thisisatest",
              result.payload()->getString("/parentObjt/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_multilevel_ref_large_success_int)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"$parentObjt_1.field2check",
                                                           "$parentObjt_2.field2check",
                                                           "$parentObjt_4.field2check",
                                                           "$parentObjt_3.field2check"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 20,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    },
                    "parentObjt_4": {
                        "field2check": 30,
                        "ref_key": 10
                    },
                    "parentObjt_3": {
                        "field2check": 40,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("10203040",
              result.payload()->getString("/parentObjt/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_multilevel_mix_field_not_exist)
{
    auto tuple =
        std::make_tuple(std::string {"/parentObjt_1/field2check"},
                        std::string {"concat"},
                        std::vector<std::string> {"concat", "$parentObjt_2.field2check"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": "test",
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "fieldcheck": 10,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("concattest",
              result.payload()->getString("/parentObjt_1/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_multilevel_ref_field_success_int)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"$parentObjt_1.field2check",
                                                           "$parentObjt_3.field2check"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    },
                    "parentObjt_4": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_3": {
                        "field2check": 20,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("1020",
              result.payload()->getString("/parentObjt/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_multilevel_mix_ref_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"concat",
                                                           "$parentObjt_2.fieldcheck"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "field2check": 10,
                    "parentObjt_2": {
                        "field2check": "test",
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "fieldcheck": "test",
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

// TODO $parentObjt_3.field2check a $/parentObjt_3/fieldcheck
TEST(opBuilderHelperStringConcat, Exec_string_concat_multilevel_mix_ref_success)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"concat",
                                                           "$parentObjt_3.field2check"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 15,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 12,
                        "ref_key": 11
                    },
                    "parentObjt_4": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_3": {
                        "field2check": "test",
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("concattest",
              result.payload()->getString("/parentObjt/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_multilevel_mix_ref_success_int)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"10",
                                                           "$parentObjt_3.field2check"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": "is",
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": "This",
                        "ref_key": 11
                    },
                    "parentObjt_4": {
                        "field2check": "a",
                        "ref_key": 10
                    },
                    "parentObjt_3": {
                        "field2check": 20,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("1020",
              result.payload()->getString("/parentObjt/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_multilevel_mix_ref_large_success)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"This",
                                                           "$parentObjt_2.field2check",
                                                           "a",
                                                           "$parentObjt_4.field2check"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": "is",
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    },
                    "parentObjt_4": {
                        "field2check": "test",
                        "ref_key": 10
                    },
                    "parentObjt_3": {
                        "field2check": 15,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("Thisisatest",
              result.payload()->getString("/parentObjt/field2check").value());
}

TEST(opBuilderHelperStringConcat, Exec_string_concat_multilevel_mix_ref_large_success_int)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt/field2check"},
                                 std::string {"concat"},
                                 std::vector<std::string> {"This",
                                                           "$parentObjt_2.field2check",
                                                           "10",
                                                           "$parentObjt_4.field2check"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": "is",
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": "This",
                        "ref_key": 11
                    },
                    "parentObjt_4": {
                        "field2check": 20,
                        "ref_key": 10
                    },
                    "parentObjt_3": {
                        "field2check": "a",
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperStringConcat(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ("Thisis1020",
              result.payload()->getString("/parentObjt/field2check").value());
}
