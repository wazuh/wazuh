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

TEST(opBuilderHelperIntCalc, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"sum", "10"});

    ASSERT_NO_THROW(bld::opBuilderHelperIntCalc(tuple));
}

TEST(opBuilderHelperIntCalc, Builds_error_bad_operator)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"test", "10"});

    ASSERT_THROW(bld::opBuilderHelperIntCalc(tuple), std::runtime_error);
}

TEST(opBuilderHelperIntCalc, Builds_error_zero_division)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"div", "0"});

    ASSERT_THROW(bld::opBuilderHelperIntCalc(tuple), std::runtime_error);
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"sum", "10"});

    auto event1 = std::make_shared<json::Json>(R"({"fieldcheck": 10})");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_sum)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"sum", "10"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10})");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(20, result.payload()->getInt("/field2check").value());
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_sub)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"sub", "10"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10})");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(0, result.payload()->getInt("/field2check").value());
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_mul)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"mul", "10"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10})");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(100, result.payload()->getInt("/field2check").value());
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_div)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"div", "10"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10})");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(1, result.payload()->getInt("/field2check").value());
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_ref_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"sum", "$otherfield"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield2": 10})");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_ref_sum)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"sum", "$otherfield"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": 10})");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(20, result.payload()->getInt("/field2check").value());
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_ref_sub)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"sub", "$otherfield"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": 10})");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(0, result.payload()->getInt("/field2check").value());
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_ref_mul)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"mul", "$otherfield"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": 10})");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(100, result.payload()->getInt("/field2check").value());
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_ref_division_by_zero)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"div", "$otherfield"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield2": 0})");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_ref_div)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"div", "$otherfield"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield": 10})");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(1, result.payload()->getInt("/field2check").value());
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_multilevel_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"sum", "10"});

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

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_multilevel_sum)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"sum", "10"});

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

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(20, result.payload()->getInt("/parentObjt_1/field2check").value());
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_multilevel_sub)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"sub", "10"});

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

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(0, result.payload()->getInt("/parentObjt_1/field2check").value());
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_multilevel_mul)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"mul", "10"});

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

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(100, result.payload()->getInt("/parentObjt_1/field2check").value());
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_multilevel_div)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"div", "10"});

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

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(1, result.payload()->getInt("/parentObjt_1/field2check").value());
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_multilevel_ref_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"i_calc"},
                                 std::vector<std::string> {"sum", "$otherfield"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": 10,
                                                   "otherfield2": 10})");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_multilevel_ref_sum)
{
    auto tuple =
        std::make_tuple(std::string {"/parentObjt_1/field2check"},
                        std::string {"i_calc"},
                        std::vector<std::string> {"sum", "$parentObjt_2.field2check"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(20, result.payload()->getInt("/parentObjt_1/field2check").value());
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_multilevel_ref_sub)
{
    auto tuple =
        std::make_tuple(std::string {"/parentObjt_1/field2check"},
                        std::string {"i_calc"},
                        std::vector<std::string> {"sub", "$parentObjt_2.field2check"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(0, result.payload()->getInt("/parentObjt_1/field2check").value());
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_multilevel_ref_mul)
{
    auto tuple =
        std::make_tuple(std::string {"/parentObjt_1/field2check"},
                        std::string {"i_calc"},
                        std::vector<std::string> {"mul", "$parentObjt_2.field2check"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                    })");
    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(100, result.payload()->getInt("/parentObjt_1/field2check").value());
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_multilevel_ref_division_by_zero)
{
    auto tuple =
        std::make_tuple(std::string {"/parentObjt_1/field2check"},
                        std::string {"i_calc"},
                        std::vector<std::string> {"div", "$parentObjt_2.field2check"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 0,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperIntCalc, Exec_int_calc_multilevel_ref_div)
{
    auto tuple =
        std::make_tuple(std::string {"/parentObjt_1/field2check"},
                        std::string {"i_calc"},
                        std::vector<std::string> {"div", "$parentObjt_2.field2check"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": 10,
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperIntCalc(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result);

    ASSERT_EQ(1, result.payload()->getInt("/parentObjt_1/field2check").value());
}
