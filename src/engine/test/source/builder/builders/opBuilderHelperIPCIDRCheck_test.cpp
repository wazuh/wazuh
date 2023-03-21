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

#include "opBuilderHelperFilter.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperIPCIDR, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"ip_cidr_match"},
                                 std::vector<std::string> {"192.168.255.255", "24"});

    ASSERT_NO_THROW(bld::opBuilderHelperIPCIDR(tuple));
}

TEST(opBuilderHelperIPCIDR, Exec_IPCIDR_false)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"ip_cidr_match"},
                                 std::vector<std::string> {"192.168.255.0", "24"});

    auto event1 =
        std::make_shared<json::Json>(R"({"field2check": "192.168.255.255/24"})");

    auto op = bld::opBuilderHelperIPCIDR(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperIPCIDR, Exec_IPCIDR__CIDR_true)
{
    auto tuple = std::make_tuple(std::string {"/field2check"},
                                 std::string {"ip_cidr_match"},
                                 std::vector<std::string> {"192.168.255.0", "24"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": "192.168.255.255"})");

    auto op = bld::opBuilderHelperIPCIDR(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperIPCIDR, Exec_IPCIDR_subred_true)
{
    auto tuple =
        std::make_tuple(std::string {"/field2check"},
                        std::string {"ip_cidr_match"},
                        std::vector<std::string> {"192.168.255.0", "255.255.255.0"});

    auto event1 = std::make_shared<json::Json>(R"({"field2check": "192.168.255.255"})");

    auto op = bld::opBuilderHelperIPCIDR(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperIPCIDR, Exec_IPCIDR_multilevel_false)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"ip_cidr_match"},
                                 std::vector<std::string> {"192.168.255.0", "24"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": "10.0.0.1",
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperIPCIDR(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperIPCIDR, Exec_IPCIDR_CIDR_multilevel_true)
{
    auto tuple = std::make_tuple(std::string {"/parentObjt_1/field2check"},
                                 std::string {"ip_cidr_match"},
                                 std::vector<std::string> {"192.168.255.0", "24"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": "192.168.255.255",
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperIPCIDR(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperIPCIDR, Exec_IPCIDR_subred_multilevel_true)
{
    auto tuple =
        std::make_tuple(std::string {"/parentObjt_1/field2check"},
                        std::string {"ip_cidr_match"},
                        std::vector<std::string> {"192.168.255.0", "255.255.255.0"});

    auto event1 = std::make_shared<json::Json>(R"({
                    "parentObjt_2": {
                        "field2check": 10,
                        "ref_key": 10
                    },
                    "parentObjt_1": {
                        "field2check": "192.168.255.255",
                        "ref_key": 11
                    }
                    })");

    auto op = bld::opBuilderHelperIPCIDR(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_TRUE(result.success());
}
