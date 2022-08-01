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

#include "opBuilderHelperNetInfoAddress.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperNetInfoTest, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"netInfoAddress"},
                                 std::vector<std::string> {"0"});

    ASSERT_NO_THROW(bld::opBuilderHelperNetInfoAddres(tuple));
}

TEST(opBuilderHelperNetInfoTest, CorrectExecutionWithEvent)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"netInfoAddress"},
                                 std::vector<std::string> {"0"});

    auto event1 =
        std::make_shared<json::Json>(R"({"agent":{"id":"021"},"event":{"original":{"ID":"123456","iface":{"IPv4":{"address":["192.168.10.15","192.168.11.16"],"netmask":["255.255.255.0","255.255.255.0"],"broadcast":["192.168.10.255","192.168.11.255"]}}}}})");

    auto op =
        bld::opBuilderHelperNetInfoAddres(tuple)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result);
}

