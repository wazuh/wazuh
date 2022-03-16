/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "opBuilderHelperFilter.hpp"
#include "testUtils.hpp"
#include <gtest/gtest.h>

using namespace builder::internals::builders;

TEST(opBuilderHelperIPCIDR, Builds)
{
    Document doc{R"({
        "check":
            {"field2check": "+ip_cidr/192.168.0.0/24"}
    })"};
    Document doc2{R"({
        "check":
            {"field2check": "+ip_cidr/192.168.0.0/255.255.0.0"}
    })"};

    ASSERT_NO_THROW(opBuilderHelperIPCIDR(doc.get("/check")));
    ASSERT_NO_THROW(opBuilderHelperIPCIDR(doc2.get("/check")));
}

TEST(opBuilderHelperIPCIDR, Builds_incorrect_number_of_arguments)
{
    Document doc{R"({
        "check":
            {"field2check": "+ip_cidr/192.168.0.0/255.255.0.0/123"}
    })"};

    ASSERT_THROW(opBuilderHelperIPCIDR(doc.get("/check")), std::runtime_error);
}

TEST(opBuilderHelperIPCIDR, Builds_invalid_arguments)
{
    Document doc{R"({
        "check":
            {"field2check": "+ip_cidr/192.168.0.0/256.255.0.0"}
    })"};

    ASSERT_THROW(opBuilderHelperIPCIDR(doc.get("/check")), std::runtime_error);

    Document doc2{R"({
        "check":
            {"field2check": "+ip_cidr/192.168.0.-1/255.255.0.0.1"}
    })"};

    ASSERT_THROW(opBuilderHelperIPCIDR(doc2.get("/check")), std::runtime_error);

    Document doc3{R"({
        "check":
            {"field2check": "+ip_cidr/192.168.0.1/33"}
    })"};

    ASSERT_THROW(opBuilderHelperIPCIDR(doc3.get("/check")), std::runtime_error);
}

// Test ok
TEST(opBuilderHelperIPCIDR, chack_ip_range)
{
    Document doc{R"({
        "check":
            {"field2check": "+ip_cidr/192.168.0.0/16"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // Network address
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"192.168.0.0"}
            )"));
            // First address
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"192.168.0.1"}
            )"));
            // Last address
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"192.168.255.254"}
            )"));
            // Broadcast address
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"192.168.255.255"}
            )"));
            // Address out of cidr range
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"10.0.0.1"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"127.0.0.1"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperIPCIDR(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 4);
    ASSERT_STREQ(expected[0]->get("/field2check").GetString(), "192.168.0.0");
    ASSERT_STREQ(expected[1]->get("/field2check").GetString(), "192.168.0.1");
    ASSERT_STREQ(expected[2]->get("/field2check").GetString(), "192.168.255.254");
    ASSERT_STREQ(expected[3]->get("/field2check").GetString(), "192.168.255.255");
}
