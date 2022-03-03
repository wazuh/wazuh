/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include "testUtils.hpp"
#include "OpBuilderHelperFilter.hpp"


using namespace builder::internals::builders;

uint32_t IPToUInt(const std::string ip)
{
    int a, b, c, d;
    uint32_t addr = 0;

    if (sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
        return 0;

    addr = a << 24;
    addr |= b << 16;
    addr |= c << 8;
    addr |= d;
    return addr;
}

TEST(opBuilderHelperIpCIDR, Local_test)
{

    uint32_t ip = IPToUInt("192.168.1.1");
    uint32_t network = IPToUInt("192.168.1.0");
    uint32_t mask = IPToUInt("255.255.255.0");

    uint32_t net_lower = (network & mask);
    uint32_t net_upper = (net_lower | (~mask));

    ASSERT_TRUE((ip >= net_lower && ip <= net_upper));
}

TEST(opBuilderHelperIpCIDR, Function_helper_test)
{
    Document doc{R"({
        "check":
            {"field": "+ip_cidr/192.168.1.0/255.255.255.0"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field":"192.168.1.1"}
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperIPCIDR(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
}
