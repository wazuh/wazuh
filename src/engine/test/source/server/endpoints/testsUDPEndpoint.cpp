/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "testsUDPEndpoint.hpp"

#define GTEST_COUT cerr << "[          ] [ INFO ]"


using namespace engineserver;
using namespace engineserver::endpoints;
using namespace std;
using namespace rxcpp;


TEST(UDPTest, Initializes)
{
    const string config = "localhost:5054";
    ASSERT_NO_THROW(UDPEndpoint udp (config));
}

TEST(UDPTest, RunStop)
{
    const string config = "localhost:5054";
    UDPEndpoint udp (config);
    ASSERT_NO_THROW(udp.run());
    // Give time to initialize before closing
    this_thread::sleep_for(chrono::milliseconds(5));
    ASSERT_NO_THROW(udp.close());
}
