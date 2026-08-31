/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "requestTarget.hpp"

#include <gtest/gtest.h>

// #38492/#38491: the configured reverse-proxy segment is folded into the wire target -- a routing
// matter only, since the bearer token does not bind the target.

TEST(PrefixedTargetTest, EmptyEndpointLeavesTheTargetUnchanged)
{
    EXPECT_EQ("/stateless", prefixedTarget("", "/stateless"));
}

TEST(PrefixedTargetTest, JoinsTheNormalizedEndpointAndTheBareTarget)
{
    EXPECT_EQ("/wazuh-manager/stateless", prefixedTarget("wazuh-manager", "/stateless"));
}

TEST(PrefixedTargetTest, ComposesWithAMultiSegmentEndpoint)
{
    EXPECT_EQ("/gateway/wazuh/enroll", prefixedTarget("gateway/wazuh", "/enroll"));
}

TEST(PrefixedTargetTest, KeepsTheQueryString)
{
    EXPECT_EQ("/wazuh-manager/stateful?x=1", prefixedTarget("wazuh-manager", "/stateful?x=1"));
}
