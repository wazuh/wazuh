/*
 * Wazuh task manager module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "upgrade/httpWpkRepository.hpp"

#include <gtest/gtest.h>

using namespace task_manager::upgrade;

TEST(UpgradeHttpWpkRepositoryTest, UserAgentDropsTheVersionPrefix)
{
    EXPECT_EQ(HttpWpkRepository::userAgentFor("v5.0.0"), "wazuh-manager/5.0.0");
}

TEST(UpgradeHttpWpkRepositoryTest, UserAgentKeepsAVersionWithoutPrefix)
{
    EXPECT_EQ(HttpWpkRepository::userAgentFor("5.0.1"), "wazuh-manager/5.0.1");
}

TEST(UpgradeHttpWpkRepositoryTest, UserAgentIsNeverEmpty)
{
    // An empty CURLOPT_USERAGENT sends no header, which is exactly what a WAF blocks.
    EXPECT_EQ(HttpWpkRepository::userAgentFor(""), "wazuh-manager");
    EXPECT_EQ(HttpWpkRepository::userAgentFor("v"), "wazuh-manager");
    EXPECT_EQ(HttpWpkRepository::Options {}.userAgent, "wazuh-manager");
}
