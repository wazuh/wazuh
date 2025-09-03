/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "policyHarvesterManager.hpp"
#include "gtest/gtest.h"

class PolicyHarvesterManagerTest : public ::testing::Test
{
protected:
    PolicyHarvesterManagerTest() = default;
    // LCOV_EXCL_START
    ~PolicyHarvesterManagerTest() override = default;
    // LCOV_EXCL_STOP

    std::unique_ptr<PolicyHarvesterManager> m_policyHarvesterManager = std::make_unique<PolicyHarvesterManager>();
};

TEST_F(PolicyHarvesterManagerTest, ModuleEnabled)
{
    nlohmann::json configJson = nlohmann::json::parse(R"({
        "enabled": true,
        "clusterName": "clusterName",
        "clusterEnabled": false
    })");

    m_policyHarvesterManager->initialize(configJson);
    EXPECT_EQ(m_policyHarvesterManager->isGlobalQueriesEnabled(), true);
}

TEST_F(PolicyHarvesterManagerTest, ModuleDisabled)
{
    nlohmann::json configJson = nlohmann::json::parse(R"({
        "enabled": false,
        "clusterName": "clusterName",
        "clusterEnabled": false
    })");

    m_policyHarvesterManager->initialize(configJson);
    EXPECT_EQ(m_policyHarvesterManager->isGlobalQueriesEnabled(), false);
}

TEST_F(PolicyHarvesterManagerTest, EnabledOptionNotFound)
{
    nlohmann::json configJson = nlohmann::json::parse(R"({
        "clusterName": "clusterName",
        "clusterEnabled": false
    })");

    m_policyHarvesterManager->initialize(configJson);
    EXPECT_EQ(m_policyHarvesterManager->isGlobalQueriesEnabled(), true);
}
