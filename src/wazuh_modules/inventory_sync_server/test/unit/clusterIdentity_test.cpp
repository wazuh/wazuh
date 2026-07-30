/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "common/clusterIdentity.hpp"
#include "inventory_sync_server.h"

#include <gtest/gtest.h>

#include <cstring>

namespace
{
    inventory_sync_server_config_t zeroedConfig()
    {
        inventory_sync_server_config_t config {};
        return config;
    }
} // namespace

TEST(ClusterIdentityTest, ReadsBothFixedBuffers)
{
    auto config = zeroedConfig();
    std::snprintf(config.cluster_name, sizeof(config.cluster_name), "%s", "prod-cluster");
    std::snprintf(config.node_name, sizeof(config.node_name), "%s", "node-07");

    const auto identity = invsync::common::buildClusterIdentity(config);

    EXPECT_EQ("prod-cluster", identity.clusterName);
    EXPECT_EQ("node-07", identity.nodeName);
}

/// inventory_sync_server_config_t documents an empty buffer as "no opinion" -- confirmed here rather
/// than assumed, since the endpoints stamp whatever this returns without a further empty-check.
TEST(ClusterIdentityTest, EmptyBuffersBuildEmptyStrings)
{
    const auto identity = invsync::common::buildClusterIdentity(zeroedConfig());

    EXPECT_EQ("", identity.clusterName);
    EXPECT_EQ("", identity.nodeName);
}

TEST(ClusterIdentityTest, OneFieldSetDoesNotLeakIntoTheOther)
{
    auto config = zeroedConfig();
    std::snprintf(config.cluster_name, sizeof(config.cluster_name), "%s", "only-cluster-set");

    const auto identity = invsync::common::buildClusterIdentity(config);

    EXPECT_EQ("only-cluster-set", identity.clusterName);
    EXPECT_EQ("", identity.nodeName);
}
