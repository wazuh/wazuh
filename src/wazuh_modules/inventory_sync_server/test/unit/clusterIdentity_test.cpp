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
#include <json.hpp>

#include <cstdio>
#include <cstring>

using namespace nlohmann::literals;

namespace
{
    inventory_sync_server_config_t zeroedConfig()
    {
        inventory_sync_server_config_t config {};
        return config;
    }
} // namespace

TEST(ClusterIdentityTest, ReadsClusterName)
{
    auto config = zeroedConfig();
    std::snprintf(config.cluster_name, sizeof(config.cluster_name), "%s", "prod-cluster");

    const auto identity = invsync::common::buildClusterIdentity(config);

    EXPECT_EQ("prod-cluster", identity.clusterName);
}

/// inventory_sync_server_config_t documents an empty buffer as "no opinion" -- confirmed here rather
/// than assumed, since the endpoints stamp whatever this returns without a further empty-check.
TEST(ClusterIdentityTest, EmptyBufferBuildsEmptyString)
{
    const auto identity = invsync::common::buildClusterIdentity(zeroedConfig());

    EXPECT_EQ("", identity.clusterName);
}

/**
 * @brief Invalid UTF-8 in a manager-side name must not reach the JSON serializer.
 *
 * The failure this prevents was a total outage of /stats and /config: nlohmann validates UTF-8 at
 * dump() time, not on assignment, so one stray latin-1 byte in <cluster><name> made the serialization
 * of EVERY enriched document throw, and the endpoints answered 400 "Body must be a JSON object" --
 * blaming the agent for a manager configuration problem, with the only trace at debug level.
 */
TEST(ClusterIdentityTest, InvalidUtf8IsReplacedAndReported)
{
    auto config = zeroedConfig();
    // 0xFF is never valid UTF-8 anywhere.
    std::snprintf(config.cluster_name, sizeof(config.cluster_name), "%s", "prod-\xff-cluster");

    const auto identity = invsync::common::buildClusterIdentity(config);

    EXPECT_TRUE(identity.sanitized) << "the caller has to be able to warn about it";
    EXPECT_EQ("prod-?-cluster", identity.clusterName);

    // The point of the exercise: what comes out can be serialized.
    nlohmann::json document = nlohmann::json::object();
    document["/wazuh/cluster/name"_json_pointer] = identity.clusterName;
    EXPECT_NO_THROW(document.dump());
}

/// Well-formed multi-byte UTF-8 must survive untouched -- accented cluster names are legitimate.
TEST(ClusterIdentityTest, ValidMultiByteUtf8IsPreserved)
{
    auto config = zeroedConfig();
    std::snprintf(config.cluster_name, sizeof(config.cluster_name), "%s", "cl\xc3\xbaster-\xe2\x9c\x93");

    const auto identity = invsync::common::buildClusterIdentity(config);

    EXPECT_FALSE(identity.sanitized);
    EXPECT_EQ("cl\xc3\xbaster-\xe2\x9c\x93", identity.clusterName);
}

/// A truncated multi-byte sequence at the very end is the other way this arises: a name that was cut
/// mid-character by the fixed-size buffer it travels in.
TEST(ClusterIdentityTest, ATruncatedSequenceAtTheEndIsReplaced)
{
    auto config = zeroedConfig();
    std::snprintf(config.cluster_name, sizeof(config.cluster_name), "%s", "prod-\xc3");

    const auto identity = invsync::common::buildClusterIdentity(config);

    EXPECT_TRUE(identity.sanitized);
    EXPECT_EQ("prod-?", identity.clusterName);
    nlohmann::json document = nlohmann::json::object();
    document["/wazuh/cluster/name"_json_pointer] = identity.clusterName;
    EXPECT_NO_THROW(document.dump());
}
