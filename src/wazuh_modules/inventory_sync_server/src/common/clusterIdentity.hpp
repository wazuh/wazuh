/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_COMMON_CLUSTER_IDENTITY_HPP
#define _INVSYNC_COMMON_CLUSTER_IDENTITY_HPP

#include "inventory_sync_server.h"

#include <string>

namespace invsync::common
{

    /**
     * @brief This manager's cluster name and node name, copied out of the C-ABI config.
     *
     * `std::string`, not a reference into `inventory_sync_server_config_t`: the endpoints capture
     * this by value into handlers that are registered once and live for the process's lifetime, well
     * past the single start() call that owns the C-ABI struct's fixed buffers. Two small strings are
     * cheap to copy once per attempt and cannot dangle.
     */
    struct ClusterIdentity
    {
        std::string clusterName;
        std::string nodeName;
    };

    /**
     * @brief Reads the two fixed-size buffers out of the module's config.
     *
     * Same "C-ABI struct -> typed value" shape as buildServerConfig() (http_server/) and
     * buildSyncConnectorConfig()/buildAsyncConnectorConfig() (indexer/): a free function next to the
     * type it builds, independently testable, no facade state involved.
     *
     * An empty buffer stays an empty string -- inventory_sync_server_config_t documents empty as
     * "no opinion", and stamping "" is what an operator sees if cluster/node were never configured.
     */
    inline ClusterIdentity buildClusterIdentity(const inventory_sync_server_config_t& config)
    {
        return ClusterIdentity {config.cluster_name, config.node_name};
    }

} // namespace invsync::common

#endif // _INVSYNC_COMMON_CLUSTER_IDENTITY_HPP
