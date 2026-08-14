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
     * @brief This manager's cluster name, copied out of the C-ABI config.
     *
     * `std::string`, not a reference into `inventory_sync_server_config_t`: the endpoints capture
     * this by value into handlers that are registered once and live for the process's lifetime, well
     * past the single start() call that owns the C-ABI struct's fixed buffer. A small string is
     * cheap to copy once per attempt and cannot dangle.
     */
    struct ClusterIdentity
    {
        std::string clusterName;
        /// True when the name contained bytes that are not valid UTF-8 and were replaced. The facade
        /// logs it once at startup; keeping the reporting out of here avoids pulling the logger into
        /// headers the endpoint tests include.
        bool sanitized {false};
    };

    /**
     * @brief Replaces any byte that is not part of well-formed UTF-8 with '?'.
     *
     * The reason this exists at all: this name comes from the MANAGER's own configuration and is
     * stamped into every enriched document, and nlohmann validates UTF-8 at dump() time rather than on
     * assignment. A single stray latin-1 byte in `<cluster><name>` -- a mis-encoded accent is enough --
     * therefore made the serialization of EVERY request throw, and the endpoints answered 400 "Body
     * must be a JSON object": a total outage of /stats and /config that blamed the agent for a
     * manager-side configuration problem, with the only trace at debug level.
     *
     * Sanitising once here, at startup, removes that whole failure mode from the request path. Rejecting
     * the name outright would be the other option, but refusing to serve because of a cosmetic
     * configuration typo is worse than serving the name with a visible replacement character.
     */
    inline std::string sanitizeUtf8(const char* raw, bool& changed)
    {
        std::string out;
        const std::string input {raw};
        out.reserve(input.size());

        for (std::size_t i = 0; i < input.size();)
        {
            const auto byte = static_cast<unsigned char>(input[i]);

            std::size_t sequenceLength {0};
            if (byte < 0x80U)
            {
                sequenceLength = 1;
            }
            else if ((byte & 0xE0U) == 0xC0U)
            {
                sequenceLength = 2;
            }
            else if ((byte & 0xF0U) == 0xE0U)
            {
                sequenceLength = 3;
            }
            else if ((byte & 0xF8U) == 0xF0U)
            {
                sequenceLength = 4;
            }

            // A bad leading byte, a truncated sequence, or a continuation byte that is not one.
            bool valid = sequenceLength != 0 && i + sequenceLength <= input.size();
            for (std::size_t k = 1; valid && k < sequenceLength; ++k)
            {
                valid = (static_cast<unsigned char>(input[i + k]) & 0xC0U) == 0x80U;
            }

            if (!valid)
            {
                out += '?';
                changed = true;
                ++i;
                continue;
            }

            out.append(input, i, sequenceLength);
            i += sequenceLength;
        }

        return out;
    }

    /**
     * @brief Reads the fixed-size buffer out of the module's config.
     *
     * Same "C-ABI struct -> typed value" shape as buildServerConfig() (http_server/) and
     * buildSyncConnectorConfig()/buildAsyncConnectorConfig() (indexer/): a free function next to the
     * type it builds, independently testable, no facade state involved.
     *
     * An empty buffer stays an empty string -- inventory_sync_server_config_t documents empty as
     * "no opinion", and stamping "" is what an operator sees if the cluster name was never configured.
     */
    inline ClusterIdentity buildClusterIdentity(const inventory_sync_server_config_t& config)
    {
        ClusterIdentity identity;
        identity.clusterName = sanitizeUtf8(config.cluster_name, identity.sanitized);
        return identity;
    }

} // namespace invsync::common

#endif // _INVSYNC_COMMON_CLUSTER_IDENTITY_HPP
