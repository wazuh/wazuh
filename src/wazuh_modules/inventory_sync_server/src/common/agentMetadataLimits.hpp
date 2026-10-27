/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_COMMON_AGENT_METADATA_LIMITS_HPP
#define _INVSYNC_COMMON_AGENT_METADATA_LIMITS_HPP

/**
 * @file agentMetadataLimits.hpp
 * @brief Bounds on the agent metadata (groups, host) the agent reports and this module copies
 *        into its documents, shared by the stateful Start validation and the /stats and /config
 *        endpoints.
 */

#include <cstddef>

namespace invsync::common
{
    /// Restates MAX_GROUPS_PER_MULTIGROUP (defs.h), which C++ does not include -- keep the two equal.
    constexpr std::size_t MAX_AGENT_GROUPS {128};
    /// One group name. Restates MAX_GROUP_NAME (defs.h).
    constexpr std::size_t MAX_AGENT_GROUP_NAME_BYTES {255};
    /// One host string (hostname, architecture, os.*): the agent keeps each in a char[256].
    constexpr std::size_t MAX_AGENT_HOST_FIELD_BYTES {255};
} // namespace invsync::common

#endif // _INVSYNC_COMMON_AGENT_METADATA_LIMITS_HPP
