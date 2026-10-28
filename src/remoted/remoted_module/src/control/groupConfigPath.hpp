/*
 * Wazuh remoted module - Shared configuration path of an agent's groups
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_CONTROL_GROUP_CONFIG_PATH_HPP
#define _REMOTED_CONTROL_GROUP_CONFIG_PATH_HPP

#include <string>
#include <string_view>
#include <vector>

namespace remoted::control
{
    /// A group name as authd and the API accept it when they assign one to an agent: 1 to 255
    /// bytes of [A-Za-z0-9._-], not "." or "..". It has no path separator, so a valid name is a
    /// safe path component.
    bool isValidGroupName(std::string_view name);

    /// Path of the merged.mg an agent with these groups downloads, or "" when there is none.
    ///
    /// The resolution /control uses for config_hash; /download validates group names with the same
    /// isValidGroupName(). An empty list is the "default" group (membershipGroups()). One group names
    /// <sharedGroupsRoot>/<group>/merged.mg; several name <multiGroupsRoot>/<hash>/merged.mg, <hash> being the first 32
    /// hex characters of the SHA-256 of toGroupsCsv(groups) -- wazuh-db's group_hash, so group order is part of the
    /// identity. A name that fails isValidGroupName(), or a failed digest, gives "".
    std::string resolveMergedConfigPath(std::vector<std::string> groups,
                                        const std::string& sharedGroupsRoot,
                                        const std::string& multiGroupsRoot);
} // namespace remoted::control

#endif // _REMOTED_CONTROL_GROUP_CONFIG_PATH_HPP
