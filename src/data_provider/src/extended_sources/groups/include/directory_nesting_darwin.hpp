/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <map>
#include <set>
#include <string>
#include <sys/types.h>
#include <vector>

/// @brief The local macOS groups that a directory service such as Active Directory feeds members
/// into, through the groups nested in them.
namespace DirectoryNesting
{
    struct LocalGroup
    {
        gid_t gid;
        std::string guid;
        std::set<std::string> nestedGuids;
    };

    /// @brief For each local group that nests a group from outside the local node, directly or
    /// through other local groups, the GUIDs of those outside groups. "Allow administration by"
    /// does this with `admin`. An account is in the local group through the directory service only
    /// when it is in one of those groups.
    /// @param localGuids The GUIDs of every group in the local node: any other GUID is a group of a
    /// directory service. GUIDs are compared as given, so they must be folded the same way.
    std::map<gid_t, std::set<std::string>> directoryFeeds(const std::vector<LocalGroup>& groups,
                                                          const std::set<std::string>& localGuids);
} // namespace DirectoryNesting
