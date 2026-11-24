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

/// @brief How macOS account names and GUIDs are compared when matching group members.
///
/// Account names are not case sensitive on macOS, so a group listing "Bob" lists the user "bob":
/// names are folded to lower case. OpenDirectory writes GUIDs in upper case, but nothing
/// guarantees it for every record: GUIDs are folded to upper case. Only ASCII letters are folded.
namespace DirectoryKeys
{
    std::string name(std::string accountName);
    std::string guid(std::string value);
    std::set<std::string> names(const std::set<std::string>& accountNames);
    std::set<std::string> guids(const std::set<std::string>& values);

    /// @brief The same map with every account name key folded. Keys that fold to the same name
    /// keep the value of the last one in key order.
    std::map<std::string, std::string> byName(const std::map<std::string, std::string>& valueByAccountName);
} // namespace DirectoryKeys
