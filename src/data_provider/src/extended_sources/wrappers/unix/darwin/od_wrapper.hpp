/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <map>
#include <string>

#include "json.hpp"

namespace od
{
    /// @brief Queries local OpenDirectory records.
    ///
    /// Searches the local OpenDirectory node for user or group records based on `record_type`.
    /// If `record` is provided, filters by that name. Fills `names` with record names and
    /// a boolean indicating if each is hidden.
    ///
    /// @param record_type Type of record to search (e.g., users or groups).
    /// @param record Optional record name to filter the search.
    /// @param names Output map of record names to hidden status.
    void genEntries(const std::string& record_type,
                    const std::string* record,
                    std::map<std::string, bool>& names);

    /// @brief Retrieves account policy data for a given user UID.
    ///
    /// Queries the local OpenDirectory node for the `accountPolicyData` attribute of the user
    /// corresponding to the provided UID. Parses the returned property list (plist) data
    /// and extracts relevant account policy fields.
    ///
    /// The following fields are extracted and populated in the output JSON object:
    /// - "creation_time": When the account was first created (double)
    /// - "failed_login_count": Number of failed login attempts (int)
    /// - "failed_login_timestamp": Time of last failed login attempt (double)
    /// - "password_last_set_time": Time when the password was last changed (double)
    ///
    /// If the user does not have `accountPolicyData`, or the attribute is missing or malformed,
    /// the output JSON will still contain those fields with `null` values.
    ///
    /// @param uid The UID of the user to query.
    /// @param policyData Output JSON object to be populated with account policy data.
    void genAccountPolicyData(const std::string& uid, nlohmann::json& policyData);

} // namespace od
