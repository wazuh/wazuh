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
#include <set>
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

    /// @brief Retrieves the password status and hash algorithm of every local user.
    ///
    /// Reads the whole local OpenDirectory node in a single query and derives, per account,
    /// the state of its `AuthenticationAuthority` attribute. macOS stores no shadow file, so
    /// the presence of a `;ShadowHash;` authority is what tells a password apart from an
    /// account that has none, and that same authority carries the enabled algorithms as
    /// `HASHLIST:<alg1,alg2,...>`.
    ///
    /// Each entry is keyed by every name the record holds, since getpwuid may report an
    /// alias rather than the primary one, and holds:
    /// - "password_status": "active" when a password is set, "not_set" otherwise (string)
    /// - "password_hash_algorithm": first algorithm of the hash list, empty when absent (string)
    ///
    /// A record whose attribute cannot be read is omitted, so that callers can tell a failed
    /// lookup apart from an account with no password.
    ///
    /// @param passwordData Output map of record name to its password data.
    void genPasswordData(std::map<std::string, nlohmann::json>& passwordData);

    /// @brief Collects the names of the accounts macOS marks as disabled.
    ///
    /// A disabled account keeps an OpenDirectory record identical to an enabled one, so the
    /// state cannot be read from the user record. macOS tracks it as membership in the
    /// `com.apple.access_disabled` group, which is what this function reads.
    ///
    /// @param disabledUsers Output set to be filled with the names of the disabled accounts.
    /// @return True when the directory was read, false when it could not be: an empty set then
    /// means the membership is unknown rather than nobody being disabled.
    bool genDisabledUsers(std::set<std::string>& disabledUsers);

} // namespace od
