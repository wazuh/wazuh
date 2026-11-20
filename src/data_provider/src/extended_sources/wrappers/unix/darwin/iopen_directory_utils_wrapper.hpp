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
#include "json.hpp"

/// @brief Direct members of one group record, as OpenDirectory stores them.
///
/// A group lists a member by name (`GroupMembership`), by the member's GUID (`GroupMembers`), or
/// both. Groups nested inside it (`NestedGroups`) are not members and are never listed here.
struct ODGroupMembers
{
    std::set<std::string> names;
    std::set<std::string> uuids;
};

// Interface for the open directory utils wrapper
class IODUtilsWrapper
{
    public:
        /// Destructor
        virtual ~IODUtilsWrapper() = default;

        /// @brief Queries local OpenDirectory records.
        ///
        /// Searches the local OpenDirectory node for user or group records based on `record_type`.
        /// If `record` is provided, filters by that name. Fills `names` with record names and
        /// a boolean indicating if each is hidden.
        ///
        /// @param record_type Type of record to search (e.g., users or groups).
        /// @param record Optional record name to filter the search.
        /// @param names Output map of record names to hidden status.
        virtual void genEntries(const std::string& recordType,
                                const std::string* record,
                                std::map<std::string, bool>& names) = 0;

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
        virtual void genAccountPolicyData(const std::string& uid, nlohmann::json& policyData) = 0;

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
        virtual void genPasswordData(std::map<std::string, nlohmann::json>& passwordData) = 0;

        /// @brief Collects the names of the accounts macOS marks as disabled.
        ///
        /// A disabled account keeps an OpenDirectory record identical to an enabled one, so the
        /// state cannot be read from the user record. macOS tracks it as membership in the
        /// `com.apple.access_disabled` group, which is what this function reads.
        ///
        /// @param disabledUsers Output set to be filled with the names of the disabled accounts.
        /// @return True when the directory was read, false when it could not be: an empty set then
        /// means the membership is unknown rather than nobody being disabled.
        virtual bool genDisabledUsers(std::set<std::string>& disabledUsers) = 0;

        /// @brief Reads the direct members of every local group in a single query.
        ///
        /// Only what the group record lists is returned: members by name and by GUID, without
        /// expanding nested groups. getgrent() cannot be used for this, its `gr_mem` leaves out
        /// the members a group lists only by GUID.
        ///
        /// @param membersByGroup Output map of group record name to its direct members.
        /// @return True when the directory was read, false when it could not be: the map is then
        /// not to be trusted, it does not mean the groups have no members.
        virtual bool genGroupMembers(std::map<std::string, ODGroupMembers>& membersByGroup) = 0;

        /// @brief Reads the GUID of every local user from its directory record, keyed by record name.
        ///
        /// The groups list their members by these GUIDs, so reading both from the same directory node
        /// keeps them consistent. mbr_uid_to_uuid() is not used for this: with the membership service
        /// unavailable it still succeeds and answers with a made-up UUID, not the account's own.
        ///
        /// @param guidByName Output map of record name (every name the record holds) to GUID; an account whose record has no GUID is left out.
        /// @return True when the directory was read, false when it could not be.
        virtual bool genUserGuids(std::map<std::string, std::string>& guidByName) = 0;
};
