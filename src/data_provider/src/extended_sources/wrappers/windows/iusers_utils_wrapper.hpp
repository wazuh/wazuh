/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <winsock2.h>
#include <windows.h>
#include <limits>
#include <set>
#include <memory>
#include <string>
#include <vector>

struct User
{
    std::uint32_t generation{0};
    std::uint32_t uid{std::numeric_limits<std::uint32_t>::max()};
    std::uint32_t gid{std::numeric_limits<std::uint32_t>::max()};
    std::string sid;
    std::string username;
    std::string description;
    std::string type;
    std::string directory;

    bool operator==(const User& other) const
    {
        return uid == other.uid && gid == other.gid && sid == other.sid &&
               username == other.username && description == other.description &&
               type == other.type && directory == other.directory;
    }
};

// Interface for the windows user helper wrapper
class IUsersHelper
{
    public:
        /// Destructor
        virtual ~IUsersHelper() = default;

        /// @brief Converts a UTF-8 std::string to a wide string (wstring).
        /// @param src Input UTF-8 string.
        /// @return Converted wide string.
        virtual std::wstring stringToWstring(const std::string& src) = 0;

        /// @brief Retrieves the shell path for the user identified by the SID.
        /// @param sid String representation of the user's SID.
        /// @return The shell executable path.
        virtual std::string getUserShell(const std::string& sid) = 0;

        /// @brief Processes local Windows user accounts and collects user data.
        /// @param processed_sids Set to track processed SIDs and avoid duplicates.
        /// @return Vector of User objects representing local accounts.
        virtual std::vector<User> processLocalAccounts(std::set<std::string>& processed_sids) = 0;

        /// @brief Processes roaming profiles and collects user data.
        /// @param processed_sids Set to track processed SIDs and avoid duplicates.
        /// @return Vector of User objects representing roaming profiles.
        virtual std::vector<User> processRoamingProfiles(std::set<std::string>& processed_sids) = 0;

        /// @brief Retrieves the SID for a given account name.
        /// @param accountNameInput Wide string account name.
        /// @return Unique pointer managing the SID bytes.
        virtual std::unique_ptr<BYTE[]> getSidFromAccountName(const std::wstring& accountNameInput) = 0;

        /// @brief Converts a SID to its string representation.
        /// @param sid Pointer to the SID.
        /// @return String representation of the SID.
        virtual std::string psidToString(PSID sid) = 0;

        /// @brief Extracts the Relative Identifier (RID) from a SID.
        /// @param sid Pointer to the SID.
        /// @return RID as a DWORD.
        virtual DWORD getRidFromSid(PSID sid) = 0;
};
