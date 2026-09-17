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

class SudoersProvider
{
    public:
        /// Constructor
        explicit SudoersProvider(std::string fileName);

        /// Default constructor
        SudoersProvider();

        nlohmann::json collect();

        /// @brief Builds the User_Alias name -> member-list map used to resolve aliases in a user
        /// list, so callers checking several users against the same collected rules can build it
        /// once instead of paying to rebuild it on every isUserSudoer() call.
        ///
        /// @param sudoers Rules as returned by collect().
        /// @return Map of alias name to its (unexpanded) member-list string.
        static std::map<std::string, std::string> collectUserAliases(const nlohmann::json& sudoers);

        /// @brief Tells whether the collected rules grant sudo to a given user, by name, through one
        /// of userGroups (the stock macOS "%admin" and Linux "%sudo"/"%wheel" grants), or through a
        /// User_Alias covering either.
        ///
        /// Never matches what the endpoint cannot resolve -- netgroups ("+netgroup") and numeric ids
        /// ("#501", "%#80"). A "!"-prefixed entry does not itself grant, but per sudoers(5) it can
        /// revoke a grant an earlier entry in the same user list gave -- the last entry in the list
        /// that actually applies to the user (negated or not) decides the result.
        ///
        /// This overload builds the User_Alias map itself; prefer the one below when checking
        /// several users against the same sudoers rules, and build the map once with
        /// collectUserAliases().
        ///
        /// @param sudoers Rules as returned by collect().
        /// @param userName Name of the user to look up.
        /// @param userGroups Names of the groups the user belongs to.
        /// @return true when at least one rule grants sudo to the user.
        static bool isUserSudoer(const nlohmann::json& sudoers,
                                 const std::string& userName,
                                 const std::set<std::string>& userGroups);

        /// @brief Same as the overload above, but takes an already-built User_Alias map (see
        /// collectUserAliases()) instead of rebuilding it from sudoers on every call.
        ///
        /// @param sudoers Rules as returned by collect().
        /// @param userName Name of the user to look up.
        /// @param userGroups Names of the groups the user belongs to.
        /// @param userAliases Result of collectUserAliases(sudoers).
        /// @return true when at least one rule grants sudo to the user.
        static bool isUserSudoer(const nlohmann::json& sudoers,
                                 const std::string& userName,
                                 const std::set<std::string>& userGroups,
                                 const std::map<std::string, std::string>& userAliases);

    private:
        void genSudoersFile(const std::string& fileName,
                            unsigned int level,
                            nlohmann::json& results);

        // #if !defined(FREEBSD)
        // const std::string kSudoFile = "/etc/sudoers";
        // #else
        // const std::string kSudoFile = "/usr/local/etc/sudoers";
        // #endif
        std::string m_sudoFile;
};
