/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

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

        /// @brief Tells whether the collected rules grant sudo to a given user, by name, through one
        /// of userGroups (the stock macOS "%admin" and Linux "%sudo"/"%wheel" grants), or through a
        /// User_Alias covering either.
        ///
        /// Never matches what the endpoint cannot resolve -- netgroups ("+netgroup") and numeric ids
        /// ("#501", "%#80") -- nor negated entries, which subtract from a grant instead of adding one.
        ///
        /// @param sudoers Rules as returned by collect().
        /// @param userName Name of the user to look up.
        /// @param userGroups Names of the groups the user belongs to.
        /// @return true when at least one rule grants sudo to the user.
        static bool isUserSudoer(const nlohmann::json& sudoers,
                                 const std::string& userName,
                                 const std::set<std::string>& userGroups);

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
