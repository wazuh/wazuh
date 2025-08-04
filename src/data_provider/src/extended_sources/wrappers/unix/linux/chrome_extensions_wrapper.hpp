/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "ichrome_extensions_wrapper.hpp"
#include "filesystemHelper.h"
#include <pwd.h>

class ChromeExtensionsWrapper : public IChromeExtensionsWrapper
{
    public:
        std::string getHomePath() override
        {
            return std::string("/home");
        }

        std::unordered_map<std::string, std::string> getUserIdsMap() override
        {
            std::string homePath = getHomePath();
            std::unordered_map<std::string, std::string> userIdsMap;

            for (const auto& user : Utils::enumerateDir(homePath))
            {
                if (user == "." || user == "..") continue;

                struct passwd* pwd = getpwnam(user.c_str());

                if (pwd == nullptr)
                {
                    userIdsMap[Utils::joinPaths(homePath, user)] = "";
                }
                else
                {
                    userIdsMap[Utils::joinPaths(homePath, user)] = std::to_string(pwd->pw_uid);
                }
            }

            return userIdsMap;
        }
};
