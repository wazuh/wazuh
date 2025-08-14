/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <string>
#include <pwd.h>
#include "ibrowser_extensions_wrapper.hpp"

#define APP_PATH "/Applications"
#define HOME_PATH "/Users"

class BrowserExtensionsWrapper : public IBrowserExtensionsWrapper
{
    public:
        std::string getApplicationsPath() override
        {
            return std::string(APP_PATH);
        }

        std::string getHomePath() override
        {
            return std::string(HOME_PATH);
        }

        std::string getUserId(std::string user) override
        {
            std::string uid = "";
            struct passwd* pwd = getpwnam(user.c_str());

            if (pwd != nullptr)
            {
                uid = std::to_string(pwd->pw_uid);
            }

            return uid;
        }
};
