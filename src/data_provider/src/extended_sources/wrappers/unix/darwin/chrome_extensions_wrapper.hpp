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
// #include "filesystemHelper.h"
#include <pwd.h>

class ChromeExtensionsWrapper : public IChromeExtensionsWrapper
{
    public:
        std::string getHomePath() override
        {
            return std::string("/Users");
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
