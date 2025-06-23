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
#include "ibrowser_extensions_wrapper.hpp"

#define kAppPath "/Applications/"

class BrowserExtensionsWrapper : public IBrowserExtensionsWrapper
{
    public:
        std::string getApplicationsPath() override
        {
            return std::string(kAppPath);
        }
};
