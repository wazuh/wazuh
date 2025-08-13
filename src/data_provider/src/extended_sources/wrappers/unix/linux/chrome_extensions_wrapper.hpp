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

class ChromeExtensionsWrapper : public IChromeExtensionsWrapper
{
    public:
        std::string getHomePath() override
        {
            return std::string("/home");
        }
};
