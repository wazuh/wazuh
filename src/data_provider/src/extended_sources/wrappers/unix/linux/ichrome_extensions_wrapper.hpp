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
#include <unordered_map>

class IChromeExtensionsWrapper
{
    public:
        /// Destructor
        virtual ~IChromeExtensionsWrapper() = default;
        virtual std::string getHomePath() = 0;
        virtual std::unordered_map<std::string, std::string> getUserIdsMap() = 0;
};
