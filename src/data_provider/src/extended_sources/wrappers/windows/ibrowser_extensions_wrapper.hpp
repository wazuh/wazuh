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
#include "filesystemHelper.h"

class IBrowserExtensionsWrapper
{
    public:
        /// Destructor
        virtual ~IBrowserExtensionsWrapper() = default;
        virtual std::string getHomePath() = 0;
        virtual std::string getApplicationsPath() = 0;
        virtual std::string getUserId(std::string user) = 0;
        /// @brief Tells whether a home directory entry is an automount point not mounted yet, so it is
        /// skipped instead of mounted by looking inside it.
        virtual bool isUnmountedAutomountPoint(const std::string& path)
        {
            return Utils::isUnmountedAutomountPoint(path);
        }
};
