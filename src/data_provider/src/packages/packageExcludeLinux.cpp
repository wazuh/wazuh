/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "filesystemHelper.h"
#include "packageLinuxDataRetriever.h"
#include "packageExclude.hpp"

void getExcludePackages(std::unordered_set<std::string>& excludedPaths)
{
    if (Utils::existsDir(DPKG_PATH))
    {
        getDpkgPythonPackages(excludedPaths);
    }

    if (Utils::existsDir(RPM_PATH))
    {
        getRpmPythonPackages(excludedPaths);
    }
}