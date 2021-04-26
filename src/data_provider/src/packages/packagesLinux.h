/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2021, Wazuh Inc.
 * April 16, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGES_LINUX_H
#define _PACKAGES_LINUX_H

#include <fstream>
#include "sharedDefs.h"
#include "cmdHelper.h"
#include "stringHelper.h"
#include "json.hpp"
#include "timeHelper.h"
#include "berkeleyRpmDbHelper.h"

class PackagesType{
    public:
        static void getPacmanInfo(const std::string& libPath, nlohmann::json& jsonPackages);
        static void getRpmInfo(nlohmann::json& jsonPackages);
        static void getDpkgInfo(const std::string& libPath, nlohmann::json& jsonPackages);
};

#endif // _PACKAGES_LINUX_H