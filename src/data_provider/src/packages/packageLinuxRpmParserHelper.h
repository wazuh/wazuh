/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * January 28, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGE_LINUX_RPM_PARSER_HELPER_H
#define _PACKAGE_LINUX_RPM_PARSER_HELPER_H

#include "json.hpp"
#include "rpmPackageManager.h"
#include "sharedDefs.h"

#include "stringHelper.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"


namespace PackageLinuxHelper
{
    static nlohmann::json parseRpm(const RpmPackageManager::Package& package)
    {
        nlohmann::json ret;
        auto version { package.version };
        std::string vendor       { UNKNOWN_VALUE };
        std::string email        { UNKNOWN_VALUE };

        if (package.epoch)
        {
            version = std::to_string(package.epoch) + ":" + version;
        }

        if (!package.release.empty())
        {
            version += "-" + package.release;
        }

        if (package.name.compare("gpg-pubkey") != 0 && !package.name.empty())
        {
            if (!package.vendor.empty())
            {
                Utils::splitMaintainerField(package.vendor, vendor, email);
            }

            ret["name"]         = package.name;
            ret["size"]         = package.size;
            ret["installed"]    = package.installTime;
            ret["path"]         = UNKNOWN_VALUE;
            ret["category"]     = package.group;
            ret["version"]      = version;
            ret["priority"]     = UNKNOWN_VALUE;
            ret["architecture"] = package.architecture;
            ret["source"]       = UNKNOWN_VALUE;
            ret["type"]         = "rpm";
            ret["vendor"]       = vendor;
            ret["description"]  = package.description;
        }

        return ret;
    }

};

#pragma GCC diagnostic pop

#endif // _PACKAGE_LINUX_RPM_PARSER_HELPER_H
