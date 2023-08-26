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

#ifndef _PACKAGE_LINUX_PARSER_HELPER_EXTRA_H
#define _PACKAGE_LINUX_PARSER_HELPER_EXTRA_H

#include <fstream>
#include "sharedDefs.h"
#include "cmdHelper.h"
#include "stringHelper.h"
#include "json.hpp"
#include "timeHelper.h"
#include <alpm.h>
#include <package.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"


// Parse helper for partially incompatible Linux packaging systems (pacman, ...)
namespace PackageLinuxHelper
{
    static nlohmann::json parsePacman(const alpm_list_t* pItem)
    {
        const auto pArchPkg{reinterpret_cast<alpm_pkg_t*>(pItem->data)};
        nlohmann::json packageInfo;
        std::string groups;
        static const auto alpmWrapper
        {
            [] (auto pkgData)
            {
                return pkgData ? pkgData : "";
            }
        };

        packageInfo["name"]         = alpmWrapper(alpm_pkg_get_name(pArchPkg));
        packageInfo["size"]         = alpm_pkg_get_isize(pArchPkg);
        packageInfo["install_time"] = Utils::getTimestamp(static_cast<time_t>(alpm_pkg_get_installdate(pArchPkg)));

        for (auto group{alpm_pkg_get_groups(pArchPkg)}; group; group = alpm_list_next(group))
        {
            if (group->data)
            {
                const std::string groupString{reinterpret_cast<char*>(group->data)};
                groups  += groupString + "-";
            }
        }

        packageInfo["groups"]       = groups.empty() ? UNKNOWN_VALUE : groups.substr(0, groups.size() - 1);
        const std::string version          = alpmWrapper(alpm_pkg_get_version(pArchPkg));
        packageInfo["version"]      = version.empty() ? UNKNOWN_VALUE : version;
        packageInfo["location"]     = UNKNOWN_VALUE;
        const std::string architecture = alpmWrapper(alpm_pkg_get_arch(pArchPkg));
        packageInfo["architecture"] = architecture.empty() ? UNKNOWN_VALUE : architecture;
        packageInfo["priority"]         = UNKNOWN_VALUE;
        packageInfo["format"]       = "pacman";
        packageInfo["vendor"]       = "Arch Linux";
        packageInfo["source"]       = UNKNOWN_VALUE;
        const std::string description = alpmWrapper(alpm_pkg_get_desc(pArchPkg));
        packageInfo["description"]  = description.empty() ? UNKNOWN_VALUE : description;
        // The multiarch field won't have a default value

        return packageInfo;
    }

};

#pragma GCC diagnostic pop

#endif // _PACKAGE_LINUX_PARSER_HELPER_EXTRA_H
