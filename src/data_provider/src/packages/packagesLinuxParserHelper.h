/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2021, Wazuh Inc.
 * January 28, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGES_LINUX_PARSER_HELPER_H
#define _PACKAGES_LINUX_PARSER_HELPER_H

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

namespace PackageLinuxHelper
{
    static nlohmann::json parseRpm(const std::string& packageInfo)
    {
        nlohmann::json ret;
        const auto fields { Utils::split(packageInfo,'\t') };
        constexpr auto DEFAULT_VALUE { "(none)" };

        if (RPMFields::RPM_FIELDS_SIZE <= fields.size())
        {
            std::string name             { fields.at(RPMFields::RPM_FIELDS_NAME) };
            if (name.compare("gpg-pubkey") != 0 && !name.empty())
            {
                std::string size         { fields.at(RPMFields::RPM_FIELDS_PACKAGE_SIZE) };
                std::string install_time { fields.at(RPMFields::RPM_FIELDS_INSTALLTIME) };
                std::string groups       { fields.at(RPMFields::RPM_FIELDS_GROUPS) };
                std::string version      { fields.at(RPMFields::RPM_FIELDS_VERSION) };
                std::string architecture { fields.at(RPMFields::RPM_FIELDS_ARCHITECTURE) };
                std::string vendor       { fields.at(RPMFields::RPM_FIELDS_VENDOR) };
                std::string description  { fields.at(RPMFields::RPM_FIELDS_SUMMARY) };

                std::string release      { fields.at(RPMFields::RPM_FIELDS_RELEASE) };
                std::string epoch        { fields.at(RPMFields::RPM_FIELDS_EPOCH) };

                if (!epoch.empty() && epoch.compare(DEFAULT_VALUE) != 0)
                {
                    version = epoch + ":" + version;
                }

                if (!release.empty() && release.compare(DEFAULT_VALUE) != 0)
                {
                    version += "-" + release;
                }

                ret["name"]         = name;
                ret["size"]         = size.empty() || size.compare(DEFAULT_VALUE) == 0 ? 0 : stoi(size);
                ret["install_time"] = install_time.empty() || install_time.compare(DEFAULT_VALUE) == 0 ? "" : install_time;
                ret["groups"]       = groups.empty() || groups.compare(DEFAULT_VALUE) == 0 ? "" : groups;
                ret["version"]      = version.empty() || version.compare(DEFAULT_VALUE) == 0 ? "" : version;
                ret["architecture"] = architecture.empty() || architecture.compare(DEFAULT_VALUE) == 0 ? "" : architecture;
                ret["format"]       = "rpm";
                ret["vendor"]       = vendor.empty() || vendor.compare(DEFAULT_VALUE) == 0 ? "" : vendor;
                ret["description"]  = description.empty() || description.compare(DEFAULT_VALUE) == 0 ? "" : description;
            }
        }
        return ret;
    }

    static nlohmann::json parseDpkg(const std::vector<std::string>& entries)
    {
        std::map<std::string, std::string> info;
        nlohmann::json ret;
        for (const auto& entry: entries)
        {
            const auto pos{entry.find(":")};
            if (pos != std::string::npos)
            {
                const auto key{Utils::trim(entry.substr(0, pos))};
                const auto value{Utils::trim(entry.substr(pos + 1), " \n")};
                info[key] = value;
            }
        }
        if (!info.empty() && info.at("Status") == "install ok installed")
        {
            ret["name"] = info.at("Package");

            std::string priority;
            std::string groups;
            std::string multiarch;
            std::string architecture;
            std::string source;
            std::string version;
            std::string vendor;
            std::string description;
            int size                 { 0 };

            auto it{info.find("Priority")};
            if (it != info.end())
            {
                priority = it->second;
            }
            it = info.find("Section");
            if (it != info.end())
            {
                groups = it->second;
            }
            it = info.find("Installed-Size");
            if (it != info.end())
            {
                size = stol(it->second);
            }
            it = info.find("Multi-Arch");
            if (it != info.end())
            {
                multiarch = it->second;
            }
            it = info.find("Architecture");
            if (it != info.end())
            {
                architecture = it->second;
            }
            it = info.find("Source");
            if (it != info.end())
            {
                source = it->second;
            }
            it = info.find("Version");
            if (it != info.end())
            {
                version = it->second;
            }
            it = info.find("Maintainer");
            if (it != info.end())
            {
                vendor = it->second;
            }
            it = info.find("Description");
            if (it != info.end())
            {
                description = Utils::substrOnFirstOccurrence(it->second, "\n");
            }

            ret["priority"]     = priority;
            ret["groups"]       = groups;
            ret["size"]         = size;
            ret["multiarch"]    = multiarch;
            ret["architecture"] = architecture;
            ret["source"]       = source;
            ret["version"]      = version;
            ret["format"]       = "deb";
            ret["vendor"]       = vendor;
            ret["description"]  = description;
        }
        return ret;
    }

    static nlohmann::json parsePacman(const alpm_list_t *item)
    {
        alpm_pkg_t* pkg{reinterpret_cast<alpm_pkg_t*>(item->data)};
        nlohmann::json packageInfo;
        std::string groups;
        auto alpmWrapper
        {
            [] (auto pkgData) { return pkgData ? pkgData : ("(null)"); }
        };

        packageInfo["name"]         = alpmWrapper(alpm_pkg_get_name(pkg));
        packageInfo["size"]         = alpm_pkg_get_isize(pkg);
        packageInfo["install_time"] = Utils::getTimestamp(static_cast<time_t>(alpm_pkg_get_installdate(pkg)));
        for (auto group{alpm_pkg_get_groups(pkg)}; group; group = alpm_list_next(group))
        {
            if (!group->data)
            {
                group->data = const_cast<char *>("(null)");
            }
            const std::string groupString{reinterpret_cast<char*>(group->data)};
            groups += groupString + "-";
        }
        groups = groups.empty() ? "": groups.substr(0, groups.size()-1);
        packageInfo["groups"]       = groups;
        packageInfo["version"]      = alpmWrapper(alpm_pkg_get_version(pkg));
        packageInfo["architecture"] = alpmWrapper(alpm_pkg_get_arch(pkg));
        packageInfo["format"]       = "pacman";
        packageInfo["vendor"]       = "";
        packageInfo["description"]  = alpmWrapper(alpm_pkg_get_desc(pkg));
        return packageInfo;
    }
};

#endif // _PACKAGES_LINUX_PARSER_HELPER_H
