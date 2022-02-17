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

#ifndef _PACKAGE_LINUX_PARSER_HELPER_H
#define _PACKAGE_LINUX_PARSER_HELPER_H

#include "stringHelper.h"
#include "json.hpp"
#include "timeHelper.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"


// Parse helpers for standard Linux packaging systems (rpm, dpkg, ...)
namespace PackageLinuxHelper
{

    static nlohmann::json parseDpkg(const std::vector<std::string>& entries)
    {
        std::map<std::string, std::string> info;
        nlohmann::json ret;

        for (const auto& entry : entries)
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

};

#pragma GCC diagnostic pop

#endif // _PACKAGE_LINUX_PARSER_HELPER_H
