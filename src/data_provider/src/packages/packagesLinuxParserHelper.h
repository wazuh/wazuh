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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace PackageLinuxHelper
{
    static nlohmann::json parseRpm(const std::string& packageInfo)
    {
        nlohmann::json ret;
        std::string token;
        std::istringstream tokenStream{ packageInfo };
        std::map<std::string, std::string> info;
        while (std::getline(tokenStream, token))
        {
            auto pos{token.find(":")};
            while (pos != std::string::npos && (pos + 1) < token.size())
            {
                const auto key{Utils::trim(token.substr(0, pos))};
                token = Utils::trim(token.substr(pos + 1));
                if(((pos = token.find("  ")) != std::string::npos) ||
                ((pos = token.find("\t")) != std::string::npos))
                {
                    info[key] = Utils::trim(token.substr(0, pos), " \t");
                    token = Utils::trim(token.substr(pos));
                    pos = token.find(":");
                }
                else
                {
                    info[key] = token;
                }
            }
        }
        auto it{info.find("Name")};
        if (it != info.end() && it->second != "gpg-pubkey")
        {
            std::string size         { UNKNOWN_VALUE };
            std::string install_time { UNKNOWN_VALUE };
            std::string groups       { UNKNOWN_VALUE };
            std::string version;
            std::string architecture { UNKNOWN_VALUE };
            std::string vendor       { UNKNOWN_VALUE };
            std::string description  { UNKNOWN_VALUE };

            ret["name"] = it->second;

            it = info.find("Size");
            if (it != info.end())
            {
                size = it->second;
            }
            it = info.find("Install Date");
            if (it != info.end())
            {
                install_time = it->second;
            }
            it = info.find("Group");
            if (it != info.end())
            {
                groups = it->second;
            }
            it = info.find("Epoch");
            if (it != info.end())
            {
                version += it->second + "-";
            }
            it = info.find("Release");
            if (it != info.end())
            {
                version +=it->second + "-";
            }
            it = info.find("Version");
            if (it != info.end())
            {
                version += it->second;
            }
            it = info.find("Architecture");
            if (it != info.end())
            {
                architecture = it->second;
            }
            it = info.find("Vendor");
            if (it != info.end())
            {
                vendor = it->second;
            }
            it = info.find("Summary");
            if (it != info.end())
            {
                // For the "Description" field it has been decided to populate it with the "Summary" field information
                // so that Kibana is able to show this in a easier and clear way.
                description = it->second;
            }

            ret["size"]         = size;
            ret["install_time"] = install_time;
            ret["groups"]       = groups;
            ret["version"]      = version.empty() ? UNKNOWN_VALUE : version;
            ret["architecture"] = architecture;
            ret["format"]       = "rpm";
            ret["os_patch"]     = UNKNOWN_VALUE;
            ret["vendor"]       = vendor;
            ret["description"]  = description;
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

            std::string priority     { UNKNOWN_VALUE };
            std::string groups       { UNKNOWN_VALUE };
            std::string size         { UNKNOWN_VALUE };
            std::string multiarch    { UNKNOWN_VALUE };
            std::string architecture { UNKNOWN_VALUE };
            std::string source       { UNKNOWN_VALUE };
            std::string version      { UNKNOWN_VALUE };
            std::string vendor       { UNKNOWN_VALUE };
            std::string description  { UNKNOWN_VALUE };

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
                size = it->second;
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
                description = it->second;
            }

            ret["priority"]     = priority;
            ret["groups"]       = groups;
            ret["size"]         = size;
            ret["multiarch"]    = multiarch;
            ret["architecture"] = architecture;
            ret["source"]       = source;
            ret["version"]      = version;
            ret["format"]       = "deb";
            ret["os_patch"]     = UNKNOWN_VALUE;
            ret["vendor"]       = vendor;
            ret["description"]  = description;
        }
        return ret;
    }
};

#endif // _PACKAGES_LINUX_PARSER_HELPER_H
