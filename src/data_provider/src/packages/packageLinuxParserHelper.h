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

#include <iostream>

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


    static nlohmann::json parseSnap(const nlohmann::json& info)
    {
        nlohmann::json ret;

    /*    std::string name;
        std::string version;
        std::string vendor;
        std::string install_time;
        std::string location;
        std::string architecture;
        std::string group;
        std::string description;
        std::string size;
        std::string priority;
        std::string multiarch;
        std::string source;
        std::string format;
    
        if (info.find("name")!=info.end()) {
            name = info.at("name");
        } 

        if (info.find("version")!=info.end()) {
            version = info.at("version");
        }

        if (info.find("publisher")!=info.end()) {
            auto publisher = info.at("publisher");
            if (publisher.find("display-name")!=publisher.end()) {
                vendor = publisher.at("display-name");
            }
        }


        if (info.find("install_time")!=info.end()) {
            install_time = info.at("install_time");
        }

        if (info.find("description")!=info.end()) {
            description = info.at("description");
        }

        if (info.find("installed-size")!=info.end()) {
            size = info.at("installed-size");
        }

        ret["name"]             = name;
        ret["location"]         = "/snap/" + name.substr(1, name.length()-2);
        ret["version"]          = version;
        ret["vendor"]           = vendor;
        ret["install_time"]     = install_time;
        ret["description"]      = description;
        ret["size"]             = size;
        ret["source"]           = "snapcraft";
        ret["format"]           = "snap";

        ret["priority"]         = "UNKOWN_VALUE";
        ret["multiarch"]        = "UNKOWN_VALUE";
        ret["architecture"]     = "UNKOWN_VALUE";
        ret["group"]            = "UNKOWN_VALUE";
*/
        std::cout << ret.dump() << std::endl;

        return ret;
    }


};

#pragma GCC diagnostic pop

#endif // _PACKAGE_LINUX_PARSER_HELPER_H
