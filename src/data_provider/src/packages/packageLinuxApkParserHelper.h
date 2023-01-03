/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2021, Wazuh Inc.
 * January 03, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGE_LINUX_APK_PARSER_HELPER_H
#define _PACKAGE_LINUX_APK_PARSER_HELPER_H

#include "json.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace PackageLinuxHelper
{
    static nlohmann::json parseApk(const std::vector<std::pair<char, std::string>>& entries)
    {
        nlohmann::json packageInfo;

        for (const auto& item : entries)
        {
            switch (item.first)
            {
                case 'P':
                    packageInfo["name"] = item.second;
                    break;

                case 'V':
                    packageInfo["version"] = item.second;
                    break;

                case 'A':
                    packageInfo["architecture"] = !item.second.empty() ? item.second : " ";
                    break;

                case 'I':
                    packageInfo["size"] = !item.second.empty() ? stol(item.second) : 0;
                    break;

                case 'T':
                    packageInfo["description"] = !item.second.empty() ? item.second : " ";
                    break;
            }
        }

        if (packageInfo.contains("name") &&
                packageInfo.contains("version") &&
                0 != packageInfo.at("name").get<std::string>().size() &&
                0 != packageInfo.at("version").get<std::string>().size())
        {

            if (!packageInfo.contains("architecture"))
            {
                packageInfo["architecture"] = " ";
            }

            if (!packageInfo.contains("size"))
            {
                packageInfo["size"] = 0;
            }

            if (!packageInfo.contains("description"))
            {
                packageInfo["description"] = " ";
            }

            packageInfo["format"] = "apk";
            packageInfo["vendor"] = "Alpine Linux";
            packageInfo["install_time"] = " ";
            packageInfo["location"] = " ";
            packageInfo["groups"] = " ";
            packageInfo["priority"] = " ";
            packageInfo["multiarch"] = " ";
            packageInfo["source"] = " ";
        }
        else
        {
            packageInfo.clear();
        }

        return packageInfo;
    }
}

#pragma GCC diagnostic pop

#endif // _PACKAGE_LINUX_APK_PARSER_HELPER_H