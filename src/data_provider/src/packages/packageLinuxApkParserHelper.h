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
#include "sharedDefs.h"
#include <typeindex>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace PackageLinuxHelper
{
    static const std::map<char, std::pair<std::type_index, std::string>> s_mapAlpineFields =
    {
        {'P', {typeid(std::string), "name"}},
        {'V', {typeid(std::string), "version_"}},
        {'A', {typeid(std::string), "architecture"}},
        {'I', {typeid(int64_t), "size"}},
        {'T', {typeid(std::string), "description"}},
    };

    static nlohmann::json parseApk(const std::vector<std::pair<char, std::string>>& entries)
    {
        nlohmann::json packageInfo;

        packageInfo["architecture"] = UNKNOWN_VALUE;
        packageInfo["size"] = 0;
        packageInfo["type"] = "apk";
        packageInfo["vendor"] = "Alpine Linux";
        packageInfo["installed"] = UNKNOWN_VALUE;
        packageInfo["path"] = UNKNOWN_VALUE;
        packageInfo["category"] = UNKNOWN_VALUE;
        packageInfo["priority"] = UNKNOWN_VALUE;
        packageInfo["source"] = UNKNOWN_VALUE;
        // The multiarch field won't have a default value

        // Lambda to check if a string is empty and assign default value.
        const auto loadData = [&packageInfo](const std::pair<std::type_index, std::string>& key,
                                             const std::string & value)
        {
            if (!value.empty())
            {
                if (key.first == typeid(std::string))
                {
                    packageInfo[key.second] = value;
                }
                else if (key.first == typeid(int64_t))
                {
                    try
                    {
                        packageInfo[key.second] = std::stoll(value);
                    }
                    catch (const std::exception&)
                    {
                        packageInfo[key.second] = 0;
                    }
                }
            }
        };

        for (const auto& item : entries)
        {
            loadData(s_mapAlpineFields.at(item.first), item.second);
        }

        if (!packageInfo.contains("name") ||
                !packageInfo.contains("version_"))
        {
            packageInfo.clear();
        }

        return packageInfo;
    }
}

#pragma GCC diagnostic pop

#endif // _PACKAGE_LINUX_APK_PARSER_HELPER_H
