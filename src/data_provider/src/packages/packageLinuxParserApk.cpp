/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * December 19, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "json.hpp"
#include <fstream>
#include "packageLinuxApkParserHelper.h"

void getApkInfo(const std::string& fileName, std::function<void(nlohmann::json&)> callback)
{
    std::ifstream apkDb(fileName);
    std::string line {};
    std::vector<std::pair<char, std::string>> data;

    // https://wiki.alpinelinux.org/wiki/Apk_spec#APKINDEX_Format
    std::array<char, 5> keys{'P', 'V', 'A', 'I', 'T'};
    const auto separator = ':';

    if (apkDb.is_open())
    {
        while (getline(apkDb, line))
        {
            if (!line.empty())
            {
                if (std::find(std::cbegin(keys), std::cend(keys), line.front()) != std::cend(keys))
                {
                    data.emplace_back(line.front(), line.substr(line.find_first_of(separator) + 1));
                }
            }
            else
            {
                auto packageInfo = PackageLinuxHelper::parseApk(data);
                data.clear();

                if (!packageInfo.empty())
                {
                    callback(packageInfo);
                }
            }
        }
    }
}
