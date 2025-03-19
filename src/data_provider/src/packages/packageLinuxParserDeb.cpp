/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * April 16, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sharedDefs.h"
#include "packageLinuxParserHelper.h"
#include <fstream>

void getDpkgInfo(const std::string& fileName, std::function<void(nlohmann::json&)> callback)
{
    std::fstream file{fileName, std::ios_base::in};

    if (file.is_open())
    {
        while (file.good())
        {
            std::string line;
            std::vector<std::string> data;

            do
            {
                std::getline(file, line);

                if (line.front() == ' ') //additional info
                {
                    data.back() = data.back() + line + "\n";
                }
                else
                {
                    data.push_back(line + "\n");
                }
            }
            while (!line.empty()); //end of package item info

            auto packageInfo = PackageLinuxHelper::parseDpkg(data);

            if (!packageInfo.empty())
            {
                callback(packageInfo);
            }
        }
    }
}
