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

void getApkInfo(const std::string& fileName, std::function<void(nlohmann::json&)> callback)
{
    std::ifstream apkDb(fileName);
    const size_t valuePos {2};
    std::string line;
    std::vector<std::string> data;

    if (apkDb.is_open())
    {
        while (getline(apkDb, line))
        {
            if (!line.empty())
            {
                switch (line.front())
                {
                    case 'P':
                        data.push_back(line.substr(valuePos));
                        break;

                    case 'V':
                        data.push_back(line.substr(valuePos));
                        break;

                    case 'A':
                        data.push_back(line.substr(valuePos));
                        break;

                    case 'I':
                        data.push_back(line.substr(valuePos));
                        break;

                    case 'T':
                        data.push_back(line.substr(valuePos));
                        break;
                }
            }
            else
            {
                nlohmann::json packageInfo;
                packageInfo["name"] = data.at(0);
                packageInfo["version"] = data.at(1);
                packageInfo["architecture"] = data.at(2);
                packageInfo["size"] = data.at(3);
                packageInfo["description"] = data.at(4);
                packageInfo["format"] = "apk";
                packageInfo["vendor"] = "Alpine Linux";
                data.clear();

                if (!packageInfo.empty())
                {
                    callback(packageInfo);
                }
            }
        }
    }
}
