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
#include <iostream>
#include <unordered_set>

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

std::unordered_set<std::string> getDpkgPythonPackages()
{
    std::unordered_set<std::string> pythonFiles;
    std::regex list_pattern(R"(^python.*\.list$)");
    const auto PYTHON_INFO_FILES = std::array {std::make_pair(std::regex(R"(^.*\.egg-info$)"), "/PKG-INFO"),
                                               std::make_pair(std::regex(R"(^.*\.dist-info$)"), "/METADATA")};

    try
    {
        for (const auto& entry : std::filesystem::directory_iterator(DPKG_INFO_PATH))
        {
            if (std::filesystem::is_regular_file(entry) &&
                std::regex_search(entry.path().filename().string(), list_pattern))
            {
                std::ifstream file(entry.path());
                std::string line;
                while (std::getline(file, line))
                {
                    std::smatch match;
                    for (const auto& [pattern, extra_file] : PYTHON_INFO_FILES)
                    {
                        if (std::regex_search(line, match, pattern))
                        {
                            std::string base_info_path = match.str(0);

                            if (std::filesystem::is_regular_file(base_info_path))
                            {
                                pythonFiles.insert(base_info_path);
                            }
                            else
                            {
                                std::string full_path = base_info_path + extra_file;
                                if (std::filesystem::exists(full_path))
                                {
                                    pythonFiles.insert(full_path);
                                }
                            }
                        }
                    }
                }
                file.close();
            }
        }
    }
    catch (const std::filesystem::filesystem_error& ex)
    {
        std::cerr << "Filesystem error: " << ex.what() << std::endl;
    }
    return pythonFiles;
}