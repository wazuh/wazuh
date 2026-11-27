/*
 * Wazuh SYSINFO
 * Copyright (C) Wazuh Inc.
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

#include <filesystem_wrapper.hpp>
#include <filesystem>
#include <sys/stat.h>

void getDpkgInfo(const std::string& fileName, std::function<void(nlohmann::json&)> callback)
{
    std::fstream file{fileName, std::ios_base::in};

    if (file.is_open())
    {
        const auto infoDirectory = std::filesystem::path(fileName).parent_path() / "info";

        while (file.good())
        {
            std::string line;
            std::vector<std::string> data;

            do
            {
                std::getline(file, line);

                if (!line.empty() && line.front() == ' ') //additional info
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
                auto listName = packageInfo.at("name").get<std::string>();
                const auto& architecture = packageInfo.at("architecture").get_ref<const std::string&>();
                const bool architectureQualified = packageInfo.at("multiarch") == "same";

                if (!listName.empty() && listName.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789+.-") == std::string::npos &&
                        (!architectureQualified || (!architecture.empty() &&
                                                    architecture.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-") == std::string::npos)))
                {
                    if (architectureQualified)
                    {
                        listName += ':' + architecture;
                    }

                    // The list's mtime approximates the latest install or update of this package.
                    struct stat metadata {};
                    const auto listPath = infoDirectory / (listName + ".list");

                    if (::lstat(listPath.c_str(), &metadata) == 0 && S_ISREG(metadata.st_mode) && metadata.st_mtime > 0)
                    {
                        if (auto installed = Utils::unixTimestampToISO8601(metadata.st_mtime); !installed.empty())
                        {
                            packageInfo["installed"] = std::move(installed);
                        }
                    }
                }

                callback(packageInfo);
            }
        }
    }
}

void getDpkgPythonPackages(std::unordered_set<std::string>& pythonPackages)
{
    std::regex listPattern(R"(^python.*\.list$)");
    const auto PYTHON_INFO_FILES = std::array {std::make_pair(std::regex(R"(^.*\.egg-info$)"), "/PKG-INFO"),
                                               std::make_pair(std::regex(R"(^.*\.dist-info$)"), "/METADATA")};
    const file_system::FileSystemWrapper fileSystemWrapper;

    try
    {
        for (const auto& entry : fileSystemWrapper.list_directory(DPKG_INFO_PATH))
        {
            if (fileSystemWrapper.is_regular_file(entry) &&
                    std::regex_search(entry.filename().string(), listPattern))
            {
                std::ifstream file(entry);
                std::string line;

                while (std::getline(file, line))
                {
                    std::smatch match;

                    for (const auto& [pattern, extraFile] : PYTHON_INFO_FILES)
                    {
                        if (std::regex_search(line, match, pattern))
                        {
                            std::string baseInfoPath = match.str(0);

                            if (fileSystemWrapper.is_regular_file(baseInfoPath))
                            {
                                pythonPackages.insert(std::move(baseInfoPath));
                            }
                            else
                            {
                                std::string fullPath = baseInfoPath + extraFile;

                                if (fileSystemWrapper.exists(fullPath))
                                {
                                    pythonPackages.insert(std::move(fullPath));
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
}
