/*
 * Wazuh data provider.
 * Copyright (C) 2015, Wazuh Inc.
 * July 11, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGES_PYPI_HPP
#define _PACKAGES_PYPI_HPP

#include "fileIO.hpp"
#include "fileSystem.hpp"
#include "stdFileSystemHelper.hpp"
#include "json.hpp"
#include "sharedDefs.h"
#include "stringHelper.h"
#include "utilsWrapperLinux.hpp"
#include <iostream>
#include <set>
#include <unordered_set>

const static std::map<std::string, std::string> FILE_MAPPING_PYPI {{"egg-info", "PKG-INFO"}, {"dist-info", "METADATA"}};

template<typename TFileSystem = RealFileSystem, typename TFileIO = FileIO>
class PYPI final : public TFileSystem, public TFileIO
{
        std::unordered_set<std::string> excludedPaths;

        void parseMetadata(const std::filesystem::path& path, std::function<void(nlohmann::json&)>& callback)
        {
            // Map to match fields
            static const std::map<std::string, std::string> PYPI_FIELDS {{"Name: ", "name"},
                {"Version: ", "version"},
                {"Summary: ", "description"},
                {"Home-page: ", "source"},
                {"Author: ", "vendor"}};

            // Parse the METADATA file
            nlohmann::json packageInfo;

            packageInfo["groups"] = UNKNOWN_VALUE;
            packageInfo["description"] = UNKNOWN_VALUE;
            packageInfo["architecture"] = UNKNOWN_VALUE;
            packageInfo["format"] = "pypi";
            packageInfo["source"] = UNKNOWN_VALUE;
            packageInfo["location"] = path.string();
            packageInfo["priority"] = UNKNOWN_VALUE;
            packageInfo["size"] = 0;
            packageInfo["vendor"] = UNKNOWN_VALUE;
            packageInfo["install_time"] = UNKNOWN_VALUE;
            // The multiarch field won't have a default value

            TFileIO::readLineByLine(path,
                                    [&packageInfo](const std::string & line) -> bool
            {
                const auto it {
                    std::find_if(PYPI_FIELDS.begin(),
                                 PYPI_FIELDS.end(),
                                 [&line](const auto & element)
                    {
                        return Utils::startsWith(line, element.first);
                    })};

                if (PYPI_FIELDS.end() != it)
                {
                    const auto& [key, value] {*it};

                    if (!packageInfo.contains(value))
                    {
                        packageInfo[value] = Utils::trim(line.substr(key.length()), "\r");
                    }
                }
                return true;
            });

            // Check if we have a name and version
            if (packageInfo.contains("name") && packageInfo.contains("version"))
            {
                callback(packageInfo);
            }
        }

        void findCorrectPath(const std::filesystem::path& path, std::function<void(nlohmann::json&)> callback)
        {
            try
            {
                const auto filename = path.filename().string();

                for (const auto& [key, value] : FILE_MAPPING_PYPI)
                {
                    if (filename.find(key) != std::string::npos)
                    {
                        std::filesystem::path correctPath;

                        if (TFileSystem::is_regular_file(path))
                        {
                            correctPath = path;
                        }
                        else if (TFileSystem::is_directory(path))
                        {
                            correctPath = path / value;
                        }

                        if (excludedPaths.find(correctPath.string()) != excludedPaths.end())
                        {
                            return;
                        }

                        parseMetadata(correctPath, callback);
                    }
                }
            }
            catch (const std::exception& e)
            {
                std::cerr << "Error parsing PYPI package: " << path.string() << ", " << e.what() << std::endl;
            }
        }
        void exploreExpandedPaths(const std::deque<std::string>& expandedPaths,
                                  std::function<void(nlohmann::json&)> callback)
        {
            for (const auto& expandedPath : expandedPaths)
            {
                try
                {
                    // Exist and is a directory
                    if (TFileSystem::exists(expandedPath) && TFileSystem::is_directory(expandedPath))
                    {
                        for (const std::filesystem::path& path : TFileSystem::directory_iterator(expandedPath))
                        {
                            findCorrectPath(path, callback);
                        }
                    }
                }
                catch (const std::exception&)
                {
                    // Do nothing, continue with the next path
                }
            }
        }
        void getDpkgPythonPackages(std::unordered_set<std::string>& pythonPackages)
        {
            std::regex listPattern(R"(^python.*\.list$)");
            const auto PYTHON_INFO_FILES = std::array {std::make_pair(std::regex(R"(^.*\.egg-info$)"), "/PKG-INFO"),
                                                       std::make_pair(std::regex(R"(^.*\.dist-info$)"), "/METADATA")};

            try
            {
                for (const auto& entry : std::filesystem::directory_iterator(DPKG_INFO_PATH))
                {
                    if (std::filesystem::is_regular_file(entry) &&
                            std::regex_search(entry.path().filename().string(), listPattern))
                    {
                        std::ifstream file(entry.path());
                        std::string line;

                        while (std::getline(file, line))
                        {
                            std::smatch match;

                            for (const auto& [pattern, extraFile] : PYTHON_INFO_FILES)
                            {
                                if (std::regex_search(line, match, pattern))
                                {
                                    std::string baseInfoPath = match.str(0);

                                    if (std::filesystem::is_regular_file(baseInfoPath))
                                    {
                                        pythonPackages.insert(baseInfoPath);
                                    }
                                    else
                                    {
                                        std::string fullPath = baseInfoPath + extraFile;

                                        if (std::filesystem::exists(fullPath))
                                        {
                                            pythonPackages.insert(fullPath);
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
        void getRpmPythonPackages(std::unordered_set<std::string>& pythonPackages)
        {
            const auto PYTHON_INFO_FILES = std::array {std::make_pair(std::regex(R"(^.*\.egg-info$)"), "/PKG-INFO"),
                                                       std::make_pair(std::regex(R"(^.*\.dist-info$)"), "/METADATA")};

            const auto rawPythonPackagesList {UtilsWrapperLinux::exec(
                                                  "rpm -qa | grep -E 'python.*' | xargs -I {} rpm -ql {} | grep -E '\\.egg-info$|\\.dist-info$'")};

            if (!rawPythonPackagesList.empty())
            {
                const auto rows {Utils::split(rawPythonPackagesList, '\n')};

                for (const auto& row : rows)
                {
                    std::smatch match;

                    for (const auto& [pattern, extraFile] : PYTHON_INFO_FILES)
                    {
                        if (std::regex_search(row, match, pattern))
                        {
                            std::string baseInfoPath = match.str(0);

                            if (std::filesystem::is_regular_file(baseInfoPath))
                            {
                                pythonPackages.insert(baseInfoPath);
                            }
                            else
                            {
                                std::string fullPath = baseInfoPath + extraFile;

                                if (std::filesystem::exists(fullPath))
                                {
                                    pythonPackages.insert(fullPath);
                                }
                            }
                        }
                    }
                }
            }
        }

    public:
        void getPackages(const std::set<std::string>& osRootFolders, std::function<void(nlohmann::json&)> callback, bool excludePaths = false)
        {
            if(excludePaths)
            {
                excludedPaths.clear();

                if (TFileSystem::exists(DPKG_PATH))
                {
                    getDpkgPythonPackages(excludedPaths);
                }

                if (TFileSystem::exists(RPM_PATH))
                {
                    getRpmPythonPackages(excludedPaths);
                }
            }

            for (const auto& osFolder : osRootFolders)
            {
                std::deque<std::string> expandedPaths;

                try
                {
                    // Expand paths
                    Utils::expandAbsolutePath(osFolder, expandedPaths);
                    // Explore expanded paths
                    exploreExpandedPaths(expandedPaths, callback);
                }
                catch (const std::exception&)
                {
                    // Do nothing, continue with the next path
                }
            }
        }
};

#endif // _PACKAGES_PYPI_HPP
