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

#include <ifilesystem_wrapper.hpp>
#include <filesystem_wrapper.hpp>

#include <file_io_utils.hpp>
#include <ifile_io_utils.hpp>
#include "stdFileSystemHelper.hpp"
#include "json.hpp"
#include "sharedDefs.h"
#include "stringHelper.h"
#include "utilsWrapperLinux.hpp"
#include <iostream>
#include <set>
#include <unordered_set>

const static std::map<std::string, std::string> FILE_MAPPING_PYPI {{"egg-info", "PKG-INFO"}, {"dist-info", "METADATA"}};

class PYPI final
{
        std::unique_ptr<IFileIOUtils> m_fileIOUtils;
        std::unique_ptr<IFileSystemWrapper> m_fileSystemWrapper;
        std::unordered_set<std::string> m_pathsToExclude;

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

            m_fileIOUtils->readLineByLine(path,
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

                        if (m_fileSystemWrapper->is_regular_file(path))
                        {
                            correctPath = path;
                        }
                        else if (m_fileSystemWrapper->is_directory(path))
                        {
                            correctPath = path / value;
                        }

                        if (m_pathsToExclude.find(correctPath.string()) != m_pathsToExclude.end())
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
                    if (m_fileSystemWrapper->exists(expandedPath) && m_fileSystemWrapper->is_directory(expandedPath))
                    {
                        for (const std::filesystem::path& path : m_fileSystemWrapper->list_directory(expandedPath))
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

    public:
        PYPI(std::unique_ptr<IFileIOUtils> fileIOUtils = nullptr,
             std::unique_ptr<IFileSystemWrapper> fileSystemWrapper = nullptr)
            : m_fileIOUtils(fileIOUtils ? std::move(fileIOUtils) : std::make_unique<file_io::FileIOUtils>())
            , m_fileSystemWrapper(fileSystemWrapper ? std::move(fileSystemWrapper)
                                  : std::make_unique<file_system::FileSystemWrapper>())
        {
        }
        ~PYPI() = default;

        void getPackages(const std::set<std::string>& osRootFolders,
                         std::function<void(nlohmann::json&)> callback,
                         const std::unordered_set<std::string>& excludePaths = {})
        {
            m_pathsToExclude = excludePaths;

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
