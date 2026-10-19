/*
 * Wazuh data provider.
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGES_NPM_HPP
#define _PACKAGES_NPM_HPP

#include <ifilesystem_wrapper.hpp>
#include <filesystem_wrapper.hpp>

#include <filesystem_utils.hpp>
#include "json.hpp"
#include "packageMetadataFile.hpp"
#include "sharedDefs.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <memory>

template<typename TJsonReader = PackageMetadataJsonReader>
class NPM final
    : public TJsonReader
{
    private:
        std::unique_ptr<IFileSystemWrapper> m_fileSystemWrapper;

        // A folder that cannot be inspected is treated as a link, so it is still reported, unsized
        bool isLink(const std::filesystem::path& folderPath) const
        {
            try
            {
                return m_fileSystemWrapper->is_symlink(folderPath);
            }
            catch (const std::exception&)
            {
                return true;
            }
        }

        void parsePackage(const std::filesystem::path& folderPath, std::function<void(nlohmann::json&)>& callback)
        {
            // Map to match fields
            static const std::map<std::string, std::string> NPM_FIELDS
            {
                {"name", "name"},
                {"version", "version_"},
                {"description", "description"},
                {"homepage", "source"},
            };
            const auto path = folderPath / "package.json";

            try
            {
                // Only read regular files; the reader also enforces the size limit on the opened file
                if (m_fileSystemWrapper->exists(path) && !m_fileSystemWrapper->is_regular_file(path))
                {
                    std::cerr << "Skipping NPM package metadata: " << path.string()
                              << ", not a regular file" << std::endl;
                }
                else if (m_fileSystemWrapper->is_regular_file(path))
                {
                    // Read json from filesystem path.
                    const auto packageJson = TJsonReader::readJson(path);
                    nlohmann::json packageInfo;

                    packageInfo["category"] = UNKNOWN_VALUE;
                    packageInfo["description"] = UNKNOWN_VALUE;
                    packageInfo["architecture"] = UNKNOWN_VALUE;
                    packageInfo["type"] = "npm";
                    packageInfo["source"] = UNKNOWN_VALUE;
                    packageInfo["path"] = path.string();
                    packageInfo["priority"] = UNKNOWN_VALUE;
                    packageInfo["vendor"] = UNKNOWN_VALUE;
                    packageInfo["installed"] = UNKNOWN_VALUE;
                    // The multiarch field won't have a default value

                    // Iterate over fields
                    for (const auto& [key, value] : NPM_FIELDS)
                    {
                        if (packageJson.contains(key) && packageJson.at(key).is_string())
                        {
                            packageInfo[value] = packageJson.at(key);
                        }
                    }

                    if (packageInfo.contains("name") && packageInfo.contains("version_"))
                    {
                        // The package folder includes its bundled dependencies. A linked package (npm
                        // link) points at a whole checkout, so its size stays unknown. An unknown size
                        // leaves the key out, so the size a previous scan stored is kept.
                        if (!isLink(folderPath))
                        {
                            const auto size {m_fileSystemWrapper->directory_size(
                                                 folderPath, PACKAGE_SIZE_MAX_ENTRIES, PACKAGE_SIZE_DEADLINE)};

                            if (size.has_value() && *size > 0)
                            {
                                packageInfo["size"] = static_cast<int64_t>(*size);
                            }
                        }

                        callback(packageInfo);
                    }
                }
            }
            catch (const std::exception& e)
            {
                std::cerr << "Error reading NPM package: " << path.string() << ", " << e.what() << std::endl;
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
                    const auto nodeModulesFolder {std::filesystem::path(expandedPath) / "node_modules"};

                    if (m_fileSystemWrapper->exists(nodeModulesFolder))
                    {
                        for (const auto& packageFolder : m_fileSystemWrapper->list_directory(nodeModulesFolder))
                        {
                            if (m_fileSystemWrapper->is_directory(packageFolder))
                            {
                                parsePackage(packageFolder, callback);
                            }
                        }
                    }
                }
                catch (const std::exception& e)
                {
                    // Ignore exception, continue with next folder
                }
            }
        }

    public:
        NPM(std::unique_ptr<IFileSystemWrapper> fileSystemWrapper = nullptr)
            : m_fileSystemWrapper(fileSystemWrapper ? std::move(fileSystemWrapper) : std::make_unique<file_system::FileSystemWrapper>())
        {
        }
        ~NPM() = default;

        void getPackages(const std::set<std::string>& osRootFolders, std::function<void(nlohmann::json&)> callback)
        {

            // Iterate over node_modules folders
            for (const auto& osRootFolder : osRootFolders)
            {
                try
                {
                    std::deque<std::string> expandedPaths;

                    // Expand paths
                    file_system::FileSystemUtils().expand_absolute_path(osRootFolder, expandedPaths);
                    // Explore expanded paths
                    exploreExpandedPaths(expandedPaths, callback);
                }
                catch (const std::exception& e)
                {
                    // Ignore exception, continue with next folder
                }
            }
        }
};

#endif // _PACKAGES_NPM_HPP
