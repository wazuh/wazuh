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
#include <filesystem_utils.hpp>
#include "packageMetadataFile.hpp"
#include "json.hpp"
#include "sharedDefs.h"
#include "stringHelper.h"
#include "utilsWrapperLinux.hpp"
#include <algorithm>
#include <iostream>
#include <limits>
#include <optional>
#include <set>
#include <unordered_set>
#include <vector>
#include <filesystem>

const static std::map<std::string, std::string> FILE_MAPPING_PYPI {{"egg-info", "PKG-INFO"}, {"dist-info", "METADATA"}};

/**
 * @brief File IO utils that read lines through PackageMetadataFileIO, so only non-empty regular files within the
 * size limit are read.
 */
class PackageMetadataFileIOUtils final : public file_io::FileIOUtils
{
    public:
        void readLineByLine(const std::filesystem::path& filePath,
                            const std::function<bool(const std::string&)>& callback) const override
        {
            PackageMetadataFileIO::readLineByLine(filePath, callback);
        }
};

class PYPI final
{
        std::unique_ptr<IFileIOUtils> m_fileIOUtils;
        std::unique_ptr<IFileSystemWrapper> m_fileSystemWrapper;
        std::unordered_set<std::string> m_pathsToExclude;

        /**
         * @brief Extracts the path field of a RECORD line, which is a CSV row: path,hash,size.
         */
        static std::string recordPath(const std::string& line)
        {
            if (line.empty() || line.front() != '"')
            {
                return line.substr(0, line.find(','));
            }

            std::string path;

            for (size_t i = 1; i < line.size(); ++i)
            {
                if (line[i] == '"')
                {
                    if (i + 1 < line.size() && line[i + 1] == '"')
                    {
                        path += '"';
                        ++i;
                    }
                    else
                    {
                        break;
                    }
                }
                else
                {
                    path += line[i];
                }
            }

            return path;
        }

        /**
         * @brief Whether a dist-info belongs to an editable install (pip install -e), whose RECORD only
         * lists the stub that points at the source tree.
         */
        bool isEditable(const std::filesystem::path& infoDir) const
        {
            const auto directUrl {infoDir / "direct_url.json"};

            if (!m_fileSystemWrapper->is_regular_file(directUrl))
            {
                return false;
            }

            std::string content;
            m_fileIOUtils->readLineByLine(directUrl,
                                          [&content](const std::string & line) -> bool
            {
                content += line;
                return true;
            });

            // Not brace-initialized: with nlohmann that wraps the value in an array
            const auto json = nlohmann::json::parse(content, nullptr, false);

            if (json.is_discarded() || !json.is_object())
            {
                return false;
            }

            const auto dirInfo {json.find("dir_info")};

            if (dirInfo == json.end() || !dirInfo->is_object())
            {
                return false;
            }

            const auto editable {dirInfo->find("editable")};
            return editable != dirInfo->end() && editable->is_boolean() && editable->get<bool>();
        }

        /**
         * @brief Whether a path lies inside a directory, compared component by component.
         */
        static bool isWithin(const std::filesystem::path& path, const std::filesystem::path& directory)
        {
            auto entry {path.begin()};

            for (const auto& component : directory)
            {
                if (entry == path.end() || *entry != component)
                {
                    return false;
                }

                ++entry;
            }

            return true;
        }

        /**
         * @brief Whether a path lies in the bytecode cache Apple's Python keeps outside site-packages:
         * /Users/<user>/Library/Caches/com.apple.python, or root's under /var/root or /private/var/root.
         */
        static bool isAppleBytecodeCache(const std::filesystem::path& path)
        {
            static const std::vector<std::string> CACHE {"Library", "Caches", "com.apple.python"};
            std::vector<std::string> components;

            for (const auto& component : path)
            {
                components.push_back(component.string());
            }

            const auto cacheAt = [&components](const size_t index)
            {
                return components.size() > index + CACHE.size() &&
                       std::equal(CACHE.begin(), CACHE.end(), components.begin() + static_cast<std::ptrdiff_t>(index));
            };

            if (components.size() < 2 || components[0] != "/")
            {
                return false;
            }

            if (components[1] == "Users")
            {
                return cacheAt(3);
            }

            if (components[1] == "var")
            {
                return components.size() > 2 && components[2] == "root" && cacheAt(3);
            }

            return components[1] == "private" && components.size() > 3 && components[2] == "var" &&
                   components[3] == "root" && cacheAt(4);
        }

        /**
         * @brief The installation prefix a listed file may live in: up to levels directories above base
         * (scripts in <prefix>/bin), never the filesystem root itself.
         */
        static std::filesystem::path installPrefix(std::filesystem::path base, const size_t levels)
        {
            for (size_t i = 0; i < levels && base.parent_path().has_relative_path(); ++i)
            {
                base = base.parent_path();
            }

            return base;
        }

        /**
         * @brief Measures a distribution by sizing on disk each file its metadata directory lists:
         * RECORD for dist-info, installed-files.txt for egg-info. RECORD carries no size for compiled
         * files and may list files that are gone, so its size column is not used.
         * @param infoDir The dist-info or egg-info directory.
         * @param isDistInfo Whether infoDir is a dist-info directory.
         * @return The summed size, or no value when there is no list, nothing listed exists, the
         * install is editable, the sum overflows, or the entry cap or the deadline is reached.
         */
        std::optional<int64_t> installedSize(const std::filesystem::path& infoDir, const bool isDistInfo) const
        {
            const auto listPath {infoDir / (isDistInfo ? "RECORD" : "installed-files.txt")};

            if (!m_fileSystemWrapper->is_regular_file(listPath) || (isDistInfo && isEditable(infoDir)))
            {
                return std::nullopt;
            }

            // RECORD paths are relative to site-packages, installed-files.txt paths to the egg-info
            // directory. The list is writable by whoever owns the installation, so a listed path is
            // only sized when it stays inside the installation prefix (scripts in <prefix>/bin) or in
            // Apple's bytecode cache. Paths with their own root (absolute, another drive, a network
            // share) are never touched. Symbolic links and repeated entries are skipped, as
            // directory_size() does, so no file is counted twice.
            const auto base {isDistInfo ? infoDir.parent_path() : infoDir};
            const auto prefix {installPrefix(base, isDistInfo ? 3 : 4)};
            std::unordered_set<std::string> seen;
            const auto start {std::chrono::steady_clock::now()};
            std::uintmax_t total {0};
            std::uintmax_t entries {0};
            bool bounded {true};

            m_fileIOUtils->readLineByLine(listPath,
                                          [&](const std::string & line) -> bool
            {
                if (++entries > PACKAGE_SIZE_MAX_ENTRIES || std::chrono::steady_clock::now() - start > PACKAGE_SIZE_DEADLINE)
                {
                    bounded = false;
                    return false;
                }

                const std::filesystem::path listed {Utils::trim(isDistInfo ? recordPath(line) : line, "\r")};

                if (listed.empty() || listed.has_root_name() || listed.has_root_directory())
                {
                    return true;
                }

                const auto file {(base / listed).lexically_normal()};

                if (!isWithin(file, prefix) && !isAppleBytecodeCache(file))
                {
                    return true;
                }

                if (!seen.insert(file.string()).second)
                {
                    return true;
                }

                try
                {
                    if (m_fileSystemWrapper->is_symlink(file))
                    {
                        return true;
                    }
                }
                catch (const std::exception&)
                {
                    // An entry that cannot be inspected is skipped, as a missing one is
                    return true;
                }

                const auto size {m_fileSystemWrapper->file_size(file)};

                if (size > static_cast<std::uintmax_t>(std::numeric_limits<int64_t>::max()) - total)
                {
                    bounded = false;
                    return false;
                }

                total += size;
                return true;
            });

            if (!bounded || total == 0)
            {
                return std::nullopt;
            }

            return static_cast<int64_t>(total);
        }

        void parseMetadata(const std::filesystem::path& path,
                           const std::filesystem::path& infoDir,
                           const bool isDistInfo,
                           std::function<void(nlohmann::json&)>& callback)
        {
            // Map to match fields
            static const std::map<std::string, std::string> PYPI_FIELDS {{"Name: ", "name"},
                {"Version: ", "version_"},
                {"Summary: ", "description"},
                {"Home-page: ", "source"},
                {"Author: ", "vendor"}};

            // Parse the METADATA file
            nlohmann::json packageInfo;

            packageInfo["category"] = UNKNOWN_VALUE;
            packageInfo["description"] = UNKNOWN_VALUE;
            packageInfo["architecture"] = UNKNOWN_VALUE;
            packageInfo["type"] = "pypi";
            packageInfo["source"] = UNKNOWN_VALUE;
            packageInfo["path"] = path.string();
            packageInfo["priority"] = UNKNOWN_VALUE;
            packageInfo["vendor"] = UNKNOWN_VALUE;
            packageInfo["installed"] = UNKNOWN_VALUE;
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

                    if (!packageInfo.contains(value) || packageInfo[value] == UNKNOWN_VALUE)
                    {
                        packageInfo[value] = Utils::trim(line.substr(key.length()), "\r");
                    }
                }
                return true;
            });

            // Check if we have a name and version
            if (packageInfo.contains("name") && packageInfo.contains("version_"))
            {
                // An unknown size leaves the key out, so the size a previous scan stored is kept
                const auto size {infoDir.empty() ? std::nullopt : installedSize(infoDir, isDistInfo)};

                if (size.has_value())
                {
                    packageInfo["size"] = *size;
                }

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
                        // Only a metadata directory lists the installed files; a lone egg-info file does not
                        std::filesystem::path infoDir;

                        if (m_fileSystemWrapper->is_regular_file(path))
                        {
                            correctPath = path;
                        }
                        else if (m_fileSystemWrapper->is_directory(path))
                        {
                            correctPath = path / value;
                            infoDir = path;
                        }

                        // Only read regular files; the reader also enforces the size limit on the opened file
                        if (!m_fileSystemWrapper->is_regular_file(correctPath))
                        {
                            std::cerr << "Skipping PYPI package metadata: " << (correctPath.empty() ? path : correctPath).string()
                                      << ", not a regular file" << std::endl;
                            continue;
                        }

                        if (m_pathsToExclude.find(correctPath.string()) != m_pathsToExclude.end())
                        {
                            return;
                        }

                        parseMetadata(correctPath, infoDir, key == "dist-info", callback);
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
#ifdef __APPLE__

                    // Skip symlinked Python versions (Versions/Current is typically a symlink)
                    // to avoid reporting duplicate packages on macOS
                    if (expandedPath.find("/Versions/Current/") != std::string::npos)
                    {
                        continue;
                    }

#endif

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
            : m_fileIOUtils(fileIOUtils ? std::move(fileIOUtils) : std::make_unique<PackageMetadataFileIOUtils>())
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
                    file_system::FileSystemUtils().expand_absolute_path(osFolder, expandedPaths);
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
