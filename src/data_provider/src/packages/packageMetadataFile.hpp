/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * October 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGE_METADATA_FILE_HPP
#define _PACKAGE_METADATA_FILE_HPP

#include "json.hpp"
#include "sharedDefs.h"
#include <filesystem>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>

#ifdef _WIN32
#include <fstream>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/**
 * @brief Reads package metadata files (PyPI METADATA/PKG-INFO, npm package.json).
 * @details Only non-empty regular files of at most PACKAGE_METADATA_MAX_FILE_SIZE bytes are read. Symbolic
 * links are followed, since package managers such as Homebrew install metadata files as links. On POSIX
 * systems the file is opened with O_NONBLOCK, so opening a named pipe or a device returns at once, and the
 * type and size checks are done on the opened descriptor, so they apply to the file that is actually read.
 * A file rejected after it was opened is reported on standard error.
 */
class PackageMetadataFile final
{
    public:
        /**
         * @brief Read the whole content of a package metadata file.
         * @param path Path to the metadata file.
         * @param content Output content, only valid when true is returned.
         * @return True if the file was accepted and read, false otherwise.
         */
        static bool read(const std::filesystem::path& path, std::string& content)
        {
            content.clear();
#ifdef _WIN32
            // Text mode, as the previous readers did, so CRLF line endings are converted
            std::ifstream file(path);

            if (!file.is_open())
            {
                std::cerr << "Skipping package metadata file: " << path.string() << ", could not be opened" << std::endl;
                return false;
            }

            constexpr std::size_t CHUNK_SIZE {64 * 1024};
            std::string chunk(CHUNK_SIZE, '\0');

            while (content.size() <= PACKAGE_METADATA_MAX_FILE_SIZE &&
                    file.read(chunk.data(), static_cast<std::streamsize>(chunk.size())).gcount() > 0)
            {
                content.append(chunk.data(), static_cast<std::size_t>(file.gcount()));
            }

#else
            const int fd {::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC)};

            if (fd < 0)
            {
                std::cerr << "Skipping package metadata file: " << path.string() << ", could not be opened: "
                          << std::strerror(errno) << std::endl;
                return false;
            }

            struct stat fileStat {};

            if (::fstat(fd, &fileStat) != 0 || !S_ISREG(fileStat.st_mode) || fileStat.st_size <= 0 ||
                    static_cast<std::uintmax_t>(fileStat.st_size) > PACKAGE_METADATA_MAX_FILE_SIZE)
            {
                ::close(fd);
                std::cerr << "Skipping package metadata file: " << path.string()
                          << ", not a non-empty regular file within the size limit" << std::endl;
                return false;
            }

            // One extra byte detects a file that grew after fstat
            const auto expectedSize {static_cast<std::size_t>(fileStat.st_size)};
            content.resize(expectedSize + 1);
            std::size_t total {0};
            bool readError {false};

            while (total < content.size())
            {
                const auto bytes {::read(fd, content.data() + total, content.size() - total)};

                if (bytes > 0)
                {
                    total += static_cast<std::size_t>(bytes);
                }
                else if (bytes < 0 && errno == EINTR)
                {
                    continue;
                }
                else
                {
                    readError = bytes < 0;
                    break;
                }
            }

            ::close(fd);
            content.resize(total);

            if (readError || total != expectedSize)
            {
                content.clear();
                std::cerr << "Skipping package metadata file: " << path.string()
                          << ", read failed or the file changed while reading" << std::endl;
                return false;
            }

#endif

            if (content.empty() || content.size() > PACKAGE_METADATA_MAX_FILE_SIZE)
            {
                content.clear();
                std::cerr << "Skipping package metadata file: " << path.string()
                          << ", empty or larger than the size limit" << std::endl;
                return false;
            }

            return true;
        }
};

/**
 * @brief Line reader for package metadata files, see PackageMetadataFile.
 */
class PackageMetadataFileIO
{
    public:
        static void readLineByLine(const std::filesystem::path& filePath,
                                   const std::function<bool(const std::string&)>& callback)
        {
            std::string content;

            if (!PackageMetadataFile::read(filePath, content))
            {
                return;
            }

            std::istringstream stream {content};
            std::string line;

            while (std::getline(stream, line))
            {
                if (!callback(line))
                {
                    break;
                }
            }
        }
};

/**
 * @brief JSON reader for package metadata files, see PackageMetadataFile.
 */
class PackageMetadataJsonReader
{
    public:
        static nlohmann::json readJson(const std::filesystem::path& filePath)
        {
            std::string content;

            if (!PackageMetadataFile::read(filePath, content))
            {
                return nlohmann::json();
            }

            // Stream extraction, as the previous reader did, accepts trailing data after the JSON value
            std::istringstream stream {content};
            nlohmann::json json;
            stream >> json;
            return json;
        }
};

#endif // _PACKAGE_METADATA_FILE_HPP
