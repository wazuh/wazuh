/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "layer_composer.hpp"
#include "ci_logging_helper.hpp"
#include "layer_reader.hpp"
#include "os_release_parser.hpp"
#include "packageDbParser.hpp"

#include <algorithm>
#include <iterator>
#include <string>
#include <utility>

namespace
{
    // Ceiling for one package database. A dpkg status file on a large image is a few
    // megabytes; past this the file is not inventoried rather than read into memory,
    // because the size comes from the image being scanned.
    constexpr std::uint64_t MAX_DATABASE_SIZE {64 * 1024 * 1024};

    // Ceiling for an os-release file, which is a few hundred bytes. The size comes from the
    // image being scanned, so a file past this is not read.
    constexpr std::uint64_t MAX_OS_RELEASE_SIZE {64 * 1024};

    /// A package database the module recognizes but does not parse.
    ///
    /// Recognizing them is what lets the module tell "this image uses a format we do not
    /// support yet" apart from "this image has no packages".
    struct UnsupportedPackageDb
    {
        std::string path;   ///< In-image path or directory prefix that identifies the format.
        bool isPrefix;      ///< True when the format is identified by a directory rather than a file.
        std::string format; ///< Format name, for the log line.
    };

    void logDebug(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, message);
    }

    void logWarn(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_WARNING, message);
    }

    /// @brief True if @p path is @p directory itself or anything under it.
    bool isUnderDirectory(const std::string& path, const std::string& directory)
    {
        if (directory.empty())
        {
            return true;
        }

        return path == directory || (path.size() > directory.size() && path.rfind(directory + "/", 0) == 0);
    }

    /// @brief True if @p path is one of the locations of the `os-release` file.
    bool isOsReleasePath(const std::string& path)
    {
        const auto& paths {containerimages::osReleasePaths()};
        return std::find(paths.begin(), paths.end(), path) != paths.end();
    }

    /// @brief Remove from @p files every path that is @p directory or lies under it.
    void eraseUnder(std::map<std::string, std::string>& files, const std::string& directory)
    {
        for (auto file = files.begin(); file != files.end();)
        {
            file = isUnderDirectory(file->first, directory) ? files.erase(file) : std::next(file);
        }
    }

    const std::vector<UnsupportedPackageDb>& unsupportedPackageDatabases()
    {
        static const std::vector<UnsupportedPackageDb> DATABASES
        {
            // The Berkeley DB format rpm used before 4.16. Named by file, not by directory,
            // so the sqlite and ndb databases in the same directory stay parsable.
            {"var/lib/rpm/Packages", false, "rpm"},
            {"usr/lib/sysimage/rpm/Packages", false, "rpm"},
            {"var/lib/pacman/local/", true, "pacman"},
            {"var/db/pkg/", true, "portage"},
            {"var/db/xbps/", true, "xbps"},
            {"usr/share/clear/bundles/", true, "swupd"},
        };

        return DATABASES;
    }

    /// @brief Name of the unimplemented format a path belongs to, empty when it is none.
    std::string unsupportedFormatFor(const std::string& path)
    {
        for (const auto& database : unsupportedPackageDatabases())
        {
            const auto matches {database.isPrefix ? path.rfind(database.path, 0) == 0 : path == database.path};

            if (matches)
            {
                return database.format;
            }
        }

        return {};
    }

    /// @brief The package record the module stores for a package the shared parser read.
    containerimages::ImagePackageRecord toImagePackage(PackageDb::Package&& package)
    {
        containerimages::ImagePackageRecord record;
        record.name = std::move(package.name);
        record.version = std::move(package.version);
        record.architecture = std::move(package.architecture);
        record.type = std::move(package.type);
        record.vendor = std::move(package.vendor);
        record.installed = std::move(package.installed);
        record.category = std::move(package.category);
        record.description = std::move(package.description);
        record.priority = std::move(package.priority);
        record.multiarch = std::move(package.multiarch);
        record.source = std::move(package.source);
        record.packageDbPath = std::move(package.packageDbPath);
        record.size = package.size;

        return record;
    }

    /// @brief Read the content of a tar entry into a string.
    std::string readContent(containerimages::IByteStream& content, std::uint64_t size)
    {
        std::string buffer;
        buffer.resize(static_cast<std::size_t>(size));

        const auto got {containerimages::readExact(content, buffer.data(), buffer.size())};
        buffer.resize(got);

        return buffer;
    }
} // namespace

namespace containerimages
{
    LayerSnapshot readLayerSnapshot(IByteStream& layer)
    {
        LayerSnapshot snapshot;
        std::uint64_t statusDBytes {0};

        snapshot.complete = LayerReader::read(layer, [&snapshot, &statusDBytes](const LayerEntry & entry, IByteStream & content)
        {
            if (entry.isOpaqueDirectory)
            {
                snapshot.opaqueDirectories.insert(entry.whiteoutTarget);
                return true;
            }

            if (entry.isWhiteout)
            {
                snapshot.whiteouts.insert(entry.whiteoutTarget);
                return true;
            }

            if (isOsReleasePath(entry.path))
            {
                snapshot.osReleasesReplaced.insert(entry.path);

                // Only a regular file has content to read. A link is not followed: the file it
                // names is read at its own path when the layer carries it.
                if (!entry.isRegularFile)
                {
                    return true;
                }

                if (entry.size > MAX_OS_RELEASE_SIZE)
                {
                    logWarn("File '" + entry.path + "' is larger than the supported size, skipping it.");
                    return true;
                }

                snapshot.osReleases[entry.path] = readContent(content, entry.size);
                return true;
            }

            // A path the shared parser reads is never reported as unsupported. The rpm
            // formats it reads sit in the same directory as the one it may not, so the
            // parser's paths are consulted first.
            if (!entry.isRegularFile || !PackageDb::isDatabasePath(entry.path))
            {
                const auto unsupported {unsupportedFormatFor(entry.path)};

                if (!unsupported.empty())
                {
                    snapshot.unsupportedFormats[entry.path] = unsupported;
                }

                // Not a package database this module parses: the reader skips the
                // content, so an image is read at the cost of its databases only.
                return true;
            }

            if (entry.size > MAX_DATABASE_SIZE)
            {
                logWarn("Package database '" + entry.path + "' is larger than the supported size, skipping it.");
                return true;
            }

            // The dpkg status.d directory holds one small file per package and any number of
            // them, so the layer's share of them is bounded as one database would be.
            if (PackageDb::isStatusDEntry(entry.path))
            {
                statusDBytes += entry.size;

                if (statusDBytes > MAX_DATABASE_SIZE)
                {
                    logWarn("The dpkg status.d directory is larger than the supported size, skipping '" + entry.path + "'.");
                    return true;
                }
            }

            snapshot.databases[entry.path] = readContent(content, entry.size);
            return true;
        });

        return snapshot;
    }

    void LayerComposer::apply(const LayerSnapshot& snapshot)
    {
        // An opaque directory hides everything the earlier layers put under it, including
        // files this layer does not mention at all. An unsupported-format sighting is
        // tracked by path exactly like a database, so it is retracted here the same way:
        // an image whose rpm directory is removed in a later layer should not keep
        // warning about rpm once nothing rpm-shaped is left in the composed inventory.
        for (const auto& directory : snapshot.opaqueDirectories)
        {
            for (auto database = m_databases.begin(); database != m_databases.end();)
            {
                database = isUnderDirectory(database->first, directory) ? m_databases.erase(database) : std::next(database);
            }

            for (auto format = m_unsupportedFormats.begin(); format != m_unsupportedFormats.end();)
            {
                format = isUnderDirectory(format->first, directory) ? m_unsupportedFormats.erase(format) : std::next(format);
            }

            eraseUnder(m_osReleases, directory);
        }

        // A deletion marker removes the path it names and, when that path is a directory,
        // everything under it.
        for (const auto& whiteout : snapshot.whiteouts)
        {
            for (auto database = m_databases.begin(); database != m_databases.end();)
            {
                database = isUnderDirectory(database->first, whiteout) ? m_databases.erase(database) : std::next(database);
            }

            for (auto format = m_unsupportedFormats.begin(); format != m_unsupportedFormats.end();)
            {
                format = isUnderDirectory(format->first, whiteout) ? m_unsupportedFormats.erase(format) : std::next(format);
            }

            eraseUnder(m_osReleases, whiteout);
        }

        // An os-release this layer replaces by a link, or by a file it cannot read, leaves
        // nothing of the earlier one: keeping it would report the distribution the layer
        // replaced.
        for (const auto& path : snapshot.osReleasesReplaced)
        {
            m_osReleases.erase(path);
        }

        // What this layer provides wins over the earlier layers.
        for (const auto& [path, content] : snapshot.databases)
        {
            m_databases[path] = content;
        }

        for (const auto& [path, content] : snapshot.osReleases)
        {
            m_osReleases[path] = content;
        }

        for (const auto& [path, format] : snapshot.unsupportedFormats)
        {
            m_unsupportedFormats[path] = format;
        }
    }

    const std::map<std::string, std::string>& LayerComposer::databases() const
    {
        return m_databases;
    }

    std::set<std::string> LayerComposer::unsupportedFormats() const
    {
        std::set<std::string> formats;

        for (const auto& [path, format] : m_unsupportedFormats)
        {
            formats.insert(format);
        }

        return formats;
    }

    ImageOperatingSystem LayerComposer::operatingSystem() const
    {
        for (const auto& path : osReleasePaths())
        {
            const auto file {m_osReleases.find(path)};

            if (file == m_osReleases.end())
            {
                continue;
            }

            auto os {parseOsRelease(file->second)};

            // A file that states nothing recognizable does not stop the fallback location
            // from being tried.
            if (!os.empty())
            {
                return os;
            }
        }

        return {};
    }

    std::vector<ImagePackageRecord> LayerComposer::packages() const
    {
        auto read {PackageDb::read(m_databases)};

        for (const auto& database : read.databases)
        {
            if (database.skipped)
            {
                logDebug("Skipping '" + database.path +
                         "': another location for the same package database was already used.");
            }
            else
            {
                logDebug("Parsed " + std::to_string(database.packages) + " packages from '" + database.path + "'.");
            }
        }

        std::vector<ImagePackageRecord> packages;
        packages.reserve(read.packages.size());

        for (auto& package : read.packages)
        {
            packages.push_back(toImagePackage(std::move(package)));
        }

        return packages;
    }
} // namespace containerimages
