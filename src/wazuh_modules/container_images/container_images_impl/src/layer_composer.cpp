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
#include <atomic>
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
        static const std::vector<UnsupportedPackageDb> DATABASES = []
        {
            std::vector<UnsupportedPackageDb> databases
            {
                {"var/lib/pacman/local/", true, "pacman"},
                {"var/db/pkg/", true, "portage"},
                {"var/db/xbps/", true, "xbps"},
                {"usr/share/clear/bundles/", true, "swupd"},
            };

            // The Berkeley DB format rpm used before 4.16 needs libdb, which is only read
            // on Linux. Named by file, not by directory, so the sqlite and ndb databases in
            // the same directory stay parsable.
            if (!PackageDb::BERKELEY_DB_SUPPORTED)
            {
                const std::string format {"rpm Berkeley DB (not supported on this platform)"};
                databases.push_back({"var/lib/rpm/Packages", false, format});
                databases.push_back({"usr/lib/sysimage/rpm/Packages", false, format});
            }

            return databases;
        }();

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
            // them, so the layer's share of them is bounded as one database would be. Past the
            // bound the directory is dropped as a whole: what was read before it is a part of the
            // list, and a part is not the list.
            if (PackageDb::isStatusDEntry(entry.path))
            {
                if (snapshot.oversizedDatabases.count(PackageDb::DPKG_STATUS_D_DIRECTORY) > 0)
                {
                    return true;
                }

                statusDBytes += entry.size;

                if (statusDBytes > MAX_DATABASE_SIZE)
                {
                    eraseUnder(snapshot.databases, PackageDb::DPKG_STATUS_D_DIRECTORY);
                    snapshot.oversizedDatabases.insert(PackageDb::DPKG_STATUS_D_DIRECTORY);
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
            eraseOversizedUnder(directory);
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
            eraseOversizedUnder(whiteout);
        }

        // A database this layer dropped for its size leaves nothing of the earlier layers' either.
        for (const auto& path : snapshot.oversizedDatabases)
        {
            eraseUnder(m_databases, path);
            m_oversizedDatabases.insert(path);
        }

        // An os-release this layer replaces by a link, or by a file it cannot read, leaves
        // nothing of the earlier one: keeping it would report the distribution the layer
        // replaced.
        for (const auto& path : snapshot.osReleasesReplaced)
        {
            m_osReleases.erase(path);
        }

        // What this layer provides wins over the earlier layers. A directory dropped for its size stays
        // dropped, whatever a later layer adds to it, until a layer deletes it.
        for (const auto& [path, content] : snapshot.databases)
        {
            const auto dropped {std::any_of(m_oversizedDatabases.begin(), m_oversizedDatabases.end(), [&path](const std::string & directory)
            {
                return isUnderDirectory(path, directory);
            })};

            if (!dropped)
            {
                m_databases[path] = content;
            }
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

    void LayerComposer::eraseOversizedUnder(const std::string& directory)
    {
        for (auto path = m_oversizedDatabases.begin(); path != m_oversizedDatabases.end();)
        {
            path = isUnderDirectory(*path, directory) ? m_oversizedDatabases.erase(path) : std::next(path);
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

    std::vector<ImagePackageRecord> LayerComposer::packages(const std::string& image,
                                                            const std::atomic<bool>* stop,
                                                            bool* transientFailure,
                                                            const ReadAttempt* attempt) const
    {
        PackageDb::BerkeleyDbOptions options;

        if (attempt != nullptr && attempt->controls.options != nullptr)
        {
            options = *attempt->controls.options;
        }

        if (stop != nullptr)
        {
            options.stop = [stop]
            {
                return stop->load();
            };
        }

        auto read {PackageDb::read(m_databases, options)};
        const auto where {image.empty() ? std::string {} : "Image '" + image + "': "};
        const bool stopping = stop != nullptr && stop->load();

        for (const auto& path : m_oversizedDatabases)
        {
            logWarn(where + "package database '" + path + "' could not be read: it is larger than the supported size.");
        }

        // A read that failed for a reason of the machine is counted against the image, and the count is of
        // consecutive reads: one that went well starts it again. A read cut short by a shutdown counts for
        // nothing, in either direction.
        bool gaveUp {false};

        if (attempt != nullptr && attempt->controls.failures != nullptr && !stopping)
        {
            auto& entries {attempt->controls.failures->entries};
            const auto key {ReadFailures::imageKey(attempt->source, attempt->reference, attempt->configDigest)};
            const bool failed {std::any_of(read.databases.begin(), read.databases.end(), [](const PackageDb::DatabaseReport & database)
            {
                return database.transient;
            })};

            if (!failed)
            {
                entries.erase(key);
            }
            else
            {
                gaveUp = ++entries[key].count >= MAX_TRANSIENT_READS;

                if (gaveUp)
                {
                    entries.erase(key);
                }
            }
        }

        for (const auto& database : read.databases)
        {
            if (database.skipped)
            {
                logDebug("Skipping '" + database.path +
                         "': another location for the same package database was already used.");
            }
            else if (!database.error.empty() && database.transient && gaveUp)
            {
                // Stored as a database that cannot be read: the next read would fail the same way.
                logWarn(where + "package database '" + database.path + "' could not be read: " + database.error +
                        ", " + std::to_string(MAX_TRANSIENT_READS) + " times in a row. It will not be read again until the image changes.");
            }
            else if (!database.error.empty() && database.transient)
            {
                // The database is not at fault, so the image is not stored with what was read of it. A read cut
                // short by a shutdown is not a fault of anything, and is not worth a warning.
                if (transientFailure != nullptr)
                {
                    *transientFailure = true;
                }

                (stopping ? logDebug : logWarn)(where + "package database '" + database.path + "' could not be read: " +
                                                database.error + ". It will be read again on the next scan.");
            }
            else if (!database.error.empty())
            {
                logWarn(where + "package database '" + database.path + "' could not be read: " + database.error + ".");
            }
            else
            {
                // A limit that cannot be set is a fact about this process, the same for every database
                // and every image, so it is said once.
                static std::atomic<bool> limitWarned {false};

                if (!database.warning.empty() && !limitWarned.exchange(true))
                {
                    logWarn("Package databases of images are read without the memory limit: " + database.warning + ".");
                }

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
