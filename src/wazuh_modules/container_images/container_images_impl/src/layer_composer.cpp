/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "layer_composer.hpp"
#include "ci_logging_helper.hpp"
#include "layer_reader.hpp"
#include "package_db_parser.hpp"

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

    /// @brief The parser that owns a tracked path, or nullptr when the path is not tracked.
    const containerimages::IPackageDbParser* parserFor(const std::string& path)
    {
        for (const auto& database : containerimages::knownPackageDatabases())
        {
            if (database.path == path)
            {
                return database.parser.get();
            }
        }

        return nullptr;
    }

    /// @brief Name of the unimplemented format a path belongs to, empty when it is none.
    std::string unsupportedFormatFor(const std::string& path)
    {
        for (const auto& database : containerimages::unsupportedPackageDatabases())
        {
            const auto matches {database.isPrefix ? path.rfind(database.path, 0) == 0 : path == database.path};

            if (matches)
            {
                return database.format;
            }
        }

        return {};
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

        snapshot.complete = LayerReader::read(layer, [&snapshot](const LayerEntry & entry, IByteStream & content)
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

            const auto unsupported {unsupportedFormatFor(entry.path)};

            if (!unsupported.empty())
            {
                snapshot.unsupportedFormats[entry.path] = unsupported;
                return true;
            }

            if (!entry.isRegularFile || parserFor(entry.path) == nullptr)
            {
                // Not a package database: the reader skips the content, so an image is
                // read at the cost of its databases only.
                return true;
            }

            if (entry.size > MAX_DATABASE_SIZE)
            {
                logWarn("Package database '" + entry.path + "' is larger than the supported size, skipping it.");
                return true;
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
        }

        // What this layer provides wins over the earlier layers.
        for (const auto& [path, content] : snapshot.databases)
        {
            m_databases[path] = content;
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

    std::vector<ImagePackageRecord> LayerComposer::packages() const
    {
        std::vector<ImagePackageRecord> packages;
        std::set<const IPackageDbParser*> handled;

        // Databases are visited in the preference order of the registry, not in path
        // order, so an image that carries two of them reports the preferred one first.
        // Two registered locations sharing the same parser (the two apk database paths)
        // are alternate locations of the same conceptual database, not two distinct
        // ones: an image that happens to carry a real file at both collides on the
        // packages table's primary key (name + version + architecture + type) and
        // reports the same packages twice. Once a parser has produced its records from
        // its preferred location, its other locations are skipped.
        for (const auto& location : knownPackageDatabases())
        {
            const auto database {m_databases.find(location.path)};

            if (database == m_databases.end() || location.parser == nullptr)
            {
                continue;
            }

            if (!handled.insert(location.parser.get()).second)
            {
                logDebug("Skipping '" + location.path +
                         "': another location for the same package database was already used.");
                continue;
            }

            auto parsed {location.parser->parse(database->second, location.path)};

            logDebug("Parsed " + std::to_string(parsed.size()) + " packages from '" + location.path + "'.");

            packages.insert(packages.end(),
                            std::make_move_iterator(parsed.begin()),
                            std::make_move_iterator(parsed.end()));
        }

        return packages;
    }
} // namespace containerimages
