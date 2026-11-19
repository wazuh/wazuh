/*
 * Wazuh SYSINFO
 * Copyright (C) Wazuh Inc.
 * November 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGE_DB_PARSER_HPP
#define _PACKAGE_DB_PARSER_HPP

#include "rpmDbNdbReader.hpp"
#include "rpmDbSqliteReader.hpp"
#include "rpmHeaderBlobParser.hpp"
#include "timeHelper.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

/// @brief Reading of the package databases of a filesystem that is not the running host.
///
/// Container image scanning and container runtime security both need the packages a
/// container filesystem holds, and must report the same ones for the same files. This is
/// the one place that knows how to read them. It works on bytes and in-image paths, never
/// on the host filesystem, so a caller decides how the files are obtained (a composed image
/// layer, `/proc/<pid>/root`) and hands them over as a map from path to content.
///
/// Formats: dpkg (`status`, and the `status.d` directory distroless images use), apk (both
/// database locations), rpm in sqlite and ndb. The rpm Berkeley DB format is not read.
///
/// Nothing here throws for malformed content: an unreadable database costs its own packages,
/// and the other databases are still read. The host package inventory does
/// not use this code.
namespace PackageDb
{
    /// @brief One installed package. A value the database does not carry is empty.
    struct Package
    {
        std::string name;
        std::string version;       ///< dpkg: as written. apk: as written. rpm: `[epoch:]version[-release]`.
        std::string architecture;
        std::string type;          ///< Package format: deb, apk or rpm.
        std::string vendor;
        std::string installed;     ///< ISO 8601 install date, when the database records one.
        std::string category;
        std::string description;
        std::string priority;
        std::string multiarch;
        std::string source;        ///< dpkg: Source. apk: origin. rpm: source package file name.
        std::string packageDbPath; ///< Path of the database the package was read from.
        long long size {0};        ///< Installed size in bytes.
    };

    /// @brief Files of a filesystem that may hold a package database.
    ///
    /// Keyed by the path inside the filesystem, relative and normalized: `var/lib/dpkg/status`,
    /// no leading slash, no `./`. The value is the whole content of the file.
    using Files = std::map<std::string, std::string>;

    /// @brief What happened to one package database.
    struct DatabaseReport
    {
        std::string path;        ///< Database path, or the directory for `status.d`.
        std::size_t packages {0}; ///< Packages read from it.
        bool skipped {false};    ///< Present, but another location of the same database was read instead.
    };

    /// @brief Packages read from the files, and what was done with each database found.
    struct Result
    {
        std::vector<Package> packages;
        std::vector<DatabaseReport> databases;
    };

    constexpr auto FORMAT_DPKG { "deb" };
    constexpr auto FORMAT_APK { "apk" };
    constexpr auto FORMAT_RPM { "rpm" };

    constexpr auto DPKG_STATUS_PATH { "var/lib/dpkg/status" };
    /// Read only when `status` is absent: a distroless image has no `status`, and a
    /// Debian one that has both is described by `status`.
    constexpr auto DPKG_STATUS_D_DIRECTORY { "var/lib/dpkg/status.d" };
    constexpr auto DPKG_CHECKSUM_SUFFIX { ".md5sums" };

    /// @brief The database files, in the order they are preferred.
    ///
    /// Locations of one format hold the same conceptual database, so only the first one
    /// present is read: an image that carries a file at both reports its packages once.
    /// rpm keeps its database under `var` on the Red Hat family and under `usr` on Fedora
    /// and the SUSE family.
    struct Location
    {
        const char* path;
        const char* format;
    };

    static inline const std::vector<Location>& databaseLocations()
    {
        static const std::vector<Location> LOCATIONS
        {
            {DPKG_STATUS_PATH, FORMAT_DPKG},
            {"lib/apk/db/installed", FORMAT_APK},
            {"usr/lib/apk/db/installed", FORMAT_APK},
            {"var/lib/rpm/rpmdb.sqlite", FORMAT_RPM},
            {"usr/lib/sysimage/rpm/rpmdb.sqlite", FORMAT_RPM},
            {"var/lib/rpm/Packages.db", FORMAT_RPM},
            {"usr/lib/sysimage/rpm/Packages.db", FORMAT_RPM},
        };

        return LOCATIONS;
    }

    /// @brief True for a file directly under `status.d` that holds one package.
    static inline bool isStatusDEntry(const std::string& path)
    {
        const std::string directory { std::string { DPKG_STATUS_D_DIRECTORY } + "/" };
        const std::string suffix { DPKG_CHECKSUM_SUFFIX };

        if (path.size() <= directory.size() || path.compare(0, directory.size(), directory) != 0)
        {
            return false;
        }

        const auto name { path.substr(directory.size()) };

        return name.find('/') == std::string::npos &&
               !(name.size() >= suffix.size() && name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0);
    }

    /// @brief True when @p path is a file this parser reads, so a caller keeps its content.
    static inline bool isDatabasePath(const std::string& path)
    {
        const auto& locations { databaseLocations() };

        return std::any_of(locations.begin(), locations.end(), [&path](const Location & location)
        {
            return path == location.path;
        }) || isStatusDEntry(path);
    }

    namespace detail
    {
        /// dpkg reports the installed size in kibibytes, the tables store bytes.
        constexpr long long DPKG_SIZE_UNIT { 1024 };

        /// The largest `long long`, without pulling a header in for it.
        constexpr long long LARGEST_SIZE { static_cast<long long>(~0ULL >> 1) };

        static inline std::string trim(const std::string& value)
        {
            const auto begin { value.find_first_not_of(" \t\r\n") };

            if (begin == std::string::npos)
            {
                return {};
            }

            const auto end { value.find_last_not_of(" \t\r\n") };
            return value.substr(begin, end - begin + 1);
        }

        /// @brief Parse a size field and scale it by @p unit.
        /// @return 0 for anything that is not a number, and for a value that overflows once scaled.
        static inline long long parseSize(const std::string& value, long long unit)
        {
            try
            {
                const auto number { std::stoll(value) };

                if (number > LARGEST_SIZE / unit || number < (-LARGEST_SIZE - 1) / unit)
                {
                    return 0;
                }

                return number * unit;
            }
            catch (const std::exception&)
            {
                return 0;
            }
        }

        /// @brief Split a database into stanzas, which are separated by a blank line.
        ///
        /// Lines are handed on with their leading whitespace intact, because dpkg marks the
        /// continuation of a field with it.
        static inline std::vector<std::string> splitStanzas(const std::string& content)
        {
            std::vector<std::string> stanzas;
            std::string current;
            std::istringstream stream { content };
            std::string line;

            while (std::getline(stream, line))
            {
                if (!line.empty() && line.back() == '\r')
                {
                    line.pop_back();
                }

                if (line.empty())
                {
                    if (!current.empty())
                    {
                        stanzas.push_back(std::move(current));
                        current.clear();
                    }

                    continue;
                }

                current += line;
                current += '\n';
            }

            if (!current.empty())
            {
                stanzas.push_back(std::move(current));
            }

            return stanzas;
        }

        /// @brief Read one dpkg stanza into its fields.
        ///
        /// A field continues on the following lines when they start with whitespace, which is
        /// how a multi-line Description is written.
        static inline std::map<std::string, std::string> dpkgFields(const std::string& stanza)
        {
            std::map<std::string, std::string> fields;
            std::istringstream stream { stanza };
            std::string line;
            std::string currentKey;

            while (std::getline(stream, line))
            {
                if (line.empty())
                {
                    continue;
                }

                if (line.front() == ' ' || line.front() == '\t')
                {
                    if (!currentKey.empty())
                    {
                        fields[currentKey] += "\n" + trim(line);
                    }

                    continue;
                }

                const auto colon { line.find(':') };

                if (colon == std::string::npos)
                {
                    continue;
                }

                currentKey = trim(line.substr(0, colon));
                fields[currentKey] = trim(line.substr(colon + 1));
            }

            return fields;
        }

        static inline std::string field(const std::map<std::string, std::string>& fields, const std::string& key)
        {
            const auto entry { fields.find(key) };

            if (entry == fields.end())
            {
                return {};
            }

            return entry->second;
        }

        /// @brief First line of a value, which is the short form of a dpkg description.
        static inline std::string firstLine(const std::string& value)
        {
            const auto newline { value.find('\n') };
            return newline == std::string::npos ? value : value.substr(0, newline);
        }

        /// @brief Build the package a dpkg stanza describes.
        /// @return False when the stanza is not an installed package.
        static inline bool dpkgPackage(const std::map<std::string, std::string>& fields,
                                       const std::string& dbPath,
                                       Package& package)
        {
            const auto name { field(fields, "Package") };

            // The dpkg status is "SELECTION_STATE FLAG PACKAGE_STATE". Only "ok installed"
            // means the package is really there: a removed package keeps its stanza with a
            // different state.
            if (name.empty() || field(fields, "Status").find("ok installed") == std::string::npos)
            {
                return false;
            }

            package = {};
            package.name = name;
            package.version = field(fields, "Version");
            package.architecture = field(fields, "Architecture");
            package.type = FORMAT_DPKG;
            package.vendor = field(fields, "Maintainer");
            package.category = field(fields, "Section");
            package.description = firstLine(field(fields, "Description"));
            package.priority = field(fields, "Priority");
            package.multiarch = field(fields, "Multi-Arch");
            package.source = field(fields, "Source");
            package.size = parseSize(field(fields, "Installed-Size"), DPKG_SIZE_UNIT);
            package.packageDbPath = dbPath;

            return true;
        }

        /// @brief The version as the distribution expresses it: `[epoch:]version-release`.
        ///
        /// The epoch is part of how rpm orders versions, so it is kept whenever the package
        /// carries one, including an explicit zero. A package with no epoch tag at all is
        /// reported without the prefix, which is how the package manager prints it.
        static inline std::string rpmVersion(const RpmHeaderBlob::Package& header)
        {
            std::string version;

            if (!header.epoch.empty())
            {
                version = header.epoch + ":";
            }

            version += header.version;

            if (!header.release.empty())
            {
                version += "-" + header.release;
            }

            return version;
        }

        /// @brief The install date as ISO 8601, empty when the database records none.
        static inline std::string rpmInstallDate(const std::string& timestamp)
        {
            try
            {
                return Utils::rawTimestampToISO8601(static_cast<uint32_t>(std::stoll(timestamp)));
            }
            catch (const std::exception&)
            {
                return {};
            }
        }

        /// @brief Turn one rpm header blob into a package, appended to @p packages when valid.
        static inline void collectRpmBlob(const uint8_t* blob,
                                          std::size_t size,
                                          const std::string& dbPath,
                                          std::vector<Package>& packages)
        {
            const auto header { RpmHeaderBlob::parse(blob, size) };

            // The signing keys rpm keeps in the database are not installed software.
            if (!header.valid || header.name.empty() || header.name == "gpg-pubkey")
            {
                return;
            }

            Package package;
            package.name = header.name;
            package.version = rpmVersion(header);
            package.architecture = header.architecture;
            package.type = FORMAT_RPM;
            package.vendor = header.vendor;
            package.installed = rpmInstallDate(header.installTime);
            package.category = header.group;
            package.description = header.description;
            package.source = header.source;
            package.size = parseSize(header.size, 1);
            package.packageDbPath = dbPath;

            packages.push_back(std::move(package));
        }

    } // namespace detail

    /// @brief dpkg `status`: RFC822-like stanzas separated by a blank line.
    /// @param content Full content of the file.
    /// @param dbPath Stored on every package.
    static inline std::vector<Package> parseDpkg(const std::string& content, const std::string& dbPath)
    {
        std::vector<Package> packages;

        for (const auto& stanza : detail::splitStanzas(content))
        {
            Package package;

            if (detail::dpkgPackage(detail::dpkgFields(stanza), dbPath, package))
            {
                packages.push_back(std::move(package));
            }
        }

        return packages;
    }

    /// @brief One file of the dpkg `status.d` directory: a single package, blank lines included.
    ///
    /// dpkg itself never ran for these packages, so the stanza usually has no `Status` line.
    /// Every file in the directory is an installed package by construction, so a missing one
    /// is read as installed. A file that states another status is not installed.
    static inline std::vector<Package> parseDpkgStatusD(const std::string& content, const std::string& dbPath)
    {
        auto fields { detail::dpkgFields(content) };
        fields.emplace("Status", "install ok installed");

        std::vector<Package> packages;
        Package package;

        if (detail::dpkgPackage(fields, dbPath, package))
        {
            packages.push_back(std::move(package));
        }

        return packages;
    }

    /// @brief apk `installed`: stanzas of single-letter keys.
    ///
    /// P name, V version, A architecture, m maintainer, T description, o origin and I
    /// installed size in bytes. The other keys are not inventory fields.
    static inline std::vector<Package> parseApk(const std::string& content, const std::string& dbPath)
    {
        std::vector<Package> packages;

        for (const auto& stanza : detail::splitStanzas(content))
        {
            std::map<char, std::string> fields;
            std::istringstream stream { stanza };
            std::string line;

            while (std::getline(stream, line))
            {
                if (line.size() < 2 || line[1] != ':')
                {
                    continue;
                }

                fields[line[0]] = detail::trim(line.substr(2));
            }

            const auto value = [&fields](const char key)
            {
                const auto entry { fields.find(key) };

                if (entry == fields.end())
                {
                    return std::string {};
                }

                return entry->second;
            };

            if (value('P').empty())
            {
                continue;
            }

            Package package;
            package.name = value('P');
            package.version = value('V');
            package.architecture = value('A');
            package.type = FORMAT_APK;
            package.vendor = value('m');
            package.description = value('T');
            package.source = value('o');
            package.size = detail::parseSize(value('I'), 1);
            package.packageDbPath = dbPath;

            packages.push_back(std::move(package));
        }

        return packages;
    }

    /// @brief rpm sqlite (`rpmdb.sqlite`) or ndb (`Packages.db`), read from memory.
    ///
    /// The two hold the same package headers and differ in how they store them, so one
    /// function reads both and picks the format from the content, not from the path. A
    /// database rpm left in write-ahead log mode is read as of its last checkpoint.
    static inline std::vector<Package> parseRpm(const std::string& content, const std::string& dbPath)
    {
        std::vector<Package> packages;

        const auto collect
        {
            [&packages, &dbPath](const uint8_t* blob, std::size_t size)
            {
                detail::collectRpmBlob(blob, size, dbPath, packages);
            }
        };

        if (!RpmDbSqlite::readFromMemory(content.data(), content.size(), collect))
        {
            RpmDbNdb::readFromMemory(content.data(), content.size(), collect);
        }

        return packages;
    }

    /// @brief Read the package databases among @p files.
    ///
    /// For each format the first database present, in the order of databaseLocations(), is
    /// read, and the others are reported as skipped. dpkg `status.d` is read only when
    /// `status` is absent, so a Debian image and a distroless one are each described by the
    /// file that describes them. Different formats are read independently, so an image that
    /// carries two of them reports both.
    static inline Result read(const Files& files)
    {
        Result result;

        const auto add = [&result](const std::string & path, std::vector<Package>&& packages)
        {
            DatabaseReport report;
            report.path = path;
            report.packages = packages.size();

            result.databases.push_back(std::move(report));
            result.packages.insert(result.packages.end(),
                                   std::make_move_iterator(packages.begin()),
                                   std::make_move_iterator(packages.end()));
        };

        const auto skip = [&result](const std::string & path)
        {
            DatabaseReport report;
            report.path = path;
            report.skipped = true;
            result.databases.push_back(std::move(report));
        };

        // dpkg.
        std::vector<std::string> statusD;

        for (const auto& [path, content] : files)
        {
            if (isStatusDEntry(path))
            {
                statusD.push_back(path);
            }
        }

        if (const auto status { files.find(DPKG_STATUS_PATH) }; status != files.end())
        {
            add(status->first, parseDpkg(status->second, status->first));

            if (!statusD.empty())
            {
                skip(DPKG_STATUS_D_DIRECTORY);
            }
        }
        else if (!statusD.empty())
        {
            std::vector<Package> packages;

            for (const auto& path : statusD)
            {
                auto entry { parseDpkgStatusD(files.at(path), path) };
                packages.insert(packages.end(), std::make_move_iterator(entry.begin()), std::make_move_iterator(entry.end()));
            }

            add(DPKG_STATUS_D_DIRECTORY, std::move(packages));
        }

        // apk and rpm.
        std::vector<std::string> formatsRead;

        for (const auto& location : databaseLocations())
        {
            const std::string format { location.format };

            if (format == FORMAT_DPKG)
            {
                continue;
            }

            const auto database { files.find(location.path) };

            if (database == files.end())
            {
                continue;
            }

            if (std::find(formatsRead.begin(), formatsRead.end(), format) != formatsRead.end())
            {
                skip(database->first);
                continue;
            }

            formatsRead.push_back(format);

            if (format == FORMAT_APK)
            {
                add(database->first, parseApk(database->second, database->first));
                continue;
            }

            add(database->first, parseRpm(database->second, database->first));
        }

        return result;
    }
} // namespace PackageDb

#endif // _PACKAGE_DB_PARSER_HPP
