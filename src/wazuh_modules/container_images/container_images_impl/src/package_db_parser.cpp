/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "package_db_parser.hpp"

#include <exception>
#include <map>
#include <sstream>
#include <string>
#include <utility>

namespace
{
    /// dpkg reports the installed size in kibibytes, the tables store bytes.
    constexpr long long DPKG_SIZE_UNIT {1024};

    std::string trim(const std::string& value)
    {
        const auto begin {value.find_first_not_of(" \t\r\n")};

        if (begin == std::string::npos)
        {
            return {};
        }

        const auto end {value.find_last_not_of(" \t\r\n")};
        return value.substr(begin, end - begin + 1);
    }

    /// @brief Parse a size field, returning 0 for anything that is not a number.
    long long parseSize(const std::string& value, long long unit)
    {
        try
        {
            return std::stoll(value) * unit;
        }
        catch (const std::exception&)
        {
            return 0;
        }
    }

    /// @brief Split a database into stanzas, which are separated by a blank line.
    ///
    /// Both supported formats are stanza-based, so the split is shared. Lines are handed
    /// on with their leading whitespace intact, because dpkg marks the continuation of a
    /// field with it.
    std::vector<std::string> splitStanzas(const std::string& content)
    {
        std::vector<std::string> stanzas;
        std::string current;
        std::istringstream stream {content};
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
    /// how a multi-line Description is written. Continuations are appended so the first
    /// line of the field stays usable on its own.
    std::map<std::string, std::string> dpkgFields(const std::string& stanza)
    {
        std::map<std::string, std::string> fields;
        std::istringstream stream {stanza};
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

            const auto colon {line.find(':')};

            if (colon == std::string::npos)
            {
                continue;
            }

            currentKey = trim(line.substr(0, colon));
            fields[currentKey] = trim(line.substr(colon + 1));
        }

        return fields;
    }

    /// @brief Read a field, or an empty string when it is not present.
    std::string field(const std::map<std::string, std::string>& fields, const std::string& key)
    {
        const auto entry {fields.find(key)};
        return entry == fields.end() ? std::string {} : entry->second;
    }

    /// @brief First line of a value, which is the short form of a dpkg description.
    std::string firstLine(const std::string& value)
    {
        const auto newline {value.find('\n')};
        return newline == std::string::npos ? value : value.substr(0, newline);
    }
} // namespace

namespace containerimages
{
    std::string DpkgParser::format() const
    {
        return "deb";
    }

    std::vector<ImagePackageRecord> DpkgParser::parse(const std::string& content, const std::string& dbPath) const
    {
        std::vector<ImagePackageRecord> packages;

        for (const auto& stanza : splitStanzas(content))
        {
            const auto fields {dpkgFields(stanza)};
            const auto name {field(fields, "Package")};

            // The dpkg status is "SELECTION_STATE FLAG PACKAGE_STATE". Only "ok installed"
            // means the package is really on the image: a removed package keeps its stanza
            // with a different state. Same rule the host package inventory applies.
            if (name.empty() || field(fields, "Status").find("ok installed") == std::string::npos)
            {
                continue;
            }

            ImagePackageRecord package;
            package.name = name;
            package.version = field(fields, "Version");
            package.architecture = field(fields, "Architecture");
            package.type = format();
            package.vendor = field(fields, "Maintainer");
            package.category = field(fields, "Section");
            package.description = firstLine(field(fields, "Description"));
            package.priority = field(fields, "Priority");
            package.multiarch = field(fields, "Multi-Arch");
            package.source = field(fields, "Source");
            package.size = parseSize(field(fields, "Installed-Size"), DPKG_SIZE_UNIT);
            package.packageDbPath = dbPath;

            packages.push_back(std::move(package));
        }

        return packages;
    }

    std::string ApkParser::format() const
    {
        return "apk";
    }

    std::vector<ImagePackageRecord> ApkParser::parse(const std::string& content, const std::string& dbPath) const
    {
        std::vector<ImagePackageRecord> packages;

        for (const auto& stanza : splitStanzas(content))
        {
            // The apk database uses one single-letter key per line: P name, V version,
            // A architecture, m maintainer, T description, o origin, I installed size in
            // bytes.
            std::map<char, std::string> fields;
            std::istringstream stream {stanza};
            std::string line;

            while (std::getline(stream, line))
            {
                if (line.size() < 2 || line[1] != ':')
                {
                    continue;
                }

                fields[line[0]] = trim(line.substr(2));
            }

            const auto name {fields.find('P')};

            if (name == fields.end() || name->second.empty())
            {
                continue;
            }

            const auto value = [&fields](const char key)
            {
                const auto entry {fields.find(key)};
                return entry == fields.end() ? std::string {} : entry->second;
            };

            ImagePackageRecord package;
            package.name = name->second;
            package.version = value('V');
            package.architecture = value('A');
            package.type = format();
            package.vendor = value('m');
            package.description = value('T');
            package.source = value('o');
            package.size = parseSize(value('I'), 1);
            package.packageDbPath = dbPath;

            packages.push_back(std::move(package));
        }

        return packages;
    }

    const std::vector<PackageDbLocation>& knownPackageDatabases()
    {
        // Built once and shared: the parsers hold no state, so one instance serves every
        // reference in every scan.
        static const auto DPKG_PARSER {std::make_shared<const DpkgParser>()};
        static const auto APK_PARSER {std::make_shared<const ApkParser>()};

        static const std::vector<PackageDbLocation> DATABASES
        {
            {"var/lib/dpkg/status", DPKG_PARSER},
            {"lib/apk/db/installed", APK_PARSER},
            // Wolfi and Chainguard images keep the apk database under /usr.
            {"usr/lib/apk/db/installed", APK_PARSER},
        };

        return DATABASES;
    }

    const std::vector<UnsupportedPackageDb>& unsupportedPackageDatabases()
    {
        static const std::vector<UnsupportedPackageDb> DATABASES
        {
            // RPM has its own follow-up issue: it needs the header parsing that lives in
            // shared agent code, and the database is Berkeley DB, sqlite or ndb.
            {"var/lib/rpm/", true, "rpm"},
            {"usr/lib/sysimage/rpm/", true, "rpm"},
            {"var/lib/pacman/local/", true, "pacman"},
            {"var/db/pkg/", true, "portage"},
            {"var/db/xbps/", true, "xbps"},
            {"usr/share/clear/bundles/", true, "swupd"},
        };

        return DATABASES;
    }
} // namespace containerimages
