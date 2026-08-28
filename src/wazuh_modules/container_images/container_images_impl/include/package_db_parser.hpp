/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGE_DB_PARSER_HPP
#define _PACKAGE_DB_PARSER_HPP

#include "image_inventory_types.hpp"

#include <memory>
#include <string>
#include <vector>

namespace containerimages
{
    /// @brief Parses one package database format.
    ///
    /// A new package format is added by implementing this interface and registering the
    /// paths it owns, without touching the layer reader or the parsers that already
    /// exist. The parser receives the composed content of the database file, so it never
    /// deals with layers, compression or the filesystem.
    class IPackageDbParser
    {
        public:
            virtual ~IPackageDbParser() = default;

            /// @brief Parse a package database.
            /// @param content Full content of the database file.
            /// @param dbPath In-image path of the database, stored on every record.
            /// @return One record per installed package. Unparsable entries are skipped.
            virtual std::vector<ImagePackageRecord> parse(const std::string& content, const std::string& dbPath) const = 0;

            /// @brief Package format name, stored in the `type` field of every record.
            virtual std::string format() const = 0;
    };

    /// @brief Debian and Ubuntu: `var/lib/dpkg/status`, RFC822-like stanzas.
    class DpkgParser final : public IPackageDbParser
    {
        public:
            std::vector<ImagePackageRecord> parse(const std::string& content, const std::string& dbPath) const override;
            std::string format() const override;
    };

    /// @brief Alpine and its derivatives: `lib/apk/db/installed`, single-letter keys.
    class ApkParser final : public IPackageDbParser
    {
        public:
            std::vector<ImagePackageRecord> parse(const std::string& content, const std::string& dbPath) const override;
            std::string format() const override;
    };

    /// @brief A package database this module knows how to parse, and where it lives.
    struct PackageDbLocation
    {
        std::string path;                            ///< In-image path, normalized, no leading slash.
        std::shared_ptr<const IPackageDbParser> parser; ///< Parser that owns the path.
    };

    /// @brief A package database that is recognized but not parsed yet.
    ///
    /// Recognizing them is what lets the module tell "this image uses a format we do not
    /// support yet" apart from "this image has no packages".
    struct UnsupportedPackageDb
    {
        std::string path;   ///< In-image path or directory prefix that identifies the format.
        bool isPrefix;      ///< True when the format is identified by a directory rather than a file.
        std::string format; ///< Format name, for the log line.
    };

    /// @brief The package databases parsed by this module, in the order they are preferred.
    const std::vector<PackageDbLocation>& knownPackageDatabases();

    /// @brief The package databases recognized but not parsed yet.
    const std::vector<UnsupportedPackageDb>& unsupportedPackageDatabases();
} // namespace containerimages

#endif // _PACKAGE_DB_PARSER_HPP
