/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _IMAGE_INVENTORY_TYPES_HPP
#define _IMAGE_INVENTORY_TYPES_HPP

#include <string>
#include <vector>

namespace containerimages
{
    /// @brief Where an image reference was found: the source type and its location.
    struct ImageReferenceSource
    {
        std::string sourceType; ///< Source type, e.g. "local-oci".
        std::string location;   ///< Path, repository tag or registry reference.
    };

    /// @brief A package found inside a container image.
    ///
    /// In the reference-based model a package belongs to the reference it was found
    /// under. The primary-key fields are name + version + architecture + type, scoped
    /// by the owning reference (added when the row is persisted). All other fields are
    /// attributes. Field names mirror the host package inventory so the same indexer
    /// mapping can be reused.
    struct ImagePackageRecord
    {
        std::string name;          ///< PK. Package name.
        std::string version;       ///< PK. Package version (stored as version_).
        std::string architecture;  ///< PK. Package architecture.
        std::string type;          ///< PK. Package format: deb, rpm, apk.
        std::string vendor;
        std::string installed;     ///< Installation date, when the package database records one.
        std::string path;          ///< Install path inside the image, when known.
        std::string category;
        std::string description;
        std::string priority;
        std::string multiarch;
        std::string source;
        std::string packageDbPath; ///< Package database file inside the image.
        long long size {0};        ///< Installed size in bytes.
    };

    /// @brief A discovered image reference and the packages found under it.
    ///
    /// The image reference is the owner of the inventory: in the reference-based
    /// model packages belong to the reference they were found under. Each discovered
    /// reference produces one record. The config digest is kept as metadata only, it
    /// is not an identity key.
    struct ImageReferenceRecord
    {
        ImageReferenceSource source;    ///< The reference: source type + location (the owner).
        std::string tag;                ///< Name the reference is known by.
        std::vector<std::string> tags;  ///< Every tag the image is known by, when the source lists more than one.
        std::string configDigest;    ///< Config blob digest, kept as metadata only.
        std::string manifestDigest;  ///< Manifest digest, kept as metadata only.
        std::string os;
        std::string architecture;
        std::string variant;
        std::string osVersion;
        std::vector<ImagePackageRecord> packages; ///< Packages found under this reference.
    };
} // namespace containerimages

#endif // _IMAGE_INVENTORY_TYPES_HPP
