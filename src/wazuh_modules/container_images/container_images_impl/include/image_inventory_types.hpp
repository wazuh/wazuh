/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
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

    /// @brief The operating system an image is built on, as its `os-release` file states it.
    ///
    /// Every field is empty for an image that ships no `os-release` file (a scratch or a
    /// static distroless image): that is "no operating system", not an error.
    struct ImageOperatingSystem
    {
        std::string name;       ///< NAME, e.g. "Debian GNU/Linux".
        std::string version;    ///< VERSION_ID, e.g. "12".
        std::string id;         ///< ID, e.g. "debian".
        std::string family;     ///< First word of ID_LIKE, e.g. "debian" for Ubuntu. Empty when absent.
        std::string codename;   ///< VERSION_CODENAME, e.g. "bookworm". Empty when absent.
        std::string prettyName; ///< PRETTY_NAME, e.g. "Debian GNU/Linux 12 (bookworm)".

        /// @brief True when no `os-release` information was found.
        bool empty() const
        {
            return name.empty() && version.empty() && id.empty() && family.empty() && codename.empty() &&
                   prettyName.empty();
        }
    };

    /// @brief A discovered image reference and the packages found under it.
    ///
    /// The image reference is the owner of the inventory: in the reference-based
    /// model packages belong to the reference they were found under. Each discovered
    /// reference produces one record. The config digest names the image in the shared
    /// container block but is not the key of the record, which stays the reference.
    struct ImageReferenceRecord
    {
        ImageReferenceSource source;    ///< The reference: source type + location (the owner).
        /// Full normalised name, `registry/repository` with neither tag nor digest (`nginx` is
        /// `docker.io/library/nginx`). Empty when the source gives the image no name.
        std::string name;
        std::vector<std::string> tags;  ///< Every tag of that name the image is known by.
        /// Config blob digest: the image's identity, what a container engine reports as the image
        /// id. Not the key of the record, which stays the reference.
        std::string configDigest;
        std::string manifestDigest;  ///< Manifest digest, kept as metadata only.
        /// Every digest the image is known by: the indexes it was resolved through (outermost
        /// first), then the manifest, then the configuration. A running container reports one of
        /// them, whichever its engine uses, so it is the list a container is joined to the image on.
        std::vector<std::string> digests;
        std::string os;
        std::string architecture;
        std::string variant;
        std::string osVersion;
        ImageOperatingSystem operatingSystem; ///< Distribution read from the image's `os-release`.
        std::vector<ImagePackageRecord> packages; ///< Packages found under this reference.
    };
} // namespace containerimages

#endif // _IMAGE_INVENTORY_TYPES_HPP
