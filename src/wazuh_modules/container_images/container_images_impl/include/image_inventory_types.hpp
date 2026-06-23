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

namespace containerimages
{
    /// @brief Where an image reference was found: the source type and its location.
    struct ImageReferenceSource
    {
        std::string sourceType; ///< Source type, e.g. "local-oci".
        std::string location;   ///< Path, repository tag or registry reference.
    };

    /// @brief A discovered image reference.
    ///
    /// The image reference is the owner of the inventory: in the reference-based
    /// model packages belong to the reference they were found under. Each discovered
    /// reference produces one record. The config digest is kept as metadata only, it
    /// is not an identity key. Package and layer data are intentionally left out at
    /// this stage.
    struct ImageReferenceRecord
    {
        ImageReferenceSource source; ///< The reference: source type + location (the owner).
        std::string tag;             ///< Name the reference is known by.
        std::string configDigest;    ///< Config blob digest, kept as metadata only.
        std::string manifestDigest;  ///< Manifest digest, kept as metadata only.
        std::string os;
        std::string architecture;
        std::string variant;
        std::string osVersion;
    };
} // namespace containerimages

#endif // _IMAGE_INVENTORY_TYPES_HPP
