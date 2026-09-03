/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OCI_METADATA_HPP
#define _OCI_METADATA_HPP

#include "image_inventory_types.hpp"

#include <string>

#include <json.hpp>

namespace containerimages::oci
{
    /// @brief Media types an image index, or a manifest, is served as.
    ///
    /// The OCI names and the older Docker names describe the same two documents, and a
    /// registry answers with whichever one the image was pushed as, so both are asked for
    /// and both are recognized.
    constexpr auto MEDIA_TYPE_OCI_INDEX {"application/vnd.oci.image.index.v1+json"};
    constexpr auto MEDIA_TYPE_OCI_MANIFEST {"application/vnd.oci.image.manifest.v1+json"};
    constexpr auto MEDIA_TYPE_DOCKER_LIST {"application/vnd.docker.distribution.manifest.list.v2+json"};
    constexpr auto MEDIA_TYPE_DOCKER_MANIFEST {"application/vnd.docker.distribution.manifest.v2+json"};

    /// @brief Parse image metadata, yielding an empty object rather than throwing.
    ///
    /// Every caller here reads attacker-influenced metadata, so a parse failure is an
    /// ordinary outcome and not an exception: an empty object makes every field lookup
    /// below miss, which is what a malformed document should look like to a reader.
    nlohmann::json parseJson(const std::string& content);

    /// @brief Read a string field, yielding an empty string when it is absent or is not
    /// a string.
    ///
    /// Neither the presence of a key nor its type may be assumed of a document this
    /// module did not write: nlohmann::json::value() throws on both counts.
    std::string stringField(const nlohmann::json& node, const std::string& key);

    /// @brief Read an array field, yielding an empty array when it is absent or is not
    /// an array.
    nlohmann::json arrayField(const nlohmann::json& node, const std::string& key);

    /// @brief True if a digest algorithm matches the OCI character set `[a-z0-9]+`.
    bool isSafeDigestAlgorithm(const std::string& algorithm);

    /// @brief True if a digest encoded part matches the OCI character set `[a-zA-Z0-9=_-]+`.
    bool isSafeDigestEncoded(const std::string& encoded);

    /// @brief True when @p digest is a well-formed `algorithm:encoded` OCI digest.
    ///
    /// Both components are whitelisted rather than filtered for known-bad characters. A
    /// digest reaches a filesystem path in the archive reader and a request path in the
    /// registry reader, so neither may carry a separator, a traversal segment, or a
    /// Windows drive-relative prefix.
    bool isSafeDigest(const std::string& digest);

    /// @brief Fill platform metadata from a parsed configuration blob.
    void applyConfigMetadata(const nlohmann::json& config, ImageReferenceRecord& record);

    /// @brief True when an index entry's platform marks it as an attestation or
    /// provenance manifest rather than a real image: buildx and containerd both write
    /// "unknown"/"unknown" as the platform of those, since they carry no image content.
    bool isAttestationManifest(const nlohmann::json& entry);
} // namespace containerimages::oci

#endif // _OCI_METADATA_HPP
