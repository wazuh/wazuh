/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PLATFORM_SELECTION_HPP
#define _PLATFORM_SELECTION_HPP

#include <string>

#include <json.hpp>

namespace containerimages
{
    /// @brief The platform an image has to match to be worth inventorying.
    ///
    /// The archive reader reads the platform out of an image and records it. Selecting
    /// among several variants is different work: it needs to know what the agent itself
    /// is, which nothing in the module established before now.
    struct Platform
    {
        std::string os;           ///< OCI name, e.g. "linux".
        std::string architecture; ///< OCI name, e.g. "amd64".
        std::string variant;      ///< OCI variant, e.g. "v7". Often empty.

        /// @brief How the platform reads in a log line.
        std::string describe() const
        {
            auto text {os.empty() ? "unknown" : os};
            text += "/";
            text += architecture.empty() ? "unknown" : architecture;

            if (!variant.empty())
            {
                text += "/" + variant;
            }

            return text;
        }
    };

    /// @brief One entry of an image index that could be inventoried.
    struct PlatformManifest
    {
        std::string digest;
        std::string mediaType;
        Platform platform;
    };

    /// @brief The operating system a container image has to be built for.
    ///
    /// Fixed, and not taken from the host. An OCI image is a Linux image whatever runs the
    /// engine: on macOS the engine runs Linux inside a virtual machine, so matching the
    /// host's own `darwin` would reject every image that exists.
    constexpr auto CONTAINER_OS {"linux"};

    /// @brief The platform an image must match to be worth inventorying.
    ///
    /// The operating system is @ref CONTAINER_OS rather than the host's, for the reason
    /// given there. The architecture is the host's, because that is what the container
    /// engine executes and what the packages inside the image are built for.
    Platform detectTargetPlatform();

    /// @brief Translate a machine name to the OCI architecture spelling.
    ///
    /// `uname -m` says `x86_64`, `aarch64` or `armv7l`; an image index says `amd64`,
    /// `arm64` or `arm` with variant `v7`. Without this, no reference on a 64-bit host
    /// would ever match a manifest.
    ///
    /// @param machine The machine name.
    /// @param variant Set when the machine name implies one, cleared otherwise.
    std::string normalizeArchitecture(const std::string& machine, std::string& variant);

    /// @brief True when a manifest's platform satisfies @p target.
    ///
    /// The operating system and the architecture must match. A variant matches when the
    /// manifest names none, when the target names none, or when the two are equal: an
    /// index frequently omits the variant for the only variant of an architecture, and
    /// refusing those would reject images that are in fact the right ones.
    bool platformMatches(const Platform& manifest, const Platform& target);

    /// @brief Pick the manifest of an image index that matches @p target.
    ///
    /// Handles both an index of several manifests and a single-manifest document: a
    /// reference may point at either, and the caller should not have to know which
    /// before asking.
    ///
    /// @param document The parsed index or manifest.
    /// @param target   The platform to match.
    /// @param selected Filled in when a match was found. For a single-manifest document
    ///                 the digest is empty, meaning "the document itself".
    /// @param error    Why no manifest was selected, naming the platforms that were on
    ///                 offer so the reason is actionable.
    /// @return True when a manifest was selected.
    bool selectPlatformManifest(const nlohmann::json& document,
                                const Platform& target,
                                PlatformManifest& selected,
                                std::string& error);
} // namespace containerimages

#endif // _PLATFORM_SELECTION_HPP
