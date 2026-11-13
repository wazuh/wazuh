/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "platform_selection.hpp"

#include "oci_metadata.hpp"

#include <algorithm>
#include <cctype>

#ifndef WIN32
#include <sys/utsname.h>
#endif

namespace
{
    std::string lowered(std::string value)
    {
        std::transform(value.begin(),
                       value.end(),
                       value.begin(),
                       [](const unsigned char character) { return static_cast<char>(std::tolower(character)); });

        return value;
    }
} // namespace

namespace containerimages
{
    std::string normalizeArchitecture(const std::string& machine, std::string& variant)
    {
        const auto value {lowered(machine)};

        variant.clear();

        if (value == "x86_64" || value == "amd64")
        {
            return "amd64";
        }

        if (value == "aarch64" || value == "arm64")
        {
            return "arm64";
        }

        if (value == "armv7l" || value == "armv7")
        {
            variant = "v7";
            return "arm";
        }

        if (value == "armv6l" || value == "armv6")
        {
            variant = "v6";
            return "arm";
        }

        if (value == "i386" || value == "i486" || value == "i586" || value == "i686")
        {
            return "386";
        }

        if (value == "ppc64le")
        {
            return "ppc64le";
        }

        if (value == "s390x")
        {
            return "s390x";
        }

        if (value == "riscv64")
        {
            return "riscv64";
        }

        return value;
    }

    Platform detectTargetPlatform()
    {
        Platform platform;

        // Always the container's operating system, never the host's. See CONTAINER_OS.
        platform.os = CONTAINER_OS;

#ifndef WIN32
        struct utsname system {};

        if (::uname(&system) == 0)
        {
            platform.architecture = normalizeArchitecture(system.machine, platform.variant);
        }
#else
        // Registry support is not offered on Windows, so no architecture is detected and a
        // reference reports that it matches nothing rather than guessing one.
#endif

        return platform;
    }

    bool platformMatches(const Platform& manifest, const Platform& target)
    {
        if (manifest.os.empty() || manifest.architecture.empty())
        {
            return false;
        }

        if (manifest.os != target.os || manifest.architecture != target.architecture)
        {
            return false;
        }

        // An index usually omits the variant when an architecture has only one, so an
        // absent variant on either side is not a mismatch.
        if (manifest.variant.empty() || target.variant.empty())
        {
            return true;
        }

        return manifest.variant == target.variant;
    }

    bool selectPlatformManifest(const nlohmann::json& document,
                                const Platform& target,
                                PlatformManifest& selected,
                                std::string& error)
    {
        selected = {};
        error.clear();

        if (target.os.empty() || target.architecture.empty())
        {
            error = "the platform to match could not be determined";
            return false;
        }

        // Copy-initialized, not brace-initialized: brace-initializing a json from a json
        // selects its initializer-list constructor and would wrap the array in another one.
        const auto manifests = oci::arrayField(document, "manifests");

        if (manifests.empty())
        {
            // A single-manifest document. It names no platform of its own, so its
            // configuration blob is the only thing that can confirm the platform, and
            // that is read later by the caller. An empty digest means "this document".
            const auto config {document.find("config")};

            if (config != document.end() && config->is_object())
            {
                selected.mediaType = oci::stringField(document, "mediaType");

                return true;
            }

            error = "the reference points at neither an image index nor an image manifest";

            return false;
        }

        std::string offered;

        for (const auto& entry : manifests)
        {
            if (!entry.is_object() || oci::isAttestationManifest(entry))
            {
                // Build attestations carry no image content, so they are not candidates
                // and are not worth naming in the error either.
                continue;
            }

            const auto platformNode {entry.find("platform")};

            Platform platform;

            if (platformNode != entry.end() && platformNode->is_object())
            {
                platform.os = oci::stringField(*platformNode, "os");
                platform.architecture = oci::stringField(*platformNode, "architecture");
                platform.variant = oci::stringField(*platformNode, "variant");
            }

            if (!offered.empty())
            {
                offered += ", ";
            }

            offered += platform.describe();

            if (!platformMatches(platform, target))
            {
                continue;
            }

            const auto digest {oci::stringField(entry, "digest")};

            if (!oci::isSafeDigest(digest))
            {
                // The digest becomes part of a request path, so a malformed one is
                // skipped rather than sent.
                continue;
            }

            selected.digest = digest;
            selected.mediaType = oci::stringField(entry, "mediaType");
            selected.platform = platform;

            return true;
        }

        error = "no image variant matches " + target.describe();

        if (!offered.empty())
        {
            error += ", the reference offers " + offered;
        }

        return false;
    }
} // namespace containerimages
