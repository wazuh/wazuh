/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _IMAGE_REFERENCE_HPP
#define _IMAGE_REFERENCE_HPP

#include <string>
#include <utility>

namespace container_image_inventory
{
    struct RemoteImageRef
    {
        std::string original;
        std::string registry;
        std::string repository;
        std::string reference; // tag or sha256:<digest>
    };

    // Parse a Docker-style image reference. Throws std::invalid_argument on
    // malformed input.
    RemoteImageRef parse_image_ref(const std::string& ref);

    // Returns default platform string for this host: "linux/amd64",
    // "linux/arm64", etc.
    std::string default_platform();

    // Returns (os, arch, variant). variant may be empty.
    struct PlatformParts
    {
        std::string os;
        std::string arch;
        std::string variant;
    };
    PlatformParts parse_platform(const std::string& platform);
} // namespace container_image_inventory

#endif
