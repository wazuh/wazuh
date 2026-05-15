/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTAINER_IMAGE_INVENTORY_TYPES_HPP
#define _CONTAINER_IMAGE_INVENTORY_TYPES_HPP

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace container_image_inventory
{
    constexpr const char* UNKNOWN_VALUE = " ";

    struct ImageMetadata
    {
        std::vector<std::string> repo_tags;
        std::string os{"linux"};
        std::string architecture{"unknown"};
        std::string image_id;
        std::string config_digest;
        std::optional<std::string> manifest_digest;
        int layer_count{0};
    };

    struct Package
    {
        std::string name;
        std::string version_;
        std::string architecture{UNKNOWN_VALUE};
        int64_t size{0};
        std::string description{UNKNOWN_VALUE};
        std::string priority{UNKNOWN_VALUE};
        std::string category{UNKNOWN_VALUE};
        std::string source{UNKNOWN_VALUE};
        std::string multiarch{UNKNOWN_VALUE};
        std::string vendor{UNKNOWN_VALUE};
        std::string installed{UNKNOWN_VALUE};
        std::string path{UNKNOWN_VALUE};
        std::string type;
    };

    struct ScanResult
    {
        std::string source_type{"archive"};
        std::string source_path;
        std::string configured_ref;

        ImageMetadata image;

        std::string package_manager{"none"};
        std::optional<std::string> rpm_backend;
        std::string database_path;
        int package_count{0};
        long elapsed_ms{0};

        std::vector<Package> packages;
    };

    using TraceFn = std::function<void(const std::string&)>;
} // namespace container_image_inventory

#endif
