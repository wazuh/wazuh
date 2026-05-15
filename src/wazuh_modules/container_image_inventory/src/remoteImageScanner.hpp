/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTE_IMAGE_SCANNER_HPP
#define _REMOTE_IMAGE_SCANNER_HPP

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "blobProvider.hpp"
#include "containerImageInventoryTypes.hpp"
#include "digestCache.hpp"
#include "imageReference.hpp"
#include "registryClient.hpp"

namespace container_image_inventory
{
    struct RemoteScanOptions
    {
        std::string image_ref;
        std::string platform; // empty = host default
        RegistryAuth auth;
        std::string cache_dir;
        bool use_result_cache{true};
        bool use_blob_cache{true};
    };

    struct RemoteScanResult
    {
        ScanResult base;
        std::string registry;
        std::string repository;
        std::string reference;
        std::string platform;
        std::string root_digest;
        std::string selected_manifest_digest;
        bool cache_hit{false};
    };

    class RemoteImageScanner
    {
    public:
        explicit RemoteImageScanner(TraceFn trace = nullptr);
        RemoteScanResult scan(const RemoteScanOptions& opts);

    private:
        TraceFn m_trace;
        void trace(const std::string& msg) const;
    };

    nlohmann::json remote_result_to_json(const RemoteScanResult& r);
    std::string remote_result_to_summary(const RemoteScanResult& r);
} // namespace container_image_inventory

#endif
