/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OVERLAY_FS_RESOLVER_HPP
#define _OVERLAY_FS_RESOLVER_HPP

#include <map>
#include <string>
#include <unordered_set>
#include <vector>

#include "blobProvider.hpp"
#include "containerImageInventoryTypes.hpp"

namespace container_image_inventory
{
    struct ResolvedEntry
    {
        int layer_index{-1};
        std::string layer_key;          // archive: layer path. remote: digest.
        std::string tar_member_name;
        bool is_deleted{false};
    };

    class OverlayFsResolver
    {
    public:
        explicit OverlayFsResolver(TraceFn trace = nullptr);

        // Build a path -> ResolvedEntry map. Only paths whose normalized form
        // is in `wanted` are retained. Layers are pulled in order from
        // `provider` using the keys in `layer_keys`.
        std::map<std::string, ResolvedEntry>
        resolve(BlobProvider& provider,
                const std::vector<std::string>& layer_keys,
                const std::unordered_set<std::string>& wanted);

    private:
        TraceFn m_trace;
        void trace(const std::string& msg) const;
    };
} // namespace container_image_inventory

#endif
