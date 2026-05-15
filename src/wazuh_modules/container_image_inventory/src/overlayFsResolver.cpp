/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "overlayFsResolver.hpp"

#include <algorithm>

#include "tarUtils.hpp"

namespace container_image_inventory
{
    namespace
    {
        std::string basename_of(const std::string& path)
        {
            auto pos = path.find_last_of('/');
            return (pos == std::string::npos) ? path : path.substr(pos + 1);
        }

        std::string dirname_of(const std::string& path)
        {
            auto pos = path.find_last_of('/');
            return (pos == std::string::npos) ? std::string() : path.substr(0, pos);
        }
    } // namespace

    OverlayFsResolver::OverlayFsResolver(TraceFn trace)
        : m_trace(std::move(trace))
    {
    }

    void OverlayFsResolver::trace(const std::string& msg) const
    {
        if (m_trace)
        {
            m_trace(msg);
        }
    }

    std::map<std::string, ResolvedEntry>
    OverlayFsResolver::resolve(BlobProvider& provider,
                               const std::vector<std::string>& layer_keys,
                               const std::unordered_set<std::string>& wanted)
    {
        std::map<std::string, ResolvedEntry> vfs;

        for (size_t li = 0; li < layer_keys.size(); ++li)
        {
            const std::string& layer_key = layer_keys[li];
            std::vector<unsigned char> layer_bytes;
            try
            {
                layer_bytes = provider.get_blob(layer_key);
            }
            catch (const std::exception& e)
            {
                trace("layer fetch failed index=" + std::to_string(li) + " key=" + layer_key +
                      " error=" + e.what());
                continue;
            }
            const auto members = list_tar_members(layer_bytes);
            if (members.empty())
            {
                trace("layer empty or unreadable index=" + std::to_string(li) + " key=" + layer_key);
                continue;
            }

            // Pass 1: opaque whiteouts wipe wanted entries under that prefix.
            for (const auto& m : members)
            {
                const auto base = basename_of(m.normalized);
                if (base != ".wh..wh..opq")
                {
                    continue;
                }
                const auto parent = dirname_of(m.normalized);
                const std::string prefix = parent.empty() ? std::string() : parent + "/";
                std::vector<std::string> to_delete;
                for (const auto& kv : vfs)
                {
                    const auto& key = kv.first;
                    if ((!prefix.empty() && key.rfind(prefix, 0) == 0) || key == parent)
                    {
                        to_delete.push_back(key);
                    }
                }
                for (const auto& k : to_delete)
                {
                    vfs.erase(k);
                    trace("opaque whiteout removed path=" + k + " layer=" + std::to_string(li));
                }
            }

            // Pass 2: per-file whiteouts + regular files.
            for (const auto& m : members)
            {
                const auto base = basename_of(m.normalized);
                if (base == ".wh..wh..opq")
                {
                    continue;
                }
                if (base.rfind(".wh.", 0) == 0)
                {
                    const std::string target_name = base.substr(4);
                    const auto parent = dirname_of(m.normalized);
                    const std::string target = parent.empty() ? target_name : parent + "/" + target_name;
                    const std::string dir_prefix = target + "/";
                    std::vector<std::string> to_delete;
                    for (const auto& kv : vfs)
                    {
                        const auto& key = kv.first;
                        if (key == target || key.rfind(dir_prefix, 0) == 0)
                        {
                            to_delete.push_back(key);
                        }
                    }
                    for (const auto& k : to_delete)
                    {
                        vfs.erase(k);
                        trace("whiteout removed path=" + k + " layer=" + std::to_string(li));
                    }
                    continue;
                }
                if (!m.is_file)
                {
                    continue;
                }
                if (!wanted.count(m.normalized))
                {
                    continue;
                }
                ResolvedEntry e;
                e.layer_index = static_cast<int>(li);
                e.layer_key = layer_key;
                e.tar_member_name = m.raw_name;
                e.is_deleted = false;
                vfs[m.normalized] = std::move(e);
                trace("candidate found path=" + m.normalized + " layer=" + std::to_string(li) +
                      " key=" + layer_key);
            }
        }

        return vfs;
    }
} // namespace container_image_inventory
