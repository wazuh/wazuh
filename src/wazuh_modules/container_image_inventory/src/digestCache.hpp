/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DIGEST_CACHE_HPP
#define _DIGEST_CACHE_HPP

#include <optional>
#include <string>
#include <vector>

#include "containerImageInventoryTypes.hpp"
#include "json.hpp"

namespace container_image_inventory
{
    class DigestCache
    {
    public:
        DigestCache(std::string root, bool use_blob_cache, TraceFn trace);

        // Returns the absolute path to the blob file for a digest, or an
        // empty string when the entry is missing or blob caching is disabled.
        std::string blob_path(const std::string& digest) const;

        bool has_blob(const std::string& digest) const;
        std::optional<std::vector<unsigned char>> read_blob(const std::string& digest) const;
        void write_blob(const std::string& digest,
                        const std::vector<unsigned char>& bytes) const;

        std::string result_path(const std::string& selected_manifest_digest) const;
        bool has_result(const std::string& selected_manifest_digest) const;
        std::optional<nlohmann::json> read_result(const std::string& selected_manifest_digest) const;
        void write_result(const std::string& selected_manifest_digest,
                          const nlohmann::json& result) const;

        // Reference resolution audit record.
        void write_ref_record(const std::string& registry,
                              const std::string& repository,
                              const std::string& reference,
                              const std::string& platform,
                              const std::string& root_digest,
                              const std::string& selected_manifest_digest) const;

        const std::string& root() const { return m_root; }
        bool blob_cache_enabled() const { return m_use_blob_cache; }

    private:
        std::string m_root;
        bool m_use_blob_cache;
        TraceFn m_trace;

        void ensure_dir(const std::string& path) const;
        std::string digest_hex_only(const std::string& digest) const;
        void trace(const std::string& msg) const;
    };
} // namespace container_image_inventory

#endif
