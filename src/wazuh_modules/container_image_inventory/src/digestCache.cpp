/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "digestCache.hpp"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace container_image_inventory
{
    namespace
    {
        std::string escape_segment(const std::string& s)
        {
            std::string out;
            out.reserve(s.size());
            for (char c : s)
            {
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')
                {
                    out += c;
                }
                else
                {
                    char buf[4];
                    std::snprintf(buf, sizeof(buf), "_%02X", static_cast<unsigned char>(c));
                    out += buf;
                }
            }
            return out;
        }

        std::string iso8601_now()
        {
            const auto now = std::chrono::system_clock::now();
            const auto t = std::chrono::system_clock::to_time_t(now);
            std::tm tm{};
            gmtime_r(&t, &tm);
            char buf[32];
            std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
            return buf;
        }
    } // namespace

    DigestCache::DigestCache(std::string root, bool use_blob_cache, TraceFn trace)
        : m_root(std::move(root)), m_use_blob_cache(use_blob_cache), m_trace(std::move(trace))
    {
        ensure_dir(m_root);
        ensure_dir(m_root + "/blobs/sha256");
        ensure_dir(m_root + "/results/sha256");
        ensure_dir(m_root + "/refs");
    }

    void DigestCache::trace(const std::string& msg) const
    {
        if (m_trace)
        {
            m_trace(msg);
        }
    }

    void DigestCache::ensure_dir(const std::string& path) const
    {
        std::error_code ec;
        fs::create_directories(path, ec);
        // Silent failure ok; failure to write later will surface.
    }

    std::string DigestCache::digest_hex_only(const std::string& digest) const
    {
        const auto colon = digest.find(':');
        if (colon == std::string::npos)
        {
            return digest;
        }
        return digest.substr(colon + 1);
    }

    std::string DigestCache::blob_path(const std::string& digest) const
    {
        const auto hex = digest_hex_only(digest);
        if (hex.empty())
        {
            return std::string();
        }
        return m_root + "/blobs/sha256/" + hex;
    }

    bool DigestCache::has_blob(const std::string& digest) const
    {
        if (!m_use_blob_cache)
        {
            return false;
        }
        const auto p = blob_path(digest);
        std::error_code ec;
        return !p.empty() && fs::exists(p, ec);
    }

    std::optional<std::vector<unsigned char>>
    DigestCache::read_blob(const std::string& digest) const
    {
        if (!has_blob(digest))
        {
            return std::nullopt;
        }
        const auto p = blob_path(digest);
        std::ifstream f(p, std::ios::binary);
        if (!f)
        {
            return std::nullopt;
        }
        f.seekg(0, std::ios::end);
        const std::streamoff sz = f.tellg();
        f.seekg(0, std::ios::beg);
        std::vector<unsigned char> buf(static_cast<size_t>(sz));
        if (sz > 0)
        {
            f.read(reinterpret_cast<char*>(buf.data()), sz);
        }
        return buf;
    }

    void DigestCache::write_blob(const std::string& digest,
                                 const std::vector<unsigned char>& bytes) const
    {
        if (!m_use_blob_cache)
        {
            return;
        }
        const auto p = blob_path(digest);
        if (p.empty())
        {
            return;
        }
        const auto tmp = p + ".tmp";
        {
            std::ofstream f(tmp, std::ios::binary);
            if (!f)
            {
                return;
            }
            if (!bytes.empty())
            {
                f.write(reinterpret_cast<const char*>(bytes.data()),
                        static_cast<std::streamsize>(bytes.size()));
            }
        }
        std::error_code ec;
        fs::rename(tmp, p, ec);
        if (ec)
        {
            fs::remove(tmp, ec);
        }
    }

    std::string DigestCache::result_path(const std::string& selected_manifest_digest) const
    {
        const auto hex = digest_hex_only(selected_manifest_digest);
        if (hex.empty())
        {
            return std::string();
        }
        return m_root + "/results/sha256/" + hex + ".json";
    }

    bool DigestCache::has_result(const std::string& selected_manifest_digest) const
    {
        const auto p = result_path(selected_manifest_digest);
        std::error_code ec;
        return !p.empty() && fs::exists(p, ec);
    }

    std::optional<nlohmann::json>
    DigestCache::read_result(const std::string& selected_manifest_digest) const
    {
        const auto p = result_path(selected_manifest_digest);
        if (p.empty())
        {
            return std::nullopt;
        }
        std::ifstream f(p);
        if (!f)
        {
            return std::nullopt;
        }
        try
        {
            return nlohmann::json::parse(f);
        }
        catch (const std::exception&)
        {
            return std::nullopt;
        }
    }

    void DigestCache::write_result(const std::string& selected_manifest_digest,
                                   const nlohmann::json& result) const
    {
        const auto p = result_path(selected_manifest_digest);
        if (p.empty())
        {
            return;
        }
        const auto tmp = p + ".tmp";
        {
            std::ofstream f(tmp);
            if (!f)
            {
                return;
            }
            f << result.dump(2);
        }
        std::error_code ec;
        fs::rename(tmp, p, ec);
        if (ec)
        {
            fs::remove(tmp, ec);
        }
    }

    void DigestCache::write_ref_record(const std::string& registry,
                                       const std::string& repository,
                                       const std::string& reference,
                                       const std::string& platform,
                                       const std::string& root_digest,
                                       const std::string& selected_manifest_digest) const
    {
        const std::string fname =
            escape_segment(registry) + "_" + escape_segment(repository) + "_" +
            escape_segment(reference) + "_" + escape_segment(platform) + ".json";
        const std::string p = m_root + "/refs/" + fname;
        nlohmann::json rec;
        rec["registry"] = registry;
        rec["repository"] = repository;
        rec["reference"] = reference;
        rec["platform"] = platform;
        rec["root_digest"] = root_digest;
        rec["selected_manifest_digest"] = selected_manifest_digest;
        rec["scanned_at"] = iso8601_now();
        std::ofstream f(p);
        if (!f)
        {
            return;
        }
        f << rec.dump(2);
    }
} // namespace container_image_inventory
