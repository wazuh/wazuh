/*
 * Wazuh container image inventory PoC
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "imageArchiveParser.hpp"

#include <archive.h>
#include <archive_entry.h>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include "json.hpp"

namespace container_image_inventory
{
    namespace
    {
        constexpr uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

        inline uint32_t rotr(uint32_t x, uint32_t n)
        {
            return (x >> n) | (x << (32 - n));
        }
    } // namespace

    std::string sha256_hex(const unsigned char* data, size_t len)
    {
        uint32_t H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

        std::vector<unsigned char> buf(data, data + len);
        const uint64_t bitlen = static_cast<uint64_t>(len) * 8ULL;
        buf.push_back(0x80);
        while (buf.size() % 64 != 56)
        {
            buf.push_back(0x00);
        }
        for (int i = 7; i >= 0; --i)
        {
            buf.push_back(static_cast<unsigned char>((bitlen >> (i * 8)) & 0xFF));
        }

        for (size_t off = 0; off < buf.size(); off += 64)
        {
            uint32_t w[64];
            for (int i = 0; i < 16; ++i)
            {
                w[i] = (uint32_t(buf[off + i * 4]) << 24) | (uint32_t(buf[off + i * 4 + 1]) << 16) |
                       (uint32_t(buf[off + i * 4 + 2]) << 8) | uint32_t(buf[off + i * 4 + 3]);
            }
            for (int i = 16; i < 64; ++i)
            {
                uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
            uint32_t e = H[4], f = H[5], g = H[6], h = H[7];
            for (int i = 0; i < 64; ++i)
            {
                uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                uint32_t ch = (e & f) ^ (~e & g);
                uint32_t temp1 = h + S1 + ch + K[i] + w[i];
                uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + mj;
                h = g; g = f; f = e; e = d + temp1;
                d = c; c = b; b = a; a = temp1 + temp2;
            }
            H[0] += a; H[1] += b; H[2] += c; H[3] += d;
            H[4] += e; H[5] += f; H[6] += g; H[7] += h;
        }

        std::ostringstream os;
        os << std::hex << std::setfill('0');
        for (int i = 0; i < 8; ++i)
        {
            os << std::setw(8) << H[i];
        }
        return os.str();
    }

    std::string normalize_tar_path(const std::string& raw)
    {
        std::string p = raw;
        while (p.rfind("./", 0) == 0)
        {
            p.erase(0, 2);
        }
        while (!p.empty() && p[0] == '/')
        {
            p.erase(0, 1);
        }
        return p;
    }

    ImageArchiveParser::ImageArchiveParser(TraceFn trace)
        : m_trace(std::move(trace))
    {
    }

    void ImageArchiveParser::trace(const std::string& msg) const
    {
        if (m_trace)
        {
            m_trace(msg);
        }
    }

    bool ImageArchiveParser::load(const std::string& archive_path)
    {
        struct archive* a = archive_read_new();
        archive_read_support_format_tar(a);
        archive_read_support_format_gnutar(a);
        archive_read_support_filter_gzip(a);
        archive_read_support_filter_none(a);

        if (archive_read_open_filename(a, archive_path.c_str(), 65536) != ARCHIVE_OK)
        {
            archive_read_free(a);
            return false;
        }

        struct archive_entry* entry;
        while (archive_read_next_header(a, &entry) == ARCHIVE_OK)
        {
            const char* path = archive_entry_pathname(entry);
            if (!path)
            {
                archive_read_data_skip(a);
                continue;
            }
            std::string name = normalize_tar_path(path);

            int64_t size = archive_entry_size(entry);
            const mode_t mode = archive_entry_filetype(entry);
            if (mode != AE_IFREG || size <= 0)
            {
                archive_read_data_skip(a);
                continue;
            }

            std::vector<unsigned char> data;
            data.reserve(size);
            unsigned char buf[8192];
            la_ssize_t r;
            while ((r = archive_read_data(a, buf, sizeof(buf))) > 0)
            {
                data.insert(data.end(), buf, buf + r);
            }
            m_members.emplace(std::move(name), std::move(data));
        }

        archive_read_free(a);
        return !m_members.empty();
    }

    bool ImageArchiveParser::has_member(const std::string& name) const
    {
        return m_members.count(name) > 0;
    }

    const std::vector<unsigned char>& ImageArchiveParser::member_bytes(const std::string& name) const
    {
        return m_members.at(name);
    }

    ImageManifestEntry ImageArchiveParser::read_manifest()
    {
        if (!has_member("manifest.json"))
        {
            throw std::runtime_error("manifest.json not found - not a docker-save tarball");
        }
        const auto& bytes = member_bytes("manifest.json");
        const auto parsed = nlohmann::json::parse(std::string(bytes.begin(), bytes.end()));
        if (!parsed.is_array() || parsed.empty())
        {
            throw std::runtime_error("manifest.json is empty or malformed");
        }
        const auto& first = parsed.at(0);
        ImageManifestEntry e;
        if (first.contains("Config") && first["Config"].is_string())
        {
            e.config = first["Config"].get<std::string>();
        }
        if (first.contains("Layers") && first["Layers"].is_array())
        {
            for (const auto& l : first["Layers"])
            {
                if (l.is_string())
                {
                    e.layers.push_back(l.get<std::string>());
                }
            }
        }
        if (first.contains("RepoTags") && first["RepoTags"].is_array())
        {
            for (const auto& t : first["RepoTags"])
            {
                if (t.is_string())
                {
                    e.repo_tags.push_back(t.get<std::string>());
                }
            }
        }
        trace("manifest.json loaded entries=" + std::to_string(parsed.size()));
        return e;
    }

    ImageMetadata ImageArchiveParser::read_image_config(const ImageManifestEntry& entry)
    {
        ImageMetadata m;
        m.repo_tags = entry.repo_tags;
        m.layer_count = static_cast<int>(entry.layers.size());

        if (entry.config.empty() || !has_member(entry.config))
        {
            trace("image config blob missing path=" + entry.config);
            return m;
        }
        const auto& bytes = member_bytes(entry.config);
        m.image_id = "sha256:" + sha256_hex(bytes.data(), bytes.size());

        // config_digest from manifest "Config" name (filename usually
        // "blobs/sha256/<hex>" in OCI layout, or "<hex>.json" in docker save).
        const std::string& cfg = entry.config;
        auto slash = cfg.find_last_of('/');
        std::string fname = (slash == std::string::npos) ? cfg : cfg.substr(slash + 1);
        if (fname.size() > 5 && fname.compare(fname.size() - 5, 5, ".json") == 0)
        {
            fname = fname.substr(0, fname.size() - 5);
        }
        if (!fname.empty())
        {
            m.config_digest = "sha256:" + fname;
        }

        try
        {
            const auto cfg_json = nlohmann::json::parse(std::string(bytes.begin(), bytes.end()));
            if (cfg_json.contains("os") && cfg_json["os"].is_string())
            {
                m.os = cfg_json["os"].get<std::string>();
            }
            if (cfg_json.contains("architecture") && cfg_json["architecture"].is_string())
            {
                m.architecture = cfg_json["architecture"].get<std::string>();
            }
        }
        catch (const std::exception&)
        {
            // Keep defaults.
        }

        trace("config loaded path=" + entry.config + " os=" + m.os + " architecture=" + m.architecture +
              " image_id=" + m.image_id);
        return m;
    }

    ArchiveBlobProvider::ArchiveBlobProvider(ImageArchiveParser& parser)
        : m_parser(parser)
    {
    }

    std::vector<unsigned char> ArchiveBlobProvider::get_blob(const std::string& key)
    {
        if (!m_parser.has_member(key))
        {
            throw std::runtime_error("archive member not found: " + key);
        }
        return m_parser.member_bytes(key);
    }
} // namespace container_image_inventory
